import copy
import pickle
import time

import pytest

from guard import cli
from guard.ebpf.schema import ExecEvent
from guard.model.infer import ModelCompatibilityError, ModelInferer
from guard.model.train import (
    MODEL_BUNDLE_VERSION,
    _compute_threshold,
    load_model_bundle,
    prepare_training_dataset,
    train_isolation_forest,
)
from guard.pipeline.aggregator import WindowState
from guard.pipeline.baseline import BaselineState
from guard.pipeline.features import FEATURE_VERSION, vectorize_window
from guard.storage.feature_store import FeatureStore
from guard.training.data_loader import load_training_dataset


def window(index, comm="bash", count=1):
    result = WindowState(window_start_ms=index * 60_000)
    for pid in range(count):
        result.add(
            ExecEvent(
                result.window_start_ms, "exec", pid, 100, 1000, comm, f"/usr/bin/{comm}"
            )
        )
    return result


def save_windows(tmp_path, windows, *, mixed_baselines=False):
    db = tmp_path / "features.db"
    store = FeatureStore(db)
    store.init_db()
    for index, item in enumerate(windows):
        baseline = None
        if mixed_baselines:
            baseline = BaselineState()
            # Mimic windows saved by unrelated earlier model snapshots.
            if index % 2:
                baseline.observe_window(item)
        store.insert_feature_vector(vectorize_window(item, baseline=baseline))
    return db


def test_training_replays_mixed_baselines_without_future_leakage(tmp_path):
    windows = [window(0), window(1), window(2, "curl"), window(3, "curl"), window(4)]
    db = save_windows(tmp_path, windows, mixed_baselines=True)
    dataset = load_training_dataset(str(db))
    original = copy.deepcopy(dataset)
    # The stored second curl occurrence is already known to its old baseline.
    assert dataset["X"][3][-4:] == [0, 0, 0, 0]
    prepared = prepare_training_dataset(
        dataset, baseline_fraction=0.4, min_training_rows=3
    )
    baseline = BaselineState.from_dict(prepared["baseline_snapshot"])
    assert baseline.known_comms == {"bash"}
    assert prepared["X"] == [
        vectorize_window(item, baseline=baseline).values for item in windows[2:]
    ]
    # Novel behavior stays novel on every occurrence, exactly as in detection.
    assert prepared["X"][0][-4:] == prepared["X"][1][-4:] == [1, 1, 1, 1]
    assert dataset == original


def test_reference_is_chronological_even_if_input_is_unsorted(tmp_path):
    db = save_windows(tmp_path, [window(0), window(1, "curl"), window(2, "curl")])
    dataset = load_training_dataset(str(db))
    for name in ("X", "metadata", "window_start_ms"):
        dataset[name].reverse()
    prepared = prepare_training_dataset(dataset, min_training_rows=2)
    assert prepared["baseline_end_ms"] == 0
    assert prepared["training_start_ms"] == 60_000
    assert prepared["baseline_snapshot"]["known_comms"] == ["bash"]


def test_saved_model_threshold_and_live_scores_use_identical_features(tmp_path):
    windows = [
        window(i, "bash" if i < 5 else "curl", count=1 + i % 4) for i in range(15)
    ]
    db = save_windows(tmp_path, windows, mixed_baselines=True)
    model_path = tmp_path / "model.bundle"
    result = train_isolation_forest(db, model_out_path=model_path, n_estimators=20)
    inferer = ModelInferer(model_path)
    baseline = BaselineState.from_dict(inferer.bundle["baseline_snapshot"])
    live_vectors = [vectorize_window(item, baseline=baseline) for item in windows[3:]]
    scores = [inferer.score_feature_vector(feature).score for feature in live_vectors]
    assert result["rows"] == 12
    assert result["baseline_rows"] == 3
    assert inferer.bundle["model_bundle_version"] == MODEL_BUNDLE_VERSION
    assert inferer.threshold_score == pytest.approx(_compute_threshold(scores, 10))
    assert inferer.bundle["score_summary"]["min"] == pytest.approx(min(scores))
    assert inferer.bundle["score_summary"]["max"] == pytest.approx(max(scores))
    assert baseline.known_comms == {"bash"}


def test_insufficient_fit_rows_preserves_existing_model(tmp_path):
    db = save_windows(tmp_path, [window(i) for i in range(10)])
    model_path = tmp_path / "model.bundle"
    model_path.write_bytes(b"previous model")
    with pytest.raises(ValueError, match="not enough training rows"):
        train_isolation_forest(db, model_out_path=model_path)
    assert model_path.read_bytes() == b"previous model"


@pytest.mark.parametrize("fraction", [0, 1, -0.2, float("nan")])
def test_invalid_baseline_fraction(tmp_path, fraction):
    db = save_windows(tmp_path, [window(i) for i in range(3)])
    with pytest.raises(ValueError, match="baseline_fraction"):
        prepare_training_dataset(
            load_training_dataset(str(db)), baseline_fraction=fraction
        )


def test_missing_identity_context_fails_instead_of_silently_clearing_baseline(tmp_path):
    db = save_windows(tmp_path, [window(i) for i in range(3)])
    dataset = load_training_dataset(str(db))
    del dataset["metadata"][0]["unique_files"]
    with pytest.raises(ValueError, match="identity metadata"):
        prepare_training_dataset(dataset, min_training_rows=2)


def test_legacy_model_rejected_before_loading_estimator(tmp_path):
    model_path = tmp_path / "model.bundle"
    model_path.write_bytes(
        pickle.dumps({"model_bundle_version": 1, "model_pickle": b"invalid"})
    )
    with pytest.raises(ModelCompatibilityError, match="guardd train"):
        ModelInferer(model_path)
    assert (
        cli.run_detect_loop(
            sensor_path="unused", db_path="unused", model_path=model_path
        )
        == 1
    )


def test_collect_restarts_store_unscored_observations(tmp_path, monkeypatch):
    class Reader:
        def __init__(self, path):
            pass

        def iter_events(self):
            yield ExecEvent(0, "exec", 1, 100, 1000, "bash", "/usr/bin/bash")
            yield ExecEvent(60_000, "exec", 2, 100, 1000, "bash", "/usr/bin/bash")

    monkeypatch.setattr(cli, "GuarddProcessReader", Reader)
    db = tmp_path / "features.db"
    for _ in range(2):
        assert cli.run_collect_loop(sensor_path="unused", db_path=db) == 0
    rows = FeatureStore(db).load_feature_examples(feature_version=FEATURE_VERSION)
    assert len(rows) == 2
    assert all(row["metadata"]["novelty_scored"] is False for row in rows)
    assert all(row["metadata"]["unique_comms"] == ["bash"] for row in rows)
    assert all(row["values"][-4:] == [0, 0, 0, 0] for row in rows)


@pytest.mark.parametrize("needs_more_data", [False, True])
def test_auto_mode_migrates_legacy_model_before_detection(
    tmp_path, monkeypatch, needs_more_data
):
    model_path = tmp_path / "model.bundle"
    model_path.write_bytes(pickle.dumps({"model_bundle_version": 1}))
    args = cli.resolve_args(
        cli.build_parser().parse_args(["daemon"]),
        {
            "paths": {"model_path": str(model_path)},
            "train": {"baseline_fraction": 0.3},
        },
    )
    calls = []
    outcomes = iter([False, True] if needs_more_data else [True])

    def train(**kwargs):
        assert kwargs["baseline_fraction"] == 0.3
        calls.append("train")
        return next(outcomes)

    def collect(**kwargs):
        calls.append("collect")
        return "scheduled_stop"

    def detect(**kwargs):
        calls.append("detect")
        return "interrupted"

    monkeypatch.setattr(cli, "try_train_model", train)
    monkeypatch.setattr(cli, "run_collect_loop", collect)
    monkeypatch.setattr(cli, "run_detect_loop", detect)
    assert cli.run_daemon_auto_loop(args) == 0
    assert calls == (
        ["train", "collect", "train", "detect"]
        if needs_more_data
        else ["train", "detect"]
    )


@pytest.mark.parametrize("command", ["train", "daemon"])
def test_baseline_setting_cli_overrides_config(command):
    args = cli.resolve_args(
        cli.build_parser().parse_args([command, "--baseline-fraction", "0.4"]),
        {
            "train": {"baseline_fraction": 0.3},
        },
    )
    assert args.baseline_fraction == 0.4


def test_detection_keeps_snapshot_fixed_until_reload(tmp_path, monkeypatch):
    windows = [window(i) for i in range(15)]
    db = save_windows(tmp_path, windows)
    model_path = tmp_path / "model.bundle"
    train_isolation_forest(db, model_out_path=model_path, n_estimators=20)

    class Reader:
        def __init__(self, path):
            pass

        def iter_events(self):
            for index in range(15, 18):
                yield ExecEvent(
                    index * 60_000, "exec", index, 100, 1000, "curl", "/usr/bin/curl"
                )

    monkeypatch.setattr(cli, "GuarddProcessReader", Reader)
    assert (
        cli.run_detect_loop(sensor_path="unused", db_path=db, model_path=model_path)
        == 0
    )
    rows = FeatureStore(db).load_feature_examples(start_ms=15 * 60_000)
    assert len(rows) == 3
    assert all(row["values"][-4:] == [1, 1, 1, 1] for row in rows)
    assert all(row["metadata"]["new_comms"] == ["curl"] for row in rows)
    assert load_model_bundle(model_path)["baseline_snapshot"]["known_comms"] == ["bash"]


def test_auto_upgrade_rebuilds_real_model_using_existing_rows(tmp_path, monkeypatch):
    windows = [window(i) for i in range(15)]
    # Keep these windows within the existing training retention period.
    now = int(time.time() * 1000)
    for item in windows:
        item.window_start_ms += now - 15 * 60_000
    db = save_windows(tmp_path, windows, mixed_baselines=True)
    model_path = tmp_path / "model.bundle"
    model_path.write_bytes(pickle.dumps({"model_bundle_version": 1}))
    args = cli.resolve_args(
        cli.build_parser().parse_args(["daemon"]),
        {
            "paths": {"model_path": str(model_path), "db_path": str(db)},
            "train": {"n_estimators": 20},
        },
    )

    def detect(**kwargs):
        inferer = ModelInferer(kwargs["model_path"])
        assert inferer.bundle["training_row_count"] == 12
        assert inferer.bundle["baseline_row_count"] == 3
        assert len(FeatureStore(db).load_feature_examples()) == 15
        return "interrupted"

    monkeypatch.setattr(cli, "run_detect_loop", detect)
    assert cli.run_daemon_auto_loop(args) == 0


def test_reload_replaces_baseline_only_with_new_model(tmp_path):
    db = save_windows(tmp_path, [window(i) for i in range(15)])
    model_path = tmp_path / "model.bundle"
    train_isolation_forest(db, model_out_path=model_path, n_estimators=20)
    reloader = cli.ReloadableInferer(model_path)
    new_window = window(16, "curl")
    assert reloader.baseline.new_comms(new_window) == ["curl"]
    store = FeatureStore(db)
    for index in range(15, 30):
        store.insert_feature_vector(vectorize_window(window(index, "curl")))
    train_isolation_forest(
        db, model_out_path=model_path, baseline_fraction=0.6, n_estimators=20
    )
    assert reloader.baseline.new_comms(new_window) == ["curl"]
    assert reloader.maybe_reload() is True
    assert reloader.baseline.new_comms(new_window) == []
    assert reloader.maybe_reload() is False
