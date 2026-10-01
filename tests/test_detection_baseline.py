import io
import json
import os
import pickle
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guard import cli
from guard.ebpf.schema import ExecEvent
from guard.model.train import _atomic_write_bytes, load_model_bundle, train_isolation_forest
from guard.pipeline.aggregator import WindowState
from guard.pipeline.baseline import BaselineState
from guard.pipeline.features import vectorize_window
from guard.storage.anomaly_store import AnomalyStore
from guard.storage.feature_store import FeatureStore


def exec_event(index, comm="eviltool"):
    return ExecEvent(
        ts_ms=index * 60_000, type="exec", pid=42, ppid=1, uid=1000,
        comm=comm, file=f"/usr/bin/{comm}",
    )


class DetectionBaselineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.model_path = self.root / "model.bundle"
        self.train_model("bash")

    def train_model(self, comm):
        old_mtime = self.model_path.stat().st_mtime_ns if self.model_path.exists() else 0
        store = FeatureStore(self.root / f"training-{comm}.db")
        store.init_db()
        baseline = BaselineState()
        for index in range(10):
            window = WindowState(window_start_ms=index * 60_000)
            window.add(exec_event(index, comm))
            store.insert_feature_vector(vectorize_window(window, baseline=baseline))
            baseline.observe_window(window)
        train_isolation_forest(
            store.db_path, model_out_path=self.model_path, n_estimators=5,
        )
        # Ensure replacement is visible even on filesystems with coarse timestamps.
        new_mtime = max(self.model_path.stat().st_mtime_ns, old_mtime + 1_000_000_000)
        os.utime(self.model_path, ns=(new_mtime, new_mtime))

    def run_detection(self, events, db_path, **kwargs):
        output = io.StringIO()
        with patch.object(cli, "GuarddProcessReader") as reader, redirect_stdout(output):
            reader.return_value.iter_events.return_value = iter(events)
            status = cli.run_detect_loop(
                sensor_path="unused", db_path=db_path, model_path=self.model_path,
                print_features=True, print_all_scores=True, **kwargs,
            )
        self.assertEqual(status, 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        return [record for record in records if record["type"] == "features"]

    def assert_novel(self, feature, expected):
        metadata = feature["metadata"]
        self.assertEqual(metadata["new_comms"], ["eviltool"] if expected else [])
        self.assertEqual(metadata["new_files"], ["/usr/bin/eviltool"] if expected else [])
        self.assertEqual(
            metadata["new_parent_child"],
            [{"ppid": 1, "comm": "eviltool"}] if expected else [],
        )
        self.assertEqual(feature["values"][10:14], [float(expected)] * 4)

    def test_repeated_unseen_behavior_stays_new_for_current_model(self):
        for is_anomaly in (False, True):
            for no_store in (False, True):
                with self.subTest(is_anomaly=is_anomaly, no_store=no_store):
                    bundle = load_model_bundle(self.model_path)
                    # Isolation Forest scores are negative; force either outcome
                    # while still using the real model and inference path.
                    bundle["threshold_score"] = 0.0 if is_anomaly else -1.0
                    _atomic_write_bytes(self.model_path, pickle.dumps(bundle))
                    reloader = cli.ReloadableInferer(self.model_path)
                    initial_baseline = reloader.baseline.to_dict()
                    db_path = self.root / f"detect-{is_anomaly}-{no_store}.db"
                    with patch.object(cli, "ReloadableInferer", return_value=reloader):
                        features = self.run_detection(
                            [exec_event(index) for index in range(3)], db_path,
                            no_store=no_store, reload_check_every_windows=1,
                        )
                    # Two completed windows plus the final window flushed at EOF.
                    self.assertEqual(len(features), 3)
                    for feature in features:
                        self.assert_novel(feature, True)
                    self.assertEqual(reloader.baseline.to_dict(), initial_baseline)
                    anomalies = AnomalyStore(db_path).list_anomalies()
                    self.assertEqual(len(anomalies), 3 if is_anomaly else 0)
                    for row in anomalies:
                        self.assertIn(
                            "new process names observed: eviltool",
                            json.loads(row["reasons_json"]),
                        )
                    if not no_store:
                        stored = FeatureStore(db_path).load_feature_examples()
                        self.assertEqual(len(stored), 3)
                        for feature in stored:
                            self.assert_novel(feature, True)

    def test_hot_reload_replaces_baseline_with_new_training_snapshot(self):
        def events():
            yield exec_event(0)
            yield exec_event(1)
            self.train_model("eviltool")
            yield exec_event(2)

        reloader = cli.ReloadableInferer(self.model_path)
        old_baseline = reloader.baseline
        with patch.object(cli, "ReloadableInferer", return_value=reloader):
            features = self.run_detection(
                events(), self.root / "reload.db", reload_check_every_windows=2,
            )
        self.assertEqual(len(features), 3)
        self.assert_novel(features[0], True)
        self.assert_novel(features[1], True)
        self.assert_novel(features[2], False)
        self.assertIsNot(reloader.baseline, old_baseline)
        self.assertEqual(old_baseline.known_comms, {"bash"})
        self.assertEqual(reloader.baseline.known_comms, {"eviltool"})
        self.assertEqual(reloader.baseline.known_files, {"/usr/bin/eviltool"})
        self.assertEqual(reloader.baseline.known_parent_child, {(1, "eviltool")})

    def test_collection_still_learns_observed_behavior(self):
        db_path = self.root / "collect.db"
        with patch.object(cli, "GuarddProcessReader") as reader:
            reader.return_value.iter_events.return_value = iter(
                [exec_event(index) for index in range(3)]
            )
            status = cli.run_collect_loop(sensor_path="unused", db_path=db_path)
        self.assertEqual(status, 0)
        features = FeatureStore(db_path).load_feature_examples()
        self.assertEqual(len(features), 3)
        self.assert_novel(features[0], True)
        self.assert_novel(features[1], False)
        self.assert_novel(features[2], False)


if __name__ == "__main__":
    unittest.main()
