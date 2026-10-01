from __future__ import annotations

import json
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

from sklearn.ensemble import IsolationForest

from guard.pipeline.baseline import BaselineState
from guard.pipeline.features import (
    FEATURE_VERSION,
    FeatureVector,
    rebase_feature_vector,
    window_context_from_metadata,
)
from guard.training.data_loader import load_training_dataset

MODEL_BUNDLE_VERSION = 2
NOVELTY_POLICY = "frozen_reference_v1"
DEFAULT_BASELINE_FRACTION = 0.2


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(data)
        tmp.flush()
        tmp_path = Path(tmp.name)

    tmp_path.replace(path)


def _build_baseline_snapshot(metadata_rows: list[dict[str, Any]]) -> dict[str, Any]:
    baseline = BaselineState()
    for metadata in metadata_rows:
        baseline.observe_window(window_context_from_metadata(metadata))
    return baseline.to_dict()


def prepare_training_dataset(
    dataset: dict[str, Any],
    *,
    baseline_fraction: float = DEFAULT_BASELINE_FRACTION,
    min_training_rows: int = 10,
) -> dict[str, Any]:
    """Freeze an earlier reference, then replay later windows against it.

    Reference windows are excluded from the model fit and threshold calculation.
    Future identities cannot leak into the reference, and every later window
    uses the exact baseline that will be shipped with the model.
    """
    if not 0.0 < baseline_fraction < 1.0:
        raise ValueError("baseline_fraction must be between 0 and 1")
    if min_training_rows < 1:
        raise ValueError("min_training_rows must be positive")
    if dataset["feature_version"] != FEATURE_VERSION:
        raise ValueError("unsupported training feature version")
    examples = sorted(
        zip(dataset["window_start_ms"], dataset["X"], dataset["metadata"], strict=True),
        key=lambda example: example[0],
    )
    reference_count = max(1, int(len(examples) * baseline_fraction))
    training_count = len(examples) - reference_count
    if training_count < min_training_rows:
        raise ValueError(
            f"not enough training rows: need at least {min_training_rows} after "
            f"reserving {reference_count} baseline windows, got {max(0, training_count)}"
        )
    baseline_snapshot = _build_baseline_snapshot(
        [metadata for _, _, metadata in examples[:reference_count]]
    )
    baseline = BaselineState.from_dict(baseline_snapshot)
    features = [
        rebase_feature_vector(
            FeatureVector(FEATURE_VERSION, timestamp, values, metadata), baseline
        )
        for timestamp, values, metadata in examples[reference_count:]
    ]
    return {
        "X": [feature.values for feature in features],
        "baseline_snapshot": baseline_snapshot,
        "baseline_row_count": reference_count,
        "baseline_end_ms": examples[reference_count - 1][0],
        "training_start_ms": features[0].window_start_ms,
        "training_end_ms": features[-1].window_start_ms,
        "rows": training_count,
    }


def _compute_threshold(scores: list[float], percentile: float) -> float:
    if not scores:
        raise ValueError("cannot compute threshold from empty score list")

    if not 0.0 < percentile < 100.0:
        raise ValueError("percentile must be between 0 and 100")

    ordered = sorted(scores)
    rank = (percentile / 100.0) * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower

    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def train_isolation_forest(
    db_path: str | Path,
    *,
    min_training_rows: int = 10,
    model_out_path: str | Path,
    feature_version: int = FEATURE_VERSION,
    limit: int | None = None,
    contamination: float = 0.01,
    n_estimators: int = 200,
    random_state: int = 42,
    threshold_percentile: float = 10.0,
    baseline_fraction: float = DEFAULT_BASELINE_FRACTION,
) -> dict[str, Any]:
    dataset = load_training_dataset(
        str(db_path),
        feature_version=feature_version,
        limit=limit,
    )

    prepared = prepare_training_dataset(
        dataset,
        baseline_fraction=baseline_fraction,
        min_training_rows=min_training_rows,
    )
    X = prepared["X"]
    rows = prepared["rows"]

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)

    raw_scores = model.score_samples(X)
    scores = [float(score) for score in raw_scores]

    threshold = _compute_threshold(scores, threshold_percentile)

    bundle = {
        "model_bundle_version": MODEL_BUNDLE_VERSION,
        "created_at_ms": int(time.time() * 1000),
        "model_type": "IsolationForest",
        "feature_version": dataset["feature_version"],
        "feature_names": list(dataset["feature_names"]),
        "training_row_count": rows,
        "contamination": float(contamination),
        "n_estimators": int(n_estimators),
        "random_state": int(random_state),
        "threshold_percentile": float(threshold_percentile),
        "threshold_score": float(threshold),
        "novelty_policy": NOVELTY_POLICY,
        "baseline_fraction": float(baseline_fraction),
        "baseline_snapshot": prepared["baseline_snapshot"],
        "baseline_row_count": prepared["baseline_row_count"],
        "baseline_end_ms": prepared["baseline_end_ms"],
        "training_start_ms": prepared["training_start_ms"],
        "training_end_ms": prepared["training_end_ms"],
        "score_summary": {
            "min": min(scores),
            "max": max(scores),
            "avg": sum(scores) / len(scores),
        },
        "model_pickle": pickle.dumps(model),
    }

    _atomic_write_bytes(Path(model_out_path), pickle.dumps(bundle))

    return {
        "model_out_path": str(model_out_path),
        "rows": rows,
        "baseline_rows": prepared["baseline_row_count"],
        "feature_version": dataset["feature_version"],
        "feature_names": list(dataset["feature_names"]),
        "threshold_score": float(threshold),
        "score_min": min(scores),
        "score_max": max(scores),
    }


def load_model_bundle(model_path: str | Path) -> dict[str, Any]:
    with Path(model_path).open("rb") as f:
        return pickle.load(f)


def load_model(model_path: str | Path) -> Any:
    bundle = load_model_bundle(model_path)
    return pickle.loads(bundle["model_pickle"])


def bundle_summary(model_path: str | Path) -> dict[str, Any]:
    bundle = load_model_bundle(model_path)

    return {
        "model_bundle_version": bundle["model_bundle_version"],
        "created_at_ms": bundle["created_at_ms"],
        "model_type": bundle["model_type"],
        "feature_version": bundle["feature_version"],
        "feature_names": bundle["feature_names"],
        "training_row_count": bundle["training_row_count"],
        "contamination": bundle["contamination"],
        "n_estimators": bundle["n_estimators"],
        "random_state": bundle["random_state"],
        "threshold_percentile": bundle["threshold_percentile"],
        "threshold_score": bundle["threshold_score"],
        "score_summary": bundle["score_summary"],
        "novelty_policy": bundle.get("novelty_policy", "legacy"),
        "baseline_row_count": bundle.get("baseline_row_count"),
        "baseline_fraction": bundle.get("baseline_fraction"),
        "baseline_end_ms": bundle.get("baseline_end_ms"),
        "training_start_ms": bundle.get("training_start_ms"),
        "training_end_ms": bundle.get("training_end_ms"),
    }


def bundle_summary_json(model_path: str | Path) -> str:
    return json.dumps(bundle_summary(model_path), indent=2, sort_keys=True)
