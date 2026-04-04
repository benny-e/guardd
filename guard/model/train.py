from __future__ import annotations

import json
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

from sklearn.ensemble import IsolationForest

from guard.pipeline.features import FEATURE_NAMES, FEATURE_VERSION
from guard.training.data_loader import load_training_dataset


MODEL_BUNDLE_VERSION = 1


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
    known_comms: set[str] = set()
    known_files: set[str] = set()
    known_parent_child: set[tuple[int, str]] = set()

    for metadata in metadata_rows:
        for comm in metadata.get("unique_comms", []):
            known_comms.add(str(comm))

        for path in metadata.get("unique_files", []):
            known_files.add(str(path))

        for item in metadata.get("unique_parent_child", []):
            if isinstance(item, dict):
                known_parent_child.add(
                    (int(item["ppid"]), str(item["comm"]))
                )

    return {
        "known_comms": sorted(known_comms),
        "known_files": sorted(known_files),
        "known_parent_child": [
            {"ppid": ppid, "comm": comm}
            for ppid, comm in sorted(known_parent_child)
        ],
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
    model_out_path: str | Path,
    feature_version: int = FEATURE_VERSION,
    limit: int | None = None,
    contamination: float = 0.01,
    n_estimators: int = 200,
    random_state: int = 42,
    threshold_percentile: float = 10.0,
) -> dict[str, Any]:
    dataset = load_training_dataset(
        str(db_path),
        feature_version=feature_version,
        limit=limit,
    )

    X = dataset["X"]
    rows = dataset["rows"]

    if rows < 10:
        raise ValueError(
            f"not enough training rows: need at least 10, got {rows}"
        )

    baseline_snapshot = _build_baseline_snapshot(dataset["metadata"])

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
        "baseline_snapshot": baseline_snapshot,
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
    }


def bundle_summary_json(model_path: str | Path) -> str:
    return json.dumps(bundle_summary(model_path), indent=2, sort_keys=True)
