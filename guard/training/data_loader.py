from __future__ import annotations

from typing import Any

from guard.pipeline.features import FEATURE_NAMES, FEATURE_VERSION
from guard.storage.feature_store import FeatureStore


def load_examples(
    db_path: str,
    *,
    feature_version: int | None = None,
    start_ms: int | None = None,
    end_ms: int | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    store = FeatureStore(db_path)
    return store.load_feature_examples(
        feature_version=feature_version,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
    )


def load_feature_matrix(
    db_path: str,
    *,
    feature_version: int | None = None,
    start_ms: int | None = None,
    end_ms: int | None = None,
    limit: int | None = None,
) -> list[list[float]]:
    examples = load_examples(
        db_path,
        feature_version=feature_version,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
    )
    return [example["values"] for example in examples]


def load_training_dataset(
    db_path: str,
    *,
    feature_version: int | None = None,
    start_ms: int | None = None,
    end_ms: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    resolved_version = FEATURE_VERSION if feature_version is None else feature_version

    examples = load_examples(
        db_path,
        feature_version=resolved_version,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
    )

    X = [example["values"] for example in examples]
    metadata = [example["metadata"] for example in examples]
    window_start_ms = [example["window_start_ms"] for example in examples]

    return {
        "feature_version": resolved_version,
        "feature_names": list(FEATURE_NAMES),
        "X": X,
        "metadata": metadata,
        "window_start_ms": window_start_ms,
        "rows": len(X),
    }
