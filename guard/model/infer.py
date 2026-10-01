from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard.model.train import MODEL_BUNDLE_VERSION, NOVELTY_POLICY, load_model_bundle
from guard.pipeline.features import FEATURE_NAMES, FEATURE_VERSION, FeatureVector


class ModelCompatibilityError(ValueError):
    """The model must be rebuilt before it can score current features."""


@dataclass(slots=True, frozen=True)
class InferenceResult:
    window_start_ms: int
    feature_version: int
    score: float
    threshold_score: float
    is_anomaly: bool
    values: list[float]
    metadata: dict[str, Any]


class ModelInferer:
    def __init__(self, model_path: str | Path) -> None:
        bundle = load_model_bundle(model_path)

        if (
            bundle.get("model_bundle_version") != MODEL_BUNDLE_VERSION
            or bundle.get("novelty_policy") != NOVELTY_POLICY
            or bundle.get("feature_version") != FEATURE_VERSION
            or bundle.get("feature_names") != FEATURE_NAMES
        ):
            raise ModelCompatibilityError(
                "model uses an incompatible baseline or feature schema; "
                "run 'guardd train' to rebuild it from stored windows"
            )

        self.bundle = bundle
        self.model = __import__("pickle").loads(bundle["model_pickle"])
        self.feature_version = int(bundle["feature_version"])
        self.threshold_score = float(bundle["threshold_score"])
        self.feature_names = list(bundle["feature_names"])

    def score_feature_vector(self, feature: FeatureVector) -> InferenceResult:
        if feature.feature_version != self.feature_version:
            raise ValueError(
                f"feature version mismatch: feature={feature.feature_version} "
                f"model={self.feature_version}"
            )

        score = float(self.model.score_samples([feature.values])[0])
        is_anomaly = score < self.threshold_score

        return InferenceResult(
            window_start_ms=feature.window_start_ms,
            feature_version=feature.feature_version,
            score=score,
            threshold_score=self.threshold_score,
            is_anomaly=is_anomaly,
            values=feature.values,
            metadata=feature.metadata,
        )
