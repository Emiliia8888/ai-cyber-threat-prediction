from typing import Any

from src.application.prediction_ports import PredictionEnginePort
from src.prediction.features import features_to_vector
from src.prediction.model import (
    build_model,
    predict_threat_with_confidence,
)


class LegacyPredictionEngine(PredictionEnginePort):

    """
    Adapter connecting the application prediction interface
    with the existing ML implementation.
    """

    def __init__(self) -> None:
        self._model = build_model()

    def predict(
        self,
        features: dict[str, Any],
    ) -> tuple[str, float]:

        feature_vector = features_to_vector(features)

        return predict_threat_with_confidence(
            self._model,
            feature_vector,
        )
