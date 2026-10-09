from typing import Any

import pandas as pd

from src.prediction.real_data.cic_feature_engineering import (
    add_cic_features,
)
from src.prediction.real_data.cic_model_persistence import (
    load_cic_model,
)
from src.prediction.real_data.cic_preprocessing import (
    clean_invalid_values,
)


class CICPredictionEngine:
    """
    Prediction engine for CIC-IDS2017 network-flow data.

    The engine loads a persisted CIC model together with
    its preprocessor and label encoder, then performs
    feature engineering and prediction without retraining.
    """

    def __init__(self) -> None:
        artifact = load_cic_model()

        self._model = artifact["model"]
        self._preprocessor = artifact["preprocessor"]
        self._encoder = artifact["label_encoder"]

    def predict(
        self,
        features: dict[str, Any],
    ) -> tuple[str, float]:
        dataframe = pd.DataFrame([features])

        dataframe = add_cic_features(
            dataframe
        )

        dataframe = clean_invalid_values(
            dataframe
        )

        processed = self._preprocessor.transform(
            dataframe
        )

        prediction = self._model.predict(
            processed
        )[0]

        probabilities = self._model.predict_proba(
            processed
        )[0]

        confidence = float(
            probabilities[prediction]
        )

        label = self._encoder.inverse_transform(
            [prediction]
        )[0]

        return label, confidence
