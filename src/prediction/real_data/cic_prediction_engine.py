from typing import Any

import pandas as pd

from src.prediction.real_data.cic_feature_engineering import (
    add_cic_features,
)
from src.prediction.real_data.cic_model_persistence import (
    XGBOOST_TUNING_MODEL_PATH,
    load_cic_model,
)
from src.prediction.real_data.cic_preprocessing import (
    clean_invalid_values,
)


class CICPredictionEngine:
    """
    Prediction engine for CIC-IDS2017 network-flow data.

    Loads a persisted model, preprocessor, and label encoder.
    Applies the same feature-engineering and preprocessing steps
    before prediction, without retraining the model.
    """

    def __init__(self) -> None:
        artifact = load_cic_model(XGBOOST_TUNING_MODEL_PATH)

        self._model = artifact["model"]
        self._preprocessor = artifact["preprocessor"]
        self._encoder = artifact["label_encoder"]
        self._xss_index = int(artifact["xss_index"])
        self._xss_threshold = float(artifact["xss_threshold"])

        if not 0 <= self._xss_index < len(self._encoder.classes_):
            raise ValueError(
                f"Invalid XSS class index: {self._xss_index}"
            )

        if not 0.0 <= self._xss_threshold <= 1.0:
            raise ValueError(
                f"Invalid XSS threshold: {self._xss_threshold}"
            )

        if self._model.n_features_in_ != len(
            self._preprocessor.get_feature_names_out()
        ):
            raise ValueError(
                "Model and preprocessor feature counts do not match."
            )


    def predict(
        self,
        features: dict[str, Any],
    ) -> tuple[str, float]:
        """
        Predict a CIC-IDS2017 traffic class.

        Raises:
            ValueError: If required input features are missing.

        Returns:
            A tuple containing the predicted class label and its
            predicted probability.
        """
        required_features = [
            "Total Fwd Packets",
            "Total Backward Packets",
            "Fwd Packets Length Total",
            "Bwd Packets Length Total",
            "Flow Duration",
            "Fwd Packet Length Mean",
            "Bwd Packet Length Mean",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd IAT Mean",
            "Bwd IAT Mean",
            "Fwd Header Length",
            "Bwd Header Length",
            "SYN Flag Count",
            "ACK Flag Count",
            "FIN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "URG Flag Count",
            "ECE Flag Count",
            "CWE Flag Count",
            "Active Mean",
            "Idle Mean",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Flow Packets/s",
            "Down/Up Ratio",
        ]

        missing = [
            name for name in required_features
            if name not in features
        ]

        if missing:
            raise ValueError(
                "Missing required CIC-IDS2017 features: "
                + ", ".join(missing)
            )

        dataframe = pd.DataFrame([features])
        dataframe = add_cic_features(dataframe)
        dataframe = clean_invalid_values(dataframe)

        processed = self._preprocessor.transform(dataframe)
        probabilities = self._model.predict_proba(processed)[0]

        if len(probabilities) != len(self._encoder.classes_):
            raise ValueError(
                "Model probability count does not match encoder classes."
            )

        prediction = int(probabilities.argmax())

        if probabilities[self._xss_index] >= self._xss_threshold:
            prediction = self._xss_index

        label = str(
            self._encoder.inverse_transform([prediction])[0]
        )
        confidence = float(probabilities[prediction])

        return label, confidence
