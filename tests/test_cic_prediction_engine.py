
import numpy as np
import pandas as pd
import pytest

import src.prediction.real_data.cic_prediction_engine as prediction_engine


class FakePreprocessor:
    n_features_in_ = 2

    def get_feature_names_out(self):
        return np.array(["feature_1", "feature_2"])

    def transform(self, dataframe):
        assert "Total Packets" in dataframe.columns
        assert "Total Bytes" in dataframe.columns
        return np.array([[1.0, 2.0]])


class FakeModel:
    n_features_in_ = 2

    def __init__(self, probabilities):
        self.probabilities = np.array(probabilities, dtype=float)

    def predict_proba(self, processed):
        assert processed.shape == (1, 2)
        return self.probabilities.reshape(1, -1)


class FakeEncoder:
    classes_ = np.array(["Benign", "Attack", "Web Attack XSS"])

    def inverse_transform(self, predictions):
        return self.classes_[predictions]


def make_engine(monkeypatch, probabilities, xss_threshold=0.42):
    artifact = {
        "model": FakeModel(probabilities),
        "preprocessor": FakePreprocessor(),
        "label_encoder": FakeEncoder(),
        "xss_index": 2,
        "xss_threshold": xss_threshold,
    }

    monkeypatch.setattr(
        prediction_engine,
        "load_cic_model",
        lambda path=None: artifact,
    )

    # Isolate prediction-engine tests from feature-engineering details.
    monkeypatch.setattr(
        prediction_engine,
        "add_cic_features",
        lambda dataframe: dataframe.assign(
            **{"Total Packets": 15, "Total Bytes": 1500}
        ),
    )

    monkeypatch.setattr(
        prediction_engine,
        "clean_invalid_values",
        lambda dataframe: dataframe,
    )

    return prediction_engine.CICPredictionEngine()


# Minimal complete set of fields required by add_cic_features().
VALID_FEATURES = {
    "Protocol": 6,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 5,
    "Fwd Packets Length Total": 1000,
    "Bwd Packets Length Total": 500,
    "Flow Duration": 1_000_000,
    "Fwd Packet Length Mean": 100,
    "Bwd Packet Length Mean": 100,
    "Flow IAT Max": 100,
    "Flow IAT Min": 10,
    "Fwd IAT Max": 100,
    "Fwd IAT Min": 10,
    "Bwd IAT Max": 100,
    "Bwd IAT Min": 10,
    "Fwd IAT Mean": 50,
    "Bwd IAT Mean": 50,
    "Fwd Header Length": 100,
    "Bwd Header Length": 50,
    "SYN Flag Count": 1,
    "ACK Flag Count": 1,
    "FIN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "URG Flag Count": 0,
    "ECE Flag Count": 0,
    "CWE Flag Count": 0,
    "Active Mean": 100,
    "Idle Mean": 100,
    "Fwd Packets/s": 10,
    "Bwd Packets/s": 5,
    "Flow Packets/s": 15,
    "Down/Up Ratio": 0.5,
}


def test_predicts_benign_when_xss_probability_is_below_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.90, 0.08, 0.02])

    prediction, confidence = engine.predict(VALID_FEATURES)

    assert prediction == "Benign"
    assert confidence == 0.90


def test_predicts_highest_probability_class_below_xss_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.25])

    prediction, confidence = engine.predict(VALID_FEATURES)

    assert prediction == "Benign"
    assert confidence == 0.40


def test_predicts_xss_at_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.42])

    prediction, confidence = engine.predict(VALID_FEATURES)

    assert prediction == "Web Attack XSS"
    assert confidence == 0.42


def test_predicts_xss_above_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.50])

    prediction, confidence = engine.predict(VALID_FEATURES)

    assert prediction == "Web Attack XSS"
    assert confidence == 0.50


def test_predict_rejects_missing_required_features(monkeypatch):
    engine = make_engine(monkeypatch, [0.90, 0.08, 0.02])

    with pytest.raises(
        ValueError,
        match="Missing required CIC-IDS2017 features",
    ):
        engine.predict({"Protocol": 6})
