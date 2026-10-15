import numpy as np
import pandas as pd

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


def test_predicts_benign_when_xss_probability_is_below_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.90, 0.08, 0.02])

    prediction, confidence = engine.predict({"Protocol": 6})

    assert prediction == "Benign"
    assert confidence == 0.90


def test_predicts_highest_probability_class_below_xss_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.25])

    prediction, confidence = engine.predict({"Protocol": 6})

    assert prediction == "Benign"
    assert confidence == 0.40


def test_predicts_xss_at_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.42])

    prediction, confidence = engine.predict({"Protocol": 6})

    assert prediction == "Web Attack XSS"
    assert confidence == 0.42


def test_predicts_xss_above_threshold(monkeypatch):
    engine = make_engine(monkeypatch, [0.40, 0.35, 0.50])

    prediction, confidence = engine.predict({"Protocol": 6})

    assert prediction == "Web Attack XSS"
    assert confidence == 0.50
