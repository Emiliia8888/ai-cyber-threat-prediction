import numpy as np

import src.prediction.real_data.cic_prediction_engine as prediction_engine


class FakePreprocessor:
    def transform(self, dataframe):
        assert "Total Packets" in dataframe.columns
        assert "Total Bytes" in dataframe.columns
        return np.array([[1.0, 2.0]])


class FakeModel:
    def predict(self, processed):
        assert processed.shape == (1, 2)
        return np.array([0])

    def predict_proba(self, processed):
        return np.array([[0.9, 0.1]])


class FakeEncoder:
    def inverse_transform(self, predictions):
        return np.array(["Benign"])


def test_cic_prediction_engine_predicts_benign(monkeypatch):
    artifact = {
        "model": FakeModel(),
        "preprocessor": FakePreprocessor(),
        "label_encoder": FakeEncoder(),
    }

    monkeypatch.setattr(
        prediction_engine,
        "load_cic_model",
        lambda: artifact,
    )

    engine = prediction_engine.CICPredictionEngine()

    sample = {
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Fwd Packets Length Total": 1000,
        "Bwd Packets Length Total": 500,
        "Flow Duration": 1000000,
        "Fwd Packet Length Mean": 100,
        "Bwd Packet Length Mean": 100,
        "Flow IAT Max": 100,
        "Flow IAT Min": 10,
        "Fwd IAT Max": 100,
        "Fwd IAT Min": 10,
        "Bwd IAT Max": 100,
        "Bwd IAT Min": 10,
        "Fwd IAT Mean": 20,
        "Bwd IAT Mean": 20,
        "Fwd Header Length": 20,
        "Bwd Header Length": 20,
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

    prediction, confidence = engine.predict(sample)

    assert prediction == "Benign"
    assert confidence == 0.9
