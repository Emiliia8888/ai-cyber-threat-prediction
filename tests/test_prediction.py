from src.preprocessing.events import events
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import prepare_data, train_model, predict_threat


def test_predict_high_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    features = features_to_vector(extract_features(events))

    prediction = predict_threat(model, features)

    assert prediction == "high"

def test_predict_medium_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [1, 1, 0])

    assert prediction == "medium"


def test_predict_low_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [0, 1, 0])

    assert prediction == "low"


def test_predict_normal_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [0, 0, 0])

    assert prediction == "normal"

from src.main import predict_threat_from_events


def test_pipeline_high_threat():

    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00"
        }
    ]

    ml_prediction, threat_level = predict_threat_from_events(test_events)

    assert ml_prediction == "high"
    assert threat_level == "high"


def test_pipeline_medium_threat():

    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        }
    ]

    ml_prediction, threat_level = predict_threat_from_events(test_events)

    assert ml_prediction == "medium"
    assert threat_level == "medium"

