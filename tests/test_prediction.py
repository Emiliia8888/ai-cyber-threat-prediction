from src.preprocessing.events import events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import prepare_data, train_model, predict_threat
from src.preprocessing.event_loader import load_events
from src.prediction.evaluate import load_evaluation_data
from src.main import predict_threat_from_events

def test_predict_high_threat():
    test_events = [event.copy() for event in events]

    normalize_events(test_events)
    add_time_differences(test_events)

    X, y = prepare_data()
    model = train_model(X, y)

    features = features_to_vector(extract_features(test_events))
    prediction = predict_threat(model, features)

    assert prediction == "high"

def test_predict_medium_threat():
    X, y = prepare_data()
    model = train_model(X, y)

    prediction = predict_threat(model, [1, 1, 0, 1])

    assert prediction == "medium"


def test_predict_low_threat():
    X, y = prepare_data()
    model = train_model(X, y)

    prediction = predict_threat(model, [0, 1, 0, 0])

    assert prediction == "low"


def test_predict_normal_threat():
    X, y = prepare_data()
    model = train_model(X, y)

    prediction = predict_threat(model, [0, 0, 0, 0])

    assert prediction == "normal"

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

    ml_prediction, confidence, threat_level, agreement = predict_threat_from_events(test_events)

    assert ml_prediction == "medium"
    assert threat_level == "medium"
    assert 0.0 <= confidence <= 1.0

def test_pipeline_failed_login_threat():

    test_events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-04 10:00:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-04 10:01:00"
        }
    ]

    ml_prediction, confidence, threat_level, agreement = predict_threat_from_events(test_events)

    assert ml_prediction == "low"
    assert threat_level == "low"
    assert agreement is True
    assert 0.0 <= confidence <= 1.0

def test_load_events_from_json():

    events = load_events("data/events.json")

    assert len(events) == 3
    assert events[0]["type"] == "port_scan"
    assert events[1]["type"] == "failed_login"
    assert events[2]["type"] == "successful_login"

def test_evaluation_dataset():

    data = load_evaluation_data("data/evaluation.json")

    assert len(data) == 12

    labels = [item["label"] for item in data]

    assert labels.count("normal") == 3
    assert labels.count("low") == 3
    assert labels.count("medium") == 3
    assert labels.count("high") == 3

def test_cli_help():

    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--help"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "AI Cyber Threat Prediction System" in result.stdout
    assert "events_file" in result.stdout

def test_predict_high_threat_with_unseen_feature_counts():
    X, y = prepare_data()
    model = train_model(X, y)

    prediction = predict_threat(model, [5, 5, 5, 1])

    assert prediction == "high"

def test_pipeline_returns_agreement():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-04 10:00:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-04 10:01:00"
        }
    ]

    ml_prediction, confidence, threat_level, agreement = predict_threat_from_events(
        test_events
    )

    assert agreement is True
    assert ml_prediction == threat_level

def test_feature_importance_contains_all_features():
    from src.prediction.model import get_feature_importance

    X, y = prepare_data()
    model = train_model(X, y)

    importance = get_feature_importance(model)

    assert set(importance.keys()) == {
        "port_scan_count",
        "failed_login_count",
        "successful_login_count",
        "port_scan_followed_by_failed_login",
    }

    assert all(0.0 <= value <= 1.0 for value in importance.values())
