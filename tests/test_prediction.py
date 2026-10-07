from src.preprocessing.events import events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import (
    predict_threat,
    predict_threat_with_confidence,
    get_feature_importance,
)
from src.prediction.persistence import load_model
from src.preprocessing.event_loader import load_events
from src.main import predict_threat_from_events


def test_predict_high_threat():
    test_events = [event.copy() for event in events]

    normalize_events(test_events)
    add_time_differences(test_events)

    model = load_model()
    features = features_to_vector(extract_features(test_events))

    prediction = predict_threat(model, features)

    assert prediction == "high"


def test_predict_medium_threat():
    model = load_model()

    features = {
        "port_scan_count": 3,
        "failed_login_count": 0,
        "successful_login_count": 0,
        "event_count": 3,
        "unique_source_count": 1,
        "time_span_seconds": 120.0,
        "failed_login_rate": 0.0,
        "successful_login_rate": 0.0,
        "rapid_failed_login_count": 0,
        "port_scan_followed_by_failed_login": 0,
        "failed_login_followed_by_successful_login": 0,
    }

    prediction = predict_threat(
        model,
        features_to_vector(features),
    )

    assert prediction == "medium"


def test_predict_low_threat():
    model = load_model()

    features = {
        "port_scan_count": 0,
        "failed_login_count": 3,
        "successful_login_count": 0,
        "event_count": 3,
        "unique_source_count": 1,
        "time_span_seconds": 157.0,
        "failed_login_rate": 3 / 157,
        "successful_login_rate": 0.0,
        "rapid_failed_login_count": 0,
        "port_scan_followed_by_failed_login": 0,
        "failed_login_followed_by_successful_login": 0,
    }

    prediction = predict_threat(
        model,
        features_to_vector(features),
    )

    assert prediction == "low"


def test_predict_normal_threat():
    model = load_model()

    features = {
        "port_scan_count": 0,
        "failed_login_count": 0,
        "successful_login_count": 5,
        "event_count": 5,
        "unique_source_count": 1,
        "time_span_seconds": 600.0,
        "failed_login_rate": 0.0,
        "successful_login_rate": 5 / 600,
        "rapid_failed_login_count": 0,
        "port_scan_followed_by_failed_login": 0,
        "failed_login_followed_by_successful_login": 0,
    }

    prediction = predict_threat(
        model,
        features_to_vector(features),
    )

    assert prediction == "normal"


def test_prediction_confidence_is_valid():
    model = load_model()

    features = {
        "port_scan_count": 2,
        "failed_login_count": 2,
        "successful_login_count": 1,
        "event_count": 5,
        "unique_source_count": 1,
        "time_span_seconds": 120.0,
        "failed_login_rate": 2 / 120,
        "successful_login_rate": 1 / 120,
        "rapid_failed_login_count": 1,
        "port_scan_followed_by_failed_login": 1,
        "failed_login_followed_by_successful_login": 1,
    }

    prediction, confidence = predict_threat_with_confidence(
        model,
        features_to_vector(features),
    )

    assert prediction == "high"
    assert 0.0 <= confidence <= 1.0


def test_feature_vector_contains_11_features():
    test_events = [event.copy() for event in events]

    normalize_events(test_events)
    add_time_differences(test_events)

    features = extract_features(test_events)
    vector = features_to_vector(features)

    assert len(vector) == 11


def test_feature_importance_contains_all_features():
    model = load_model()
    importance = get_feature_importance(model)

    assert set(importance.keys()) == {
        "port_scan_count",
        "failed_login_count",
        "successful_login_count",
        "event_count",
        "unique_source_count",
        "time_span_seconds",
        "failed_login_rate",
        "successful_login_rate",
        "rapid_failed_login_count",
        "port_scan_followed_by_failed_login",
        "failed_login_followed_by_successful_login",
    }

    assert all(value >= 0.0 for value in importance.values())


def test_pipeline_high_threat():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:20",
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:40",
        },
    ]

    (
        ml_prediction,
        confidence,
        threat_level,
        agreement,
        attack_type,
    ) = predict_threat_from_events(test_events)

    assert ml_prediction == "high"
    assert threat_level == "high"
    assert agreement is True
    assert attack_type == "multi_stage_attack"
    assert 0.0 <= confidence <= 1.0


def test_pipeline_normal_threat():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-04 10:00:00",
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-04 10:02:00",
        },
    ]

    (
        ml_prediction,
        confidence,
        threat_level,
        agreement,
        attack_type,
    ) = predict_threat_from_events(test_events)

    assert ml_prediction == "normal"
    assert threat_level == "normal"
    assert agreement is True
    assert attack_type == "port_scanning"
    assert 0.0 <= confidence <= 1.0


def test_load_events_from_json():
    loaded_events = load_events("data/events.json")

    assert len(loaded_events) == 3
    assert loaded_events[0]["type"] == "port_scan"
    assert loaded_events[1]["type"] == "failed_login"
    assert loaded_events[2]["type"] == "successful_login"


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
