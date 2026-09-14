from src.prediction.legacy_prediction_engine import LegacyPredictionEngine


def test_legacy_prediction_engine_predicts_high_threat():
    engine = LegacyPredictionEngine()

    features = {
        "port_scan_count": 1,
        "failed_login_count": 1,
        "successful_login_count": 1,
        "event_count": 3,
        "unique_source_count": 1,
        "time_span_seconds": 45.0,
        "failed_login_rate": 1 / 45,
        "successful_login_rate": 1 / 45,
        "rapid_failed_login_count": 0,
        "port_scan_followed_by_failed_login": 1,
        "failed_login_followed_by_successful_login": 1,
    }

    prediction, confidence = engine.predict(features)

    assert prediction == "high"
    assert 0.0 <= confidence <= 1.0
    assert confidence > 0.9


def test_legacy_prediction_engine_predicts_normal_threat():
    engine = LegacyPredictionEngine()

    features = {
        "port_scan_count": 0,
        "failed_login_count": 0,
        "successful_login_count": 4,
        "event_count": 4,
        "unique_source_count": 1,
        "time_span_seconds": 600.0,
        "failed_login_rate": 0.0,
        "successful_login_rate": 4 / 600,
        "rapid_failed_login_count": 0,
        "port_scan_followed_by_failed_login": 0,
        "failed_login_followed_by_successful_login": 0,
    }

    prediction, confidence = engine.predict(features)

    assert prediction == "normal"
    assert 0.0 <= confidence <= 1.0
