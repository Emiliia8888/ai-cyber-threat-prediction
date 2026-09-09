from src.prediction.legacy_prediction_engine import LegacyPredictionEngine


def test_legacy_prediction_engine_predicts_high_threat():
    engine = LegacyPredictionEngine()

    features = {
        "port_scan_count": 1,
        "failed_login_count": 1,
        "successful_login_count": 1,
        "port_scan_followed_by_failed_login": 1,
    }

    prediction, confidence = engine.predict(features)

    assert prediction == "high"
    assert confidence == 1.0


def test_legacy_prediction_engine_predicts_normal_threat():
    engine = LegacyPredictionEngine()

    features = {
        "port_scan_count": 0,
        "failed_login_count": 0,
        "successful_login_count": 1,
        "port_scan_followed_by_failed_login": 0,
    }

    prediction, confidence = engine.predict(features)

    assert prediction == "normal"
    assert confidence == 1.0
