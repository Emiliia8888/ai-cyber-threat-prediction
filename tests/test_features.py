from src.prediction.features import extract_features, features_to_vector


def test_extract_features():
    events = [
        {"type": "port_scan"},
        {"type": "failed_login"},
        {"type": "failed_login"},
        {"type": "successful_login"},
    ]

    features = extract_features(events)

    assert features["port_scan_count"] == 1
    assert features["failed_login_count"] == 2
    assert features["successful_login_count"] == 1


def test_features_to_vector():
    features = {
        "port_scan_count": 1,
        "failed_login_count": 2,
        "successful_login_count": 1,
    }

    vector = features_to_vector(features)

    assert vector == [1, 2, 1]
