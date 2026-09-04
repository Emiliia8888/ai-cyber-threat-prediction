from src.prediction.features import extract_features, features_to_vector
from src.preprocessing.normalize import normalize_events, add_time_differences

def test_extract_features():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:30",
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00",
        },
    ]

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    assert features["port_scan_count"] == 1
    assert features["failed_login_count"] == 2
    assert features["successful_login_count"] == 1
    assert features["port_scan_followed_by_failed_login"] == 1

def test_features_to_vector():

    features = {
        "port_scan_count": 1,
        "failed_login_count": 2,
        "successful_login_count": 1,
        "port_scan_followed_by_failed_login": 1,
    }

    vector = features_to_vector(features)

    assert vector == [1, 2, 1, 1]

def test_port_scan_followed_by_failed_login():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
        },
    ]

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    assert features["port_scan_followed_by_failed_login"] == 1


def test_port_scan_followed_by_failed_login_wrong_order():
    events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
        },
    ]

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    assert features["port_scan_followed_by_failed_login"] == 0


def test_port_scan_followed_by_failed_login_too_late():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:23:00",
        },
    ]

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    assert features["port_scan_followed_by_failed_login"] == 0

def test_port_scan_followed_by_failed_login_different_sources():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_02",
            "timestamp": "2026-09-02 16:19:00",
        },
    ]

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    assert features["port_scan_followed_by_failed_login"] == 0
