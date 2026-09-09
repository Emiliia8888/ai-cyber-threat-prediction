from datetime import datetime

from src.domain.event import Event
from src.features.feature_engine import FeatureEngine


def test_feature_engine_extracts_legacy_features():
    events = [
        Event(
            event_type="port_scan",
            source="server_01",
            timestamp=datetime(2026, 9, 2, 16, 18, 0),
        ),
        Event(
            event_type="failed_login",
            source="server_01",
            timestamp=datetime(2026, 9, 2, 16, 19, 0),
        ),
        Event(
            event_type="successful_login",
            source="server_01",
            timestamp=datetime(2026, 9, 2, 16, 20, 0),
        ),
    ]

    engine = FeatureEngine()

    features = engine.extract_from_domain_events(events)

    assert features["port_scan_count"] == 1
    assert features["failed_login_count"] == 1
    assert features["successful_login_count"] == 1
    assert features["port_scan_followed_by_failed_login"] == 1


def test_feature_engine_can_still_use_raw_events():
    events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
            "time_since_previous": None,
        }
    ]

    engine = FeatureEngine()

    features = engine.extract(events)

    assert features["failed_login_count"] == 1
