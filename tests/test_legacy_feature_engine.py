from src.domain.event import Event
from src.features.legacy_feature_engine import LegacyFeatureEngine


def test_legacy_feature_engine_extracts_features():
    events = [
        Event.from_dict(
            {
                "type": "port_scan",
                "source": "server_01",
                "timestamp": "2026-09-02 16:18:00",
            }
        ),
        Event.from_dict(
            {
                "type": "failed_login",
                "source": "server_01",
                "timestamp": "2026-09-02 16:18:30",
            }
        ),
    ]

    engine = LegacyFeatureEngine()

    features = engine.extract_from_domain_events(events)

    assert features["port_scan_count"] == 1
    assert features["failed_login_count"] == 1
    assert features["successful_login_count"] == 0
    assert features["port_scan_followed_by_failed_login"] == 1
