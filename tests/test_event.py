from datetime import datetime

from src.domain.event import Event


def test_event_from_dict():
    data = {
        "event_type": "failed_login",
        "source": "server_01",
        "timestamp": "2026-01-01 12:00:00",
    }

    event = Event.from_dict(data)

    assert event.event_type == "failed_login"
    assert event.source == "server_01"
    assert event.timestamp == datetime(2026, 1, 1, 12, 0, 0)


def test_event_to_dict():
    event = Event(
        event_type="port_scan",
        source="server_01",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )

    assert event.to_dict() == {
        "event_type": "port_scan",
        "source": "server_01",
        "timestamp": "2026-01-01 12:00:00",
    }
