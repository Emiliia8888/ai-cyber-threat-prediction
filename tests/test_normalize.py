from datetime import datetime, timedelta

from src.preprocessing.normalize import (
    normalize_events,
    add_time_differences,
)


def test_normalize_events():
    events = [
        {
            "type": "port_scan",
            "timestamp": "2026-09-04 12:00:00",
        }
    ]

    result = normalize_events(events)

    assert isinstance(result[0]["timestamp"], datetime)
    assert result[0]["timestamp"] == datetime(2026, 9, 4, 12, 0, 0)


def test_add_time_differences():
    events = [
        {
            "type": "port_scan",
            "timestamp": "2026-09-04 12:00:00",
        },
        {
            "type": "failed_login",
            "timestamp": "2026-09-04 12:01:00",
        },
        {
            "type": "successful_login",
            "timestamp": "2026-09-04 12:03:00",
        },
    ]

    normalize_events(events)
    result = add_time_differences(events)

    assert "time_since_previous" not in result[0]
    assert result[1]["time_since_previous"] == timedelta(minutes=1)
    assert result[2]["time_since_previous"] == timedelta(minutes=2)
