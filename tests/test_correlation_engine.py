from datetime import datetime, timedelta

from src.correlation.correlation_engine import CorrelationEngine


def test_detect_port_scan_followed_by_failed_login():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=30),
        },
    ]

    correlations = CorrelationEngine().correlate(events)

    assert len(correlations) == 1
    assert correlations[0]["sequence"] == "port_scan -> failed_login"
    assert correlations[0]["source"] == "server_01"
    assert correlations[0]["time_difference_seconds"] == 30


def test_detect_failed_login_followed_by_successful_login():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=20),
        },
    ]

    correlations = CorrelationEngine().correlate(events)

    assert len(correlations) == 1
    assert correlations[0]["sequence"] == "failed_login -> successful_login"


def test_ignore_events_from_different_sources():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_02",
            "timestamp": start + timedelta(seconds=30),
        },
    ]

    correlations = CorrelationEngine().correlate(events)

    assert correlations == []


def test_ignore_events_outside_time_window():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=61),
        },
    ]

    correlations = CorrelationEngine().correlate(events)

    assert correlations == []


def test_ignore_events_in_wrong_order():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=30),
        },
    ]

    correlations = CorrelationEngine().correlate(events)

    assert correlations == []
