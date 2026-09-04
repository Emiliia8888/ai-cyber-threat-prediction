from src.preprocessing.events import events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.detection.rules import assess_threat_level


def test_high_threat():
    test_events = [event.copy() for event in events]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "high"

def test_medium_threat():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "medium"

def test_low_threat():
    test_events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "low"


def test_failed_login_threat():

    test_events = [

        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },

        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        }

    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "low"

def test_normal_threat():
    test_events = [
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "normal"

def test_port_scan_and_failed_login_too_late():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:23:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "normal"

def test_wrong_event_order():
    test_events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "normal"

def test_different_sources():
    test_events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00"
        },
        {
            "type": "failed_login",
            "source": "server_02",
            "timestamp": "2026-09-02 16:19:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "normal"

def test_different_sources_failed_login_successful_login():
    test_events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00"
        },
        {
            "type": "successful_login",
            "source": "server_02",
            "timestamp": "2026-09-02 16:20:00"
        }
    ]

    normalize_events(test_events)
    add_time_differences(test_events)

    assert assess_threat_level(test_events) == "normal"
