from src.detection.severity import calculate_event_severity


def test_high_severity_event():
    events = [
        {"type": "port_scan"},
        {"type": "failed_login"},
        {"type": "successful_login"},
    ]

    result = calculate_event_severity(events)

    assert {
        "level": "HIGH",
        "message": "Successful login after failed attempts detected",
    } in result


def test_medium_severity_event():
    events = [
        {"type": "port_scan"},
    ]

    result = calculate_event_severity(events)

    assert {
        "level": "MEDIUM",
        "message": "Port scan activity detected",
    } in result


def test_no_activity_severity():
    events = []

    result = calculate_event_severity(events)

    assert result == [
        {
            "level": "LOW",
            "message": "No significant suspicious activity detected",
        }
    ]

