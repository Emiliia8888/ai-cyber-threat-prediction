from src.detection.explanation import explain_risk


def test_high_risk_explanation():
    events = [
        {"type": "port_scan"},
        {"type": "failed_login"},
        {"type": "successful_login"},
    ]

    explanation = explain_risk(events)

    assert "Port scan activity detected" in explanation
    assert "Failed login attempts detected" in explanation
    assert "Successful login after failed attempts detected" in explanation


def test_normal_explanation():
    events = []

    explanation = explain_risk(events)

    assert "No significant suspicious activity detected" in explanation

