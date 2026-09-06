from src.detection.alerts import generate_alert


def test_generate_alert_normal():
    result = generate_alert(
        "normal",
        "normal",
        1.0,
    )

    assert result == "No significant security threat detected"

def test_generate_alert_low():
    result = generate_alert(
        "credential_compromise",
        "low",
        1.0,
    )

    assert result == (
        "\u26a0\ufe0f SECURITY WARNING: "
        "credential_compromise detected "
        "(confidence: 100%)"
    )

def test_generate_alert_medium():
    result = generate_alert(
        "port_scanning",
        "medium",
        1.0,
    )

    assert result == (
        "\u26a0\ufe0f SECURITY ALERT: "
        "port_scanning detected "
        "(confidence: 100%)"
    )

def test_generate_alert_high():
    result = generate_alert(
        "multi_stage_attack",
        "high",
        1.0,
    )

    assert result == (
        "\U0001f6a8 CRITICAL SECURITY ALERT: "
        "multi_stage_attack detected "
        "(confidence: 100%)"
    )
