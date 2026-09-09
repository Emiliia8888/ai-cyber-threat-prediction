from src.alerts.legacy_alert_engine import LegacyAlertEngine


def test_legacy_alert_engine_generates_high_alert():
    engine = LegacyAlertEngine()

    result = engine.generate(
        "multi_stage_attack",
        "high",
        1.0,
    )

    assert result == (
        "\U0001f6a8 CRITICAL SECURITY ALERT: "
        "multi_stage_attack detected "
        "(confidence: 100%)"
    )


def test_legacy_alert_engine_generates_normal_result():
    engine = LegacyAlertEngine()

    result = engine.generate(
        "normal",
        "normal",
        1.0,
    )

    assert result == "No significant security threat detected"
