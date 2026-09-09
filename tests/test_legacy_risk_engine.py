from src.risk.legacy_risk_engine import LegacyRiskEngine


def test_legacy_risk_engine_assesses_threat():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:30",
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
        },
    ]

    from src.preprocessing.normalize import (
        normalize_events,
        add_time_differences,
    )

    normalize_events(events)
    add_time_differences(events)

    engine = LegacyRiskEngine()

    result = engine.assess(
        events,
        "high",
    )

    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"
    assert result["agreement"] is True
    assert len(result["explanation"]) > 0
    assert len(result["severity"]) > 0
