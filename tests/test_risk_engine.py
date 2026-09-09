from src.risk.risk_engine import RiskEngine


def test_risk_engine_combines_existing_risk_logic():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
            "time_since_previous": None,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
            "time_since_previous": __import__("datetime").timedelta(
                seconds=60
            ),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00",
            "time_since_previous": __import__("datetime").timedelta(
                seconds=60
            ),
        },
    ]

    engine = RiskEngine()

    result = engine.assess(
        events,
        ml_prediction="high",
    )

    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"
    assert result["agreement"] is True

    assert len(result["explanation"]) > 0
    assert len(result["severity"]) > 0
