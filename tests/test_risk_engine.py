from datetime import timedelta

from src.attack_chain.legacy_attack_chain_engine import (
    LegacyAttackChainEngine,
)
from src.correlation.legacy_correlation_engine import (
    LegacyCorrelationEngine,
)
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
            "time_since_previous": timedelta(
                seconds=60
            ),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:20:00",
            "time_since_previous": timedelta(
                seconds=60
            ),
        },
    ]

    engine = RiskEngine(
        correlation_engine=LegacyCorrelationEngine(),
        attack_chain_engine=LegacyAttackChainEngine(),
    )

    result = engine.assess(
        events,
        "high",
    )

    assert result.threat_level == "high"
    assert result.attack_type == "multi_stage_attack"
    assert result.agreement is True
    assert len(result.explanation) > 0
    assert len(result.severity) > 0
    assert len(result.correlations) == 2
    assert result.attack_chain is not None
