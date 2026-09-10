from typing import Any

from src.application.attack_chain_ports import AttackChainEnginePort
from src.application.correlation_ports import CorrelationEnginePort
from src.application.interfaces import RiskEnginePort
from src.application.risk_assessment import RiskAssessment
from src.risk.risk_engine import RiskEngine


class LegacyRiskEngine(RiskEnginePort):
    """
    Adapter connecting the application risk interface
    with the existing RiskEngine implementation.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEnginePort,
        attack_chain_engine: AttackChainEnginePort,
    ) -> None:
        self._engine = RiskEngine(
            correlation_engine=correlation_engine,
            attack_chain_engine=attack_chain_engine,
        )

    def assess(
        self,
        events: list[dict[str, Any]],
        ml_prediction: str,
    ) -> RiskAssessment:
        return self._engine.assess(
            events,
            ml_prediction,
        )
