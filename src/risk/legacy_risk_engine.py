from typing import Any

from src.application.interfaces import RiskEnginePort
from src.application.risk_assessment import RiskAssessment
from src.risk.risk_engine import RiskEngine


class LegacyRiskEngine(RiskEnginePort):
    """
    Adapter connecting the application risk interface
    with the existing RiskEngine implementation.
    """

    def __init__(self) -> None:
        self._engine = RiskEngine()

    def assess(
        self,
        events: list[dict[str, Any]],
        ml_prediction: str,
    ) -> RiskAssessment:
        return self._engine.assess(
            events,
            ml_prediction,
        )
