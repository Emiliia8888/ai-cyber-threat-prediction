from typing import Any

from src.attack_chain.attack_chain_engine import AttackChainEngine
from src.correlation.correlation_engine import CorrelationEngine
from src.detection.assessment import compare_assessments
from src.detection.attack_type import detect_attack_type
from src.detection.explanation import explain_risk
from src.detection.rules import assess_threat_level
from src.detection.severity import calculate_event_severity


class RiskEngine:
    """
    Application-level risk assessment interface.

    Existing detection logic remains unchanged.

    Correlation analysis detects temporal relationships
    between events.

    Attack chain analysis builds higher-level multi-stage
    attack sequences from the event stream.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEngine | None = None,
        attack_chain_engine: AttackChainEngine | None = None,
    ) -> None:
        self.correlation_engine = (
            correlation_engine
            if correlation_engine is not None
            else CorrelationEngine()
        )

        self.attack_chain_engine = (
            attack_chain_engine
            if attack_chain_engine is not None
            else AttackChainEngine()
        )

    def assess(
        self,
        events: list[dict[str, Any]],
        ml_prediction: str,
    ) -> dict[str, Any]:

        threat_level = assess_threat_level(events)

        attack_type = detect_attack_type(events)

        agreement = compare_assessments(
            ml_prediction,
            threat_level,
        )

        explanation = explain_risk(events)

        severity = calculate_event_severity(events)

        correlations = self.correlation_engine.correlate(events)

        attack_chain = self.attack_chain_engine.build_chain(events)

        return {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "agreement": agreement,
            "explanation": explanation,
            "severity": severity,
            "correlations": correlations,
            "attack_chain": attack_chain,
        }
