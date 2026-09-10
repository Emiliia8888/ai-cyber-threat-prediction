from typing import Any

from src.application.correlation_ports import CorrelationEnginePort
from src.application.risk_assessment import RiskAssessment
from src.attack_chain.legacy_attack_chain_engine import LegacyAttackChainEngine
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
    Attack chain analysis consumes correlation results
    produced by the correlation engine.
    The result is represented by the typed RiskAssessment model.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEnginePort,
        attack_chain_engine: AttackChainEnginePort,
    ) -> None:
        self.correlation_engine = correlation_engine
        self.attack_chain_engine = attack_chain_engine

    def assess(
        self,
        events: list[dict[str, Any]],
        ml_prediction: str,
    ) -> RiskAssessment:
        threat_level = assess_threat_level(events)

        attack_type = detect_attack_type(events)

        agreement = compare_assessments(
            ml_prediction,
            threat_level,
        )

        explanation = explain_risk(events)

        severity = calculate_event_severity(events)

        correlations = self.correlation_engine.correlate(events)

        attack_chain = self.attack_chain_engine.build_chain_from_correlations(
            correlations
        )

        return RiskAssessment(
            threat_level=threat_level,
            attack_type=attack_type,
            agreement=agreement,
            explanation=explanation,
            severity=severity,
            correlations=correlations,
            attack_chain=attack_chain,
        )
