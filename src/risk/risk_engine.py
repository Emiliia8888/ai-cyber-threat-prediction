from typing import Any

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

    Correlation analysis is added as an independent layer
    for detecting temporal relationships between events.
    """

    def __init__(
        self,
        correlation_engine: CorrelationEngine | None = None,
    ) -> None:
        self.correlation_engine = (
            correlation_engine
            if correlation_engine is not None
            else CorrelationEngine()
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

        return {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "agreement": agreement,
            "explanation": explanation,
            "severity": severity,
            "correlations": correlations,
        }
