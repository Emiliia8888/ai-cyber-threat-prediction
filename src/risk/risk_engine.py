from typing import Any

from src.detection.assessment import compare_assessments
from src.detection.attack_type import detect_attack_type
from src.detection.explanation import explain_risk
from src.detection.rules import assess_threat_level
from src.detection.severity import calculate_event_severity


class RiskEngine:
    """
    Application-level risk assessment interface.

    Existing detection logic remains unchanged.
    This layer provides one stable interface for future
    hybrid risk scoring and correlation logic.
    """

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

        return {
            "threat_level": threat_level,
            "attack_type": attack_type,
            "agreement": agreement,
            "explanation": explanation,
            "severity": severity,
        }
