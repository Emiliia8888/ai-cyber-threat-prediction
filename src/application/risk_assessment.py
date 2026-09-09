from dataclasses import dataclass
from typing import Any

from src.application.correlation_result import CorrelationResult


@dataclass(frozen=True)
class RiskAssessment:
    """
    Structured result of application-level risk assessment.
    """

    threat_level: str
    attack_type: str
    agreement: bool
    explanation: list[str]
    severity: list[dict[str, Any]]
    correlations: list[CorrelationResult | dict[str, Any]]
    attack_chain: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_level": self.threat_level,
            "attack_type": self.attack_type,
            "agreement": self.agreement,
            "explanation": self.explanation,
            "severity": self.severity,
            "correlations": [
                (
                    correlation.to_dict()
                    if isinstance(correlation, CorrelationResult)
                    else correlation
                )
                for correlation in self.correlations
            ],
            "attack_chain": self.attack_chain,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]
