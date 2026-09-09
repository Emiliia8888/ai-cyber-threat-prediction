from dataclasses import dataclass
from typing import Any

from src.application.correlation_result import CorrelationResult


@dataclass(frozen=True)
class AnalysisResult:
    """
    Structured result of a complete cyber threat analysis.

    This model provides a stable application-level contract
    for pipeline consumers while preserving compatibility
    with the existing dictionary-based API.
    """

    prediction: str
    confidence: float
    threat_level: str
    attack_type: str
    agreement: bool
    explanation: list[str]
    severity: list[dict[str, Any]]
    features: dict[str, Any]
    correlations: list[CorrelationResult] | None = None
    attack_chain: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the analysis result to the dictionary format
        used by the existing application.
        """
        return {
            "prediction": self.prediction,
            "confidence": self.confidence,
            "threat_level": self.threat_level,
            "attack_type": self.attack_type,
            "agreement": self.agreement,
            "explanation": self.explanation,
            "severity": self.severity,
            "features": self.features,
            "correlations": (
                [
                    correlation.to_dict()
                    for correlation in self.correlations
                ]
                if self.correlations is not None
                else None
            ),
            "attack_chain": self.attack_chain,
        }

    def __getitem__(self, key: str) -> Any:
        """
        Preserve compatibility with the previous dictionary-based
        result interface.

        Example:
            result["prediction"]
        """
        return self.to_dict()[key]
