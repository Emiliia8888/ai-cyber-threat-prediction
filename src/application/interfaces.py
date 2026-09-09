from abc import ABC, abstractmethod
from typing import Any

from src.application.risk_assessment import RiskAssessment
from src.domain.event import Event


class EventSourcePort(ABC):
    """
    Interface for event ingestion.

    Application code depends on this abstraction,
    not on a concrete data source such as JSON.
    """

    @abstractmethod
    def load(self, file_path: str) -> list[Event]:
        raise NotImplementedError


class FeatureEnginePort(ABC):
    """
    Interface for feature extraction.
    """

    @abstractmethod
    def extract_from_domain_events(
        self,
        events: list[Event],
    ) -> dict[str, Any]:
        raise NotImplementedError


class RiskEnginePort(ABC):
    """
    Interface for threat and risk assessment.
    """

    @abstractmethod
    def assess(
        self,
        events: list[dict[str, Any]],
        ml_prediction: str,
    ) -> RiskAssessment:
        raise NotImplementedError
