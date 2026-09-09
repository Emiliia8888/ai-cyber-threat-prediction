from abc import ABC, abstractmethod
from typing import Any

from src.application.correlation_result import CorrelationResult


class AttackChainEnginePort(ABC):
    """
    Application-level interface for attack chain analysis.
    """

    @abstractmethod
    def build_chain(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def build_chain_from_correlations(
        self,
        correlations: list[CorrelationResult | dict[str, Any]],
    ) -> dict[str, Any] | None:
        raise NotImplementedError
