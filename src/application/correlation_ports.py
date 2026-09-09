from abc import ABC, abstractmethod
from typing import Any

from src.application.correlation_result import CorrelationResult


class CorrelationEnginePort(ABC):
    """
    Application-level interface for event correlation.
    """

    @abstractmethod
    def correlate(
        self,
        events: list[dict[str, Any]],
    ) -> list[CorrelationResult]:
        raise NotImplementedError
