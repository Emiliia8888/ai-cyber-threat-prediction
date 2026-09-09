from abc import ABC, abstractmethod
from typing import Any


class CorrelationEnginePort(ABC):
    """
    Application-level interface for event correlation.
    """

    @abstractmethod
    def correlate(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        raise NotImplementedError
