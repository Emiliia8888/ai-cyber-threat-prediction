from abc import ABC, abstractmethod
from typing import Any


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
