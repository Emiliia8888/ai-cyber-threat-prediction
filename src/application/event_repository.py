from abc import ABC, abstractmethod
from typing import Any


class EventRepositoryPort(ABC):
    """
    Application-level interface for event persistence.

    Application code depends on this abstraction,
    not on a concrete database implementation.
    """

    @abstractmethod
    def save_events(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_events(self) -> list[dict[str, Any]]:
        raise NotImplementedError
