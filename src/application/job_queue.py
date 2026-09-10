from abc import ABC, abstractmethod
from typing import Any


class JobQueuePort(ABC):
    """
    Application-level interface for asynchronous job processing.
    """

    @abstractmethod
    def enqueue(
        self,
        job: dict[str, Any],
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def dequeue(self) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def size(self) -> int:
        raise NotImplementedError
