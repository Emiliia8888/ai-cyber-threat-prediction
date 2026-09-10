from abc import ABC, abstractmethod
from typing import Any


class PreprocessingPort(ABC):
    """
    Application-level interface for event preprocessing.

    Application code depends on this abstraction,
    not on a concrete preprocessing implementation.
    """

    @abstractmethod
    def preprocess(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        raise NotImplementedError
