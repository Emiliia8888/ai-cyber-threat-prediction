from abc import ABC, abstractmethod

from typing import Any


class PredictionEnginePort(ABC):

    """
    Interface for machine learning prediction.

    Application code depends on this abstraction,
    not on a concrete ML implementation.
    """

    @abstractmethod
    def predict(
        self,
        features: dict[str, Any],
    ) -> tuple[str, float]:
        raise NotImplementedError
