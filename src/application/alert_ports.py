from abc import ABC, abstractmethod


class AlertEnginePort(ABC):

    """
    Application-level interface for alert generation.

    Application code depends on this abstraction,
    not on a concrete alert implementation.
    """

    @abstractmethod
    def generate(
        self,
        attack_type: str,
        threat_level: str,
        confidence: float,
    ) -> str:
        raise NotImplementedError
