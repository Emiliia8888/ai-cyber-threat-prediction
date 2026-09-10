from typing import Any

from src.application.interfaces import FeatureEnginePort
from src.domain.event import Event
from src.features.feature_engine import FeatureEngine


class LegacyFeatureEngine(FeatureEnginePort):
    """
    Adapter connecting the application feature interface
    with the existing FeatureEngine implementation.
    """

    def __init__(self) -> None:
        self._engine = FeatureEngine()

    def extract(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return self._engine.extract(events)

    def extract_from_domain_events(
        self,
        events: list[Event],
    ) -> dict[str, Any]:
        return self._engine.extract_from_domain_events(events)
