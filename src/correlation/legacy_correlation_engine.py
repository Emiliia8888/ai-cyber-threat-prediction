from typing import Any

from src.application.correlation_ports import CorrelationEnginePort
from src.correlation.correlation_engine import CorrelationEngine


class LegacyCorrelationEngine(CorrelationEnginePort):
    """
    Adapter connecting the application correlation interface
    with the existing CorrelationEngine implementation.
    """

    def __init__(self) -> None:
        self._engine = CorrelationEngine()

    def correlate(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return self._engine.correlate(events)
