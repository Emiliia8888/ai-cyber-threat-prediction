from typing import Any

from src.application.correlation_ports import CorrelationEnginePort
from src.config.settings import DEFAULT_SETTINGS
from src.application.correlation_result import CorrelationResult
from src.correlation.correlation_engine import CorrelationEngine


class LegacyCorrelationEngine(CorrelationEnginePort):
    """
    Adapter connecting the application correlation interface
    with the existing CorrelationEngine implementation.
    """

    def __init__(self) -> None:
        self._engine = CorrelationEngine(
            window_seconds=DEFAULT_SETTINGS.correlation_window_seconds,
        )

    def correlate(
        self,
        events: list[dict[str, Any]],
    ) -> list[CorrelationResult]:

        legacy_results = self._engine.correlate(events)

        return [
            CorrelationResult(
                sequence=result["sequence"],
                source=result["source"],
                events=result["events"],
                time_difference_seconds=result[
                    "time_difference_seconds"
                ],
            )
            for result in legacy_results
        ]
