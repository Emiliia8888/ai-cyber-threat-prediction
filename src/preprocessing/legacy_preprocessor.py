from typing import Any

from src.application.preprocessing_ports import PreprocessingPort
from src.preprocessing.normalize import (
    add_time_differences,
    normalize_events,
)


class LegacyPreprocessor(PreprocessingPort):
    """
    Adapter connecting the application preprocessing interface
    with the existing preprocessing implementation.
    """

    def preprocess(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        normalize_events(events)
        add_time_differences(events)
        return events
