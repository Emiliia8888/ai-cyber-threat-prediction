from pathlib import Path
from typing import Any

from src.domain.event import Event
from src.preprocessing.event_loader import load_events


class EventSource:
    """
    Application-level event ingestion interface.

    The existing JSON loader remains the source of truth.
    This class converts raw dictionaries into domain Event objects.
    """

    def load_raw(self, file_path: str | Path) -> list[dict[str, Any]]:
        return load_events(file_path)

    def load(self, file_path: str | Path) -> list[Event]:
        raw_events = self.load_raw(file_path)

        return [
            Event.from_dict(event)
            for event in raw_events
        ]
