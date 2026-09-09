from pathlib import Path

from src.domain.event import Event
from src.ingestion.event_source import EventSource
from src.application.interfaces import EventSourcePort


class JsonEventSource(EventSourcePort):
    """
    Adapter for loading security events from JSON files.

    The adapter connects the application-level EventSourcePort
    with the existing JSON-based EventSource implementation.
    """

    def __init__(self) -> None:
        self._source = EventSource()

    def load(self, file_path: str | Path) -> list[Event]:
        return self._source.load(file_path)
