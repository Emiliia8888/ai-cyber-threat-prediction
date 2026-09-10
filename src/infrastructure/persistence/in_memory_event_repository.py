from typing import Any

from src.application.event_repository import EventRepositoryPort


class InMemoryEventRepository(EventRepositoryPort):
    """
    In-memory implementation of event persistence.

    This implementation is useful for tests and local development.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def save_events(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        self._events.extend(events)

    def get_events(self) -> list[dict[str, Any]]:
        return list(self._events)
