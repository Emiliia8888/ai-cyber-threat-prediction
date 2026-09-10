from typing import Any

from src.application.event_repository import EventRepositoryPort


class PostgresEventRepository(EventRepositoryPort):
    """
    PostgreSQL implementation of event persistence.

    Database connection details are injected so that
    the repository remains independent from application code.
    """

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def save_events(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        raise NotImplementedError(
            "PostgreSQL persistence will be implemented next."
        )

    def get_events(self) -> list[dict[str, Any]]:
        raise NotImplementedError(
            "PostgreSQL persistence will be implemented next."
        )
