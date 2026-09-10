from typing import Any

from src.application.event_repository import EventRepositoryPort


class PostgresEventRepository(EventRepositoryPort):
    """
    PostgreSQL implementation of event persistence.
    """

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def save_events(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        with self.connection.cursor() as cursor:
            for event in events:
                cursor.execute(
                    """
                    INSERT INTO events (
                        event_type,
                        source,
                        event_timestamp
                    )
                    VALUES (%s, %s, %s)
                    """,
                    (
                        event["type"],
                        event["source"],
                        event["timestamp"],
                    ),
                )

        self.connection.commit()

    def get_events(self) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    event_type,
                    source,
                    event_timestamp
                FROM events
                ORDER BY id
                """
            )

            rows = cursor.fetchall()

        return [
            {
                "type": row[0],
                "source": row[1],
                "timestamp": row[2].strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for row in rows
        ]
