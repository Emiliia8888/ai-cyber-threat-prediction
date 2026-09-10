from unittest.mock import MagicMock

from src.infrastructure.persistence.postgres_event_repository import (
    PostgresEventRepository,
)


def test_save_events_inserts_events_and_commits():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    repository = PostgresEventRepository(connection)

    events = [
        {
            "type": "port_scan",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:00",
        },
        {
            "type": "failed_login",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:30",
        },
    ]

    repository.save_events(events)

    assert cursor.execute.call_count == 2
    connection.commit.assert_called_once()


def test_get_events_returns_repository_events():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    cursor.fetchall.return_value = [
        (
            "port_scan",
            "192.168.1.10",
            __import__("datetime").datetime(
                2026, 9, 10, 12, 0, 0
            ),
        ),
        (
            "failed_login",
            "192.168.1.10",
            __import__("datetime").datetime(
                2026, 9, 10, 12, 0, 30
            ),
        ),
    ]

    repository = PostgresEventRepository(connection)

    result = repository.get_events()

    assert result == [
        {
            "type": "port_scan",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:00",
        },
        {
            "type": "failed_login",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:30",
        },
    ]

    cursor.execute.assert_called_once()

def test_postgres_repository_requires_connection():
    import pytest

    with pytest.raises(TypeError):
        PostgresEventRepository()
