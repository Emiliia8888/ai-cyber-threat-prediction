
import psycopg

from src.infrastructure.persistence.postgres_event_repository import (
    PostgresEventRepository,
)


DATABASE_URL = (
    "postgresql://cyber_user:cyber_password"
    "@localhost:5433/cyber_threats"
)

def test_postgres_repository_real_database():
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

    with psycopg.connect(DATABASE_URL) as connection:
        repository = PostgresEventRepository(connection)

        repository.save_events(events)

        result = repository.get_events()

    assert result[-2:] == events
