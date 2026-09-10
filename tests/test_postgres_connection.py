from unittest.mock import patch

from src.config.settings import Settings
from src.infrastructure.persistence.postgres_connection import (
    PostgresConnectionFactory,
)


def test_postgres_connection_factory_uses_database_url():
    settings = Settings(
        database_url="postgresql://test:test@localhost:5433/test_db"
    )

    factory = PostgresConnectionFactory(settings)

    with patch(
        "src.infrastructure.persistence.postgres_connection.psycopg.connect"
    ) as connect:
        factory.create()

        connect.assert_called_once_with(settings.database_url)


def test_postgres_connection_factory_returns_connection():
    settings = Settings()
    factory = PostgresConnectionFactory(settings)

    fake_connection = object()

    with patch(
        "src.infrastructure.persistence.postgres_connection.psycopg.connect",
        return_value=fake_connection,
    ):
        connection = factory.create()

    assert connection is fake_connection
