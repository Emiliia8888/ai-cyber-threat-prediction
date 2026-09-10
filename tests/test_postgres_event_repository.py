import pytest

from src.infrastructure.persistence.postgres_event_repository import (
    PostgresEventRepository,
)


def test_postgres_repository_requires_connection():
    with pytest.raises(TypeError):
        PostgresEventRepository()
