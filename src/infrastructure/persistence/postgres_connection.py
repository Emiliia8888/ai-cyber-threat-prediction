from typing import Any

import psycopg

from src.config.settings import Settings


class PostgresConnectionFactory:
    """
    Factory for creating PostgreSQL database connections.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def create(self) -> Any:
        return psycopg.connect(self.settings.database_url)
