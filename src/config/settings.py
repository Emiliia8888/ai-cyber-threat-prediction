import os
from dataclasses import dataclass, field


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    return int(value)


@dataclass(frozen=True)
class Settings:
    """
    Central application configuration.

    Values can be provided through environment variables.
    Defaults preserve the current application behaviour.
    """

    correlation_window_seconds: int = field(
        default_factory=lambda: _get_int(
            "CORRELATION_WINDOW_SECONDS", 60
        )
    )
    attack_chain_window_seconds: int = field(
        default_factory=lambda: _get_int(
            "ATTACK_CHAIN_WINDOW_SECONDS", 300
        )
    )
    ml_random_state: int = field(
        default_factory=lambda: _get_int(
            "ML_RANDOM_STATE", 42
        )
    )
    events_file: str = field(
        default_factory=lambda: os.getenv(
            "EVENTS_FILE", "data/events.json"
        )
    )
    evaluation_file: str = field(
        default_factory=lambda: os.getenv(
            "EVALUATION_FILE", "data/evaluation.json"
        )
    )
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql://cyber_user:cyber_password"
            "@localhost:5433/cyber_threats",
        )
    )
    use_postgres_jobs: bool = field(
        default_factory=lambda: _get_bool(
            "USE_POSTGRES_JOBS", False
        )
    )


DEFAULT_SETTINGS = Settings()
