import os

from dataclasses import dataclass, field


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    raise ValueError(
        f"{name} must be a boolean value"
    )


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    return int(value)


def _get_non_empty(name: str, default: str) -> str:
    value = os.getenv(name)

    if value is None:
        return default

    if not value.strip():
        raise ValueError(
            f"{name} must not be empty"
        )

    return value


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
        default_factory=lambda: _get_non_empty(
            "EVENTS_FILE", "data/events.json"
        )
    )
    evaluation_file: str = field(
        default_factory=lambda: _get_non_empty(
            "EVALUATION_FILE", "data/evaluation.json"
        )
    )
    database_url: str = field(
        default_factory=lambda: _get_non_empty(
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

    def __post_init__(self):
        if self.correlation_window_seconds <= 0:
            raise ValueError(
                "correlation_window_seconds must be greater than 0"
            )

        if self.attack_chain_window_seconds <= 0:
            raise ValueError(
                "attack_chain_window_seconds must be greater than 0"
            )

        if self.ml_random_state < 0:
            raise ValueError(
                "ml_random_state must be greater than or equal to 0"
            )


DEFAULT_SETTINGS = Settings()
