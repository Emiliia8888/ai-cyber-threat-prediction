from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """
    Central application configuration.

    Default values preserve the current behaviour of the system.
    """

    correlation_window_seconds: int = 60
    attack_chain_window_seconds: int = 300

    ml_random_state: int = 42

    events_file: str = "data/events.json"
    evaluation_file: str = "data/evaluation.json"


DEFAULT_SETTINGS = Settings()
