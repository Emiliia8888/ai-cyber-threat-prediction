from src.config.settings import DEFAULT_SETTINGS, Settings


def test_default_settings_preserve_current_values():
    assert DEFAULT_SETTINGS.correlation_window_seconds == 60
    assert DEFAULT_SETTINGS.attack_chain_window_seconds == 300
    assert DEFAULT_SETTINGS.ml_random_state == 42
    assert DEFAULT_SETTINGS.events_file == "data/events.json"
    assert DEFAULT_SETTINGS.evaluation_file == "data/evaluation.json"
    assert DEFAULT_SETTINGS.use_postgres_jobs is False
    assert (
        DEFAULT_SETTINGS.database_url
        == "postgresql://cyber_user:cyber_password"
        "@localhost:5433/cyber_threats"
    )

def test_settings_are_immutable():
    settings = Settings()

    try:
        settings.correlation_window_seconds = 120
    except AttributeError:
        pass
    else:
        raise AssertionError("Settings must be immutable")
