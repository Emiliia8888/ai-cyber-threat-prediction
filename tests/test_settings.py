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

def test_settings_read_environment_variables(monkeypatch):
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "120")
    monkeypatch.setenv("ATTACK_CHAIN_WINDOW_SECONDS", "600")
    monkeypatch.setenv("ML_RANDOM_STATE", "99")
    monkeypatch.setenv("EVENTS_FILE", "data/custom_events.json")
    monkeypatch.setenv("EVALUATION_FILE", "data/custom_evaluation.json")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://test:test@localhost:5433/test_db",
    )
    monkeypatch.setenv("USE_POSTGRES_JOBS", "true")

    settings = Settings()

    assert settings.correlation_window_seconds == 120
    assert settings.attack_chain_window_seconds == 600
    assert settings.ml_random_state == 99
    assert settings.events_file == "data/custom_events.json"
    assert settings.evaluation_file == "data/custom_evaluation.json"
    assert settings.database_url == (
        "postgresql://test:test@localhost:5433/test_db"
    )
    assert settings.use_postgres_jobs is True


def test_settings_parse_false_environment_variable(monkeypatch):
    monkeypatch.setenv("USE_POSTGRES_JOBS", "false")

    settings = Settings()

    assert settings.use_postgres_jobs is False

def test_settings_reject_negative_correlation_window(monkeypatch):
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "-1")

    try:
        Settings()
    except ValueError as exc:
        assert "correlation_window_seconds" in str(exc)
    else:
        raise AssertionError(
            "Negative correlation window must be rejected"
        )


def test_settings_reject_zero_attack_chain_window(monkeypatch):
    monkeypatch.setenv("ATTACK_CHAIN_WINDOW_SECONDS", "0")

    try:
        Settings()
    except ValueError as exc:
        assert "attack_chain_window_seconds" in str(exc)
    else:
        raise AssertionError(
            "Zero attack chain window must be rejected"
        )


def test_settings_reject_negative_random_state(monkeypatch):
    monkeypatch.setenv("ML_RANDOM_STATE", "-1")

    try:
        Settings()
    except ValueError as exc:
        assert "ml_random_state" in str(exc)
    else:
        raise AssertionError(
            "Negative ML random state must be rejected"
        )


def test_settings_reject_invalid_boolean(monkeypatch):
    monkeypatch.setenv("USE_POSTGRES_JOBS", "maybe")

    try:
        Settings()
    except ValueError as exc:
        assert "USE_POSTGRES_JOBS" in str(exc)
    else:
        raise AssertionError(
            "Invalid boolean value must be rejected"
        )


def test_settings_reject_empty_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "   ")

    try:
        Settings()
    except ValueError as exc:
        assert "DATABASE_URL" in str(exc)
    else:
        raise AssertionError(
            "Empty database URL must be rejected"
        )
