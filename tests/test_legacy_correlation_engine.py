from src.application.correlation_result import CorrelationResult
from src.correlation.legacy_correlation_engine import LegacyCorrelationEngine


def test_legacy_correlation_engine_returns_correlation_results():

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-02 16:18:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-02 16:19:00",
        },
    ]

    engine = LegacyCorrelationEngine()

    results = engine.correlate(events)

    assert len(results) == 1
    assert isinstance(results[0], CorrelationResult)

    assert results[0].sequence == "port_scan -> failed_login"
    assert results[0].source == "server_01"
    assert results[0].time_difference_seconds == 60
