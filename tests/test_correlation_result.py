from src.application.correlation_result import CorrelationResult


def test_correlation_result_to_dict():

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

    result = CorrelationResult(
        sequence="port_scan -> failed_login",
        source="server_01",
        events=events,
        time_difference_seconds=60,
    )

    assert result.to_dict() == {
        "sequence": "port_scan -> failed_login",
        "source": "server_01",
        "events": events,
        "time_difference_seconds": 60,
    }
