from datetime import datetime, timedelta

from src.preprocessing.legacy_preprocessor import LegacyPreprocessor


def test_legacy_preprocessor_normalizes_and_adds_time_differences():
    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": "2026-09-04 12:00:00",
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": "2026-09-04 12:01:00",
        },
    ]

    preprocessor = LegacyPreprocessor()

    result = preprocessor.preprocess(events)

    assert result[0]["timestamp"] == datetime(
        2026,
        9,
        4,
        12,
        0,
        0,
    )

    assert result[1]["timestamp"] == datetime(
        2026,
        9,
        4,
        12,
        1,
        0,
    )

    assert result[1]["time_since_previous"] == timedelta(
        minutes=1
    )
