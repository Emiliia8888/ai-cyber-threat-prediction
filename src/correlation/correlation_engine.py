from datetime import datetime
from typing import Any


class CorrelationEngine:
    """
    Detects temporal relationships between security events.

    The engine accepts both normalized datetime timestamps
    and legacy string timestamps.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds

    def correlate(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect known event sequences.

        Currently supported:
            port_scan -> failed_login
            failed_login -> successful_login
        """
        correlations: list[dict[str, Any]] = []

        for first, second in zip(events, events[1:]):
            if first["source"] != second["source"]:
                continue

            first_timestamp = self._parse_timestamp(first["timestamp"])
            second_timestamp = self._parse_timestamp(second["timestamp"])

            time_difference = (
                second_timestamp - first_timestamp
            ).total_seconds()

            if time_difference < 0:
                continue

            if time_difference > self.window_seconds:
                continue

            first_type = first["type"]
            second_type = second["type"]

            if first_type == "port_scan" and second_type == "failed_login":
                correlations.append(
                    {
                        "sequence": "port_scan -> failed_login",
                        "source": first["source"],
                        "events": [first, second],
                        "time_difference_seconds": time_difference,
                    }
                )

            elif (
                first_type == "failed_login"
                and second_type == "successful_login"
            ):
                correlations.append(
                    {
                        "sequence": "failed_login -> successful_login",
                        "source": first["source"],
                        "events": [first, second],
                        "time_difference_seconds": time_difference,
                    }
                )

        return correlations

    @staticmethod
    def _parse_timestamp(timestamp: datetime | str) -> datetime:
        """
        Convert a legacy timestamp string to datetime.

        Already parsed datetime values are returned unchanged.
        """
        if isinstance(timestamp, datetime):
            return timestamp

        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        )
