from datetime import datetime
from typing import Any

from src.domain.event import Event
from src.prediction.features import extract_features


class FeatureEngine:
    """
    Application-level feature extraction interface.

    The existing prediction feature implementation remains unchanged.
    This layer adapts domain events to the legacy feature format.
    """

    def extract(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return extract_features(events)

    def extract_from_domain_events(
        self,
        events: list[Event],
    ) -> dict[str, Any]:
        raw_events = []

        for event in events:
            raw_events.append(
                {
                    "type": event.event_type,
                    "source": event.source,
                    "timestamp": event.timestamp.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )

        self._add_time_differences(raw_events)

        return self.extract(raw_events)

    @staticmethod
    def _add_time_differences(
        events: list[dict[str, Any]],
    ) -> None:
        previous_timestamp: datetime | None = None

        for event in events:
            timestamp = datetime.strptime(
                event["timestamp"],
                "%Y-%m-%d %H:%M:%S",
            )

            if previous_timestamp is None:
                event["time_since_previous"] = None
            else:
                event["time_since_previous"] = (
                    timestamp - previous_timestamp
                )

            previous_timestamp = timestamp
