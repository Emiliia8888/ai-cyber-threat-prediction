from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    """
    Domain representation of a security event.

    The model provides a stable structure for future correlation,
    feature engineering, risk assessment, and alert processing.
    """

    event_type: str
    source: str
    timestamp: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        timestamp = data["timestamp"]

        if isinstance(timestamp, str):
            timestamp = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S",
            )

        event_type = data.get("event_type", data.get("type"))

        if event_type is None:
            raise ValueError("Event must contain 'type' or 'event_type'")

        return cls(
            event_type=event_type,
            source=data["source"],
            timestamp=timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "source": self.source,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
