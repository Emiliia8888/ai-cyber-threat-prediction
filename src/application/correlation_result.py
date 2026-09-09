from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CorrelationResult:
    """
    Structured result of event correlation.
    """

    sequence: str
    source: str
    events: list[dict[str, Any]]
    time_difference_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "source": self.source,
            "events": self.events,
            "time_difference_seconds": self.time_difference_seconds,
        }
