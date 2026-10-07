import re
from datetime import datetime


class SSHLogParser:
    """
    Parser for Linux SSH authentication log entries.
    """

    LOG_PATTERN = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
        r"from\s+(?P<source>\d{1,3}(?:\.\d{1,3}){3})\s+"
    )

    def parse(self, log: str, year: int) -> "Event":
        from src.domain.event import Event

        match = self.LOG_PATTERN.search(log)

        if match is None:
            raise ValueError("Unsupported SSH log format")

        timestamp = datetime.strptime(
            f"{year} {match.group('month')} "
            f"{match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        )

        if "Failed password" in log or "Invalid user" in log:
            event_type = "failed_login"
        elif "Accepted password" in log:
            event_type = "successful_login"
        else:
            raise ValueError("Unsupported SSH event type")

        return Event(
            event_type=event_type,
            source=match.group("source"),
            timestamp=timestamp,
        )
