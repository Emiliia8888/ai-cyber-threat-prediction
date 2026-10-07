from pathlib import Path

from src.application.interfaces import EventSourcePort
from src.domain.event import Event
from src.ingestion.ssh_log_parser import SSHLogParser


class SSHLogEventSource(EventSourcePort):
    """
    Adapter for loading Linux SSH authentication logs.

    Reads raw log lines and converts supported entries
    into domain Event objects.
    """

    def __init__(self, year: int) -> None:
        self._year = year
        self._parser = SSHLogParser()

    def load(self, file_path: str) -> list[Event]:
        path = Path(file_path)

        events: list[Event] = []

        with path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = self._parser.parse(line, year=self._year)
                except ValueError:
                    continue

                events.append(event)

        return events
