from src.domain.event import Event
from src.ingestion.json_event_source import JsonEventSource


def test_json_event_source_implements_event_source_port():
    source = JsonEventSource()

    events = source.load("data/events.json")

    assert isinstance(events, list)
    assert len(events) > 0
    assert all(isinstance(event, Event) for event in events)

