from src.domain.event import Event
from src.ingestion.event_source import EventSource


def test_event_source_loads_events():
    source = EventSource()

    events = source.load("data/events.json")

    assert isinstance(events, list)
    assert len(events) > 0
    assert all(isinstance(event, Event) for event in events)


def test_event_source_can_load_raw_events():
    source = EventSource()

    events = source.load_raw("data/events.json")

    assert isinstance(events, list)
    assert len(events) > 0
    assert all(isinstance(event, dict) for event in events)
