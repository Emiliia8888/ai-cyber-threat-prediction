from src.infrastructure.persistence.in_memory_event_repository import (
    InMemoryEventRepository,
)


def test_save_and_get_events():
    repository = InMemoryEventRepository()

    events = [
        {
            "type": "port_scan",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:00",
        },
        {
            "type": "failed_login",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:30",
        },
    ]

    repository.save_events(events)

    assert repository.get_events() == events


def test_get_events_returns_copy():
    repository = InMemoryEventRepository()

    events = [
        {
            "type": "port_scan",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:00",
        }
    ]

    repository.save_events(events)

    result = repository.get_events()
    result.clear()

    assert repository.get_events() == events


def test_repository_starts_empty():
    repository = InMemoryEventRepository()

    assert repository.get_events() == []
