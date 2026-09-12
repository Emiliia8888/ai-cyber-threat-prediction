from datetime import datetime, timedelta

from src.application.threat_analysis import ThreatAnalysis
from src.bootstrap.composition import (
    create_event_repository,
    create_pipeline,
    create_job_queue,
    create_job_repository,
)


def create_test_analysis(
    event_repository=None,
):
    return ThreatAnalysis(
        pipeline=create_pipeline(),
        event_repository=event_repository or create_event_repository(),
        job_queue=create_job_queue(),
        job_repository=create_job_repository(),
    )


def test_threat_analysis_analyzes_file():
    analysis = create_test_analysis()

    result = analysis.analyze_file("data/events.json")

    assert result["prediction"] == "high"
    assert result["confidence"] == 1.0
    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"
    assert result["agreement"] is True


def test_threat_analysis_analyzes_events():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start.strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": (start + timedelta(seconds=20)).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": (start + timedelta(seconds=40)).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        },
    ]

    analysis = create_test_analysis()

    result = analysis.analyze_events(events)

    assert result["prediction"] == "high"
    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"
    assert result["attack_chain"] is not None


def test_threat_analysis_saves_events_to_repository():
    from src.infrastructure.persistence.in_memory_event_repository import (
        InMemoryEventRepository,
    )

    repository = InMemoryEventRepository()
    analysis = create_test_analysis(event_repository=repository)

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
        {
            "type": "successful_login",
            "source": "192.168.1.10",
            "timestamp": "2026-09-10 12:00:45",
        },
    ]

    analysis.analyze_events(events)

    assert repository.get_events() == events
