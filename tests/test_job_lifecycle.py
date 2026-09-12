from src.application.job import Job, JobStatus
from src.application.threat_analysis import ThreatAnalysis
from src.bootstrap.composition import (
    create_event_repository,
    create_job_queue,
    create_pipeline,
)
from src.infrastructure.persistence.in_memory_job_repository import (
    InMemoryJobRepository,
)


def create_test_analysis(queue, repository):
    return ThreatAnalysis(
        pipeline=create_pipeline(),
        event_repository=create_event_repository(),
        job_queue=queue,
        job_repository=repository,
    )


def test_job_is_persisted_when_enqueued():
    queue = create_job_queue()
    repository = InMemoryJobRepository()
    analysis = create_test_analysis(queue, repository)

    job = Job(
        job_id="job-1",
        events=[
            {
                "type": "port_scan",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ],
    )

    analysis.enqueue_analysis(job)

    stored_job = repository.get("job-1")

    assert stored_job is job
    assert stored_job.status == JobStatus.PENDING


def test_job_is_completed_after_processing():
    queue = create_job_queue()
    repository = InMemoryJobRepository()
    analysis = create_test_analysis(queue, repository)

    job = Job(
        job_id="job-1",
        events=[
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
        ],
    )

    analysis.enqueue_analysis(job)
    result = analysis.process_next_job()
    stored_job = repository.get("job-1")

    assert result is not None
    assert stored_job is not None
    assert stored_job.status == JobStatus.COMPLETED
    assert stored_job.result == result
    assert stored_job.error is None


def test_empty_queue_returns_none():
    queue = create_job_queue()
    repository = InMemoryJobRepository()
    analysis = create_test_analysis(queue, repository)

    assert analysis.process_next_job() is None


def test_job_is_failed_when_processing_raises_error():
    queue = create_job_queue()
    repository = InMemoryJobRepository()
    analysis = create_test_analysis(queue, repository)

    job = Job(
        job_id="job-failed",
        events=[
            {
                "type": "invalid_event",
                "source": "192.168.1.10",
                "timestamp": "invalid timestamp",
            }
        ],
    )

    analysis.enqueue_analysis(job)

    try:
        analysis.process_next_job()
    except Exception:
        pass

    stored_job = repository.get("job-failed")

    assert stored_job is not None
    assert stored_job.status == JobStatus.FAILED
    assert stored_job.error is not None
