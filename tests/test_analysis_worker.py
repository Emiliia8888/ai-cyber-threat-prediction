from src.application.job import Job, JobStatus
from src.application.threat_analysis import ThreatAnalysis
from src.bootstrap.composition import (
    create_event_repository,
    create_job_queue,
    create_job_repository,
    create_pipeline,
)
from src.infrastructure.workers.in_memory_analysis_worker import (
    InMemoryAnalysisWorker,
)


def create_test_analysis(queue):
    return ThreatAnalysis(
        pipeline=create_pipeline(),
        event_repository=create_event_repository(),
        job_queue=queue,
        job_repository=create_job_repository(),
    )


def test_worker_processes_queued_job():
    queue = create_job_queue()
    analysis = create_test_analysis(queue)
    worker = InMemoryAnalysisWorker(analysis)

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

    assert worker.process_next() is True
    assert queue.size() == 0


def test_worker_returns_false_when_queue_is_empty():
    queue = create_job_queue()
    analysis = create_test_analysis(queue)
    worker = InMemoryAnalysisWorker(analysis)

    assert worker.process_next() is False


def test_worker_completes_job():
    queue = create_job_queue()
    analysis = create_test_analysis(queue)
    worker = InMemoryAnalysisWorker(analysis)

    job = Job(
        job_id="job-worker-1",
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

    assert job.status == JobStatus.PENDING
    assert worker.process_next() is True
    assert job.status == JobStatus.COMPLETED
    assert job.result is not None
    assert job.error is None
