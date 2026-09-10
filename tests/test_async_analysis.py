from src.application.job import Job
from src.application.threat_analysis import ThreatAnalysis
from src.infrastructure.queue.in_memory_job_queue import (
    InMemoryJobQueue,
)


def test_enqueue_analysis_adds_job_to_queue():
    queue = InMemoryJobQueue()
    analysis = ThreatAnalysis(job_queue=queue)

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

    queued_job = queue.dequeue()

    assert queued_job is job
    assert queued_job.job_id == "job-1"


def test_process_next_job_processes_queued_events():
    queue = InMemoryJobQueue()
    analysis = ThreatAnalysis(job_queue=queue)

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

    assert result is not None
    assert job.result == result
