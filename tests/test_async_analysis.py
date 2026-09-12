from src.application.job import Job
from src.application.threat_analysis import ThreatAnalysis
from src.bootstrap.composition import (
    create_event_repository,
    create_job_queue,
    create_job_repository,
    create_pipeline,
)


def create_test_analysis(queue):
    return ThreatAnalysis(
        pipeline=create_pipeline(),
        event_repository=create_event_repository(),
        job_queue=queue,
        job_repository=create_job_repository(),
    )


def test_enqueue_analysis_adds_job_to_queue():
    queue = create_job_queue()
    analysis = create_test_analysis(queue)

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
    queue = create_job_queue()
    analysis = create_test_analysis(queue)

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
