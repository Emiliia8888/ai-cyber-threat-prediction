from src.application.threat_analysis import ThreatAnalysis
from src.infrastructure.queue.in_memory_job_queue import (
    InMemoryJobQueue,
)
from src.infrastructure.workers.in_memory_analysis_worker import (
    InMemoryAnalysisWorker,
)


def test_worker_processes_queued_job():
    queue = InMemoryJobQueue()
    analysis = ThreatAnalysis(job_queue=queue)
    worker = InMemoryAnalysisWorker(analysis)

    job = {
        "job_id": "job-1",
        "events": [
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
    }

    analysis.enqueue_analysis(job)

    assert worker.process_next() is True
    assert queue.size() == 0


def test_worker_returns_false_when_queue_is_empty():
    queue = InMemoryJobQueue()
    analysis = ThreatAnalysis(job_queue=queue)
    worker = InMemoryAnalysisWorker(analysis)

    assert worker.process_next() is False
