from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.event_repository import EventRepositoryPort
from src.application.job import Job, JobStatus
from src.application.job_queue import JobQueuePort
from src.application.job_repository import JobRepositoryPort
from src.pipeline.threat_pipeline import ThreatPipeline


class ThreatAnalysis:
    """
    Application use case for complete cyber threat analysis.

    Dependencies are injected from the composition root.
    The application layer does not construct infrastructure
    or concrete implementations itself.
    """

    def __init__(
        self,
        pipeline: ThreatPipeline,
        event_repository: EventRepositoryPort,
        job_queue: JobQueuePort,
        job_repository: JobRepositoryPort,
    ) -> None:
        self.pipeline = pipeline
        self.event_repository = event_repository
        self.job_queue = job_queue
        self.job_repository = job_repository

    def analyze_file(
        self,
        file_path: str,
    ) -> AnalysisResult:
        """
        Analyze security events loaded from a file.
        """
        return self.pipeline.run(file_path)

    def analyze_events(
        self,
        events: list[dict[str, Any]],
    ) -> AnalysisResult:
        """
        Analyze already loaded event dictionaries.
        """
        self.event_repository.save_events(events)
        return self.pipeline.run_from_events(events)

    def enqueue_analysis(
        self,
        job: Job,
    ) -> None:
        """
        Add an analysis job to the asynchronous job queue
        and persist its initial state.
        """
        self.job_repository.save(job)
        self.job_queue.enqueue(job)

    def get_job(
        self,
        job_id: str,
    ) -> Job | None:
        """
        Retrieve a persisted analysis job.
        """
        return self.job_repository.get(job_id)

    def process_next_job(self) -> AnalysisResult | None:
        """
        Process the next queued analysis job.
        Returns None when the queue is empty.
        """
        job = self.job_queue.dequeue()

        if job is None:
            return None

        job.status = JobStatus.PROCESSING
        self.job_repository.save(job)

        try:
            result = self.analyze_events(job.events)

            job.status = JobStatus.COMPLETED
            job.result = result
            job.error = None
            self.job_repository.save(job)

            return result

        except Exception as exc:
            job.status = JobStatus.FAILED
            job.error = str(exc)
            self.job_repository.save(job)
            raise
