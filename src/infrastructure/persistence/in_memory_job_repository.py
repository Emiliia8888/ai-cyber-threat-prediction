from src.application.job import Job
from src.application.job_repository import JobRepositoryPort


class InMemoryJobRepository(JobRepositoryPort):
    """
    In-memory implementation of job persistence.

    Useful for tests and local development.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def save(self, job: Job) -> None:
        self._jobs[job.job_id] = job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)
