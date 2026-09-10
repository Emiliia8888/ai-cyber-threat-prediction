from src.application.job import Job, JobStatus
from src.infrastructure.persistence.in_memory_job_repository import (
    InMemoryJobRepository,
)


def test_repository_starts_empty():
    repository = InMemoryJobRepository()

    assert repository.get("job-1") is None


def test_repository_can_save_and_get_job():
    repository = InMemoryJobRepository()

    job = Job(
        job_id="job-1",
        events=[],
    )

    repository.save(job)

    result = repository.get("job-1")

    assert result == job


def test_repository_stores_updated_job_state():
    repository = InMemoryJobRepository()

    job = Job(
        job_id="job-1",
        events=[],
    )

    repository.save(job)

    job.status = JobStatus.PROCESSING
    repository.save(job)

    result = repository.get("job-1")

    assert result is not None
    assert result.status == JobStatus.PROCESSING
