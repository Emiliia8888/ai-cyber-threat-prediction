from src.application.job import Job, JobStatus


def test_job_starts_pending():
    job = Job(
        job_id="job-1",
        events=[],
    )

    assert job.job_id == "job-1"
    assert job.events == []
    assert job.status == JobStatus.PENDING
    assert job.result is None
    assert job.error is None


def test_job_can_store_completed_result():
    job = Job(
        job_id="job-1",
        events=[],
    )

    job.status = JobStatus.COMPLETED
    job.result = {
        "threat_level": "high",
    }

    assert job.status == JobStatus.COMPLETED
    assert job.result == {
        "threat_level": "high",
    }


def test_job_can_store_failure():
    job = Job(
        job_id="job-1",
        events=[],
    )

    job.status = JobStatus.FAILED
    job.error = "Analysis failed"

    assert job.status == JobStatus.FAILED
    assert job.error == "Analysis failed"
