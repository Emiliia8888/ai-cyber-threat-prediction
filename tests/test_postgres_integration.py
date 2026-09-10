
import psycopg

from src.infrastructure.persistence.postgres_event_repository import (
    PostgresEventRepository,
)


DATABASE_URL = (
    "postgresql://cyber_user:cyber_password"
    "@localhost:5433/cyber_threats"
)

def test_postgres_repository_real_database():
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
    ]

    with psycopg.connect(DATABASE_URL) as connection:
        repository = PostgresEventRepository(connection)

        repository.save_events(events)

        result = repository.get_events()

    assert result[-2:] == events

from src.application.analysis_result import AnalysisResult
from src.application.job import Job, JobStatus
from src.infrastructure.persistence.postgres_job_repository import (
    PostgresJobRepository,
)


def test_postgres_job_repository_real_database():
    job_id = "integration-job-001"

    result = AnalysisResult(
        prediction="high",
        confidence=0.99,
        threat_level="high",
        attack_type="brute_force",
        agreement=True,
        explanation=["Suspicious login sequence detected"],
        severity=[
            {
                "level": "HIGH",
                "message": "Successful login after failed attempts detected",
            }
        ],
        features={
            "port_scan_count": 2,
            "failed_login_count": 3,
            "successful_login_count": 1,
        },
        correlations=None,
        attack_chain=None,
    )

    job = Job(
        job_id=job_id,
        events=[
            {
                "type": "failed_login",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ],
        status=JobStatus.COMPLETED,
        result=result,
    )

    with psycopg.connect(DATABASE_URL) as connection:
        repository = PostgresJobRepository(connection)
        repository.save(job)

        loaded_job = repository.get(job_id)

    assert loaded_job is not None
    assert loaded_job.job_id == job_id
    assert loaded_job.status == JobStatus.COMPLETED
    assert loaded_job.events == job.events

    assert isinstance(loaded_job.result, AnalysisResult)
    assert loaded_job.result.prediction == "high"
    assert loaded_job.result.confidence == 0.99
    assert loaded_job.result.threat_level == "high"
    assert loaded_job.result.attack_type == "brute_force"
    assert loaded_job.result.agreement is True

    assert loaded_job.result.explanation == [
        "Suspicious login sequence detected"
    ]

    assert loaded_job.error is None
