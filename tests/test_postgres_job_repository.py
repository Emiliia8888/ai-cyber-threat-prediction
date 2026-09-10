import json
from unittest.mock import MagicMock

import pytest

from src.application.analysis_result import AnalysisResult
from src.application.correlation_result import CorrelationResult
from src.application.job import Job, JobStatus
from src.infrastructure.persistence.postgres_job_repository import (
    PostgresJobRepository,
)


def create_analysis_result() -> AnalysisResult:
    return AnalysisResult(
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
        correlations=[
            CorrelationResult(
                sequence="failed_login -> successful_login",
                source="192.168.1.10",
                events=[
                    {
                        "type": "failed_login",
                        "source": "192.168.1.10",
                        "timestamp": "2026-09-10 12:00:00",
                    },
                    {
                        "type": "successful_login",
                        "source": "192.168.1.10",
                        "timestamp": "2026-09-10 12:00:30",
                    },
                ],
                time_difference_seconds=30.0,
            )
        ],
        attack_chain={
            "name": "credential_attack",
            "steps": 2,
        },
    )


def test_save_new_job_inserts_and_commits():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    repository = PostgresJobRepository(connection)

    job = Job(
        job_id="job-123",
        events=[
            {
                "type": "port_scan",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ],
    )

    repository.save(job)

    cursor.execute.assert_called_once()
    connection.commit.assert_called_once()


def test_save_completed_job_serializes_result():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    repository = PostgresJobRepository(connection)

    result = create_analysis_result()

    job = Job(
        job_id="job-123",
        events=[],
        status=JobStatus.COMPLETED,
        result=result,
    )

    repository.save(job)

    execute_args = cursor.execute.call_args.args
    parameters = execute_args[1]

    assert parameters[0] == "job-123"
    assert parameters[1] == "completed"
    assert json.loads(parameters[2]) == job.events

    stored_result = json.loads(parameters[3])

    assert stored_result["prediction"] == "high"
    assert stored_result["confidence"] == 0.99
    assert stored_result["threat_level"] == "high"
    assert stored_result["attack_type"] == "brute_force"
    assert stored_result["agreement"] is True
    assert stored_result["correlations"][0]["sequence"] == (
        "failed_login -> successful_login"
    )
    assert stored_result["attack_chain"]["name"] == "credential_attack"


def test_get_pending_job_returns_job():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    cursor.fetchone.return_value = (
        "job-123",
        "pending",
        [
            {
                "type": "port_scan",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ],
        None,
        None,
    )

    repository = PostgresJobRepository(connection)

    job = repository.get("job-123")

    assert job is not None
    assert job.job_id == "job-123"
    assert job.status == JobStatus.PENDING
    assert job.events[0]["type"] == "port_scan"
    assert job.result is None
    assert job.error is None
    cursor.execute.assert_called_once()


def test_get_completed_job_deserializes_analysis_result():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    result = create_analysis_result()

    cursor.fetchone.return_value = (
        "job-123",
        "completed",
        [],
        result.to_dict(),
        None,
    )

    repository = PostgresJobRepository(connection)

    job = repository.get("job-123")

    assert job is not None
    assert job.status == JobStatus.COMPLETED
    assert isinstance(job.result, AnalysisResult)

    assert job.result.prediction == "high"
    assert job.result.confidence == 0.99
    assert job.result.threat_level == "high"

    assert job.result.correlations is not None
    assert len(job.result.correlations) == 1
    assert isinstance(job.result.correlations[0], CorrelationResult)
    assert job.result.correlations[0].sequence == (
        "failed_login -> successful_login"
    )
    assert job.result.correlations[0].time_difference_seconds == 30.0

    assert job.result.attack_chain == {
        "name": "credential_attack",
        "steps": 2,
    }


def test_get_completed_job_deserializes_json_string_result():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    result = create_analysis_result()

    cursor.fetchone.return_value = (
        "job-123",
        "completed",
        [],
        json.dumps(result.to_dict()),
        None,
    )

    repository = PostgresJobRepository(connection)

    job = repository.get("job-123")

    assert job is not None
    assert isinstance(job.result, AnalysisResult)
    assert job.result.prediction == "high"


def test_get_failed_job_returns_error():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    cursor.fetchone.return_value = (
        "job-123",
        "failed",
        [],
        None,
        "Analysis failed",
    )

    repository = PostgresJobRepository(connection)

    job = repository.get("job-123")

    assert job is not None
    assert job.status == JobStatus.FAILED
    assert job.result is None
    assert job.error == "Analysis failed"


def test_get_missing_job_returns_none():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value

    cursor.fetchone.return_value = None

    repository = PostgresJobRepository(connection)

    result = repository.get("missing-job")

    assert result is None


def test_postgres_job_repository_requires_connection():
    with pytest.raises(TypeError):
        PostgresJobRepository()
