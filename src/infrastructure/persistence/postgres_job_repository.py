import json
from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.correlation_result import CorrelationResult
from src.application.job import Job, JobStatus
from src.application.job_repository import JobRepositoryPort


class PostgresJobRepository(JobRepositoryPort):
    """
    PostgreSQL implementation of job persistence.
    """

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def save(self, job: Job) -> None:
        result = None

        if job.result is not None:
            result = job.result.to_dict()

        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO jobs (
                    job_id,
                    status,
                    events,
                    result,
                    error
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (job_id)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    events = EXCLUDED.events,
                    result = EXCLUDED.result,
                    error = EXCLUDED.error,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    job.job_id,
                    job.status.value,
                    json.dumps(job.events),
                    json.dumps(result) if result is not None else None,
                    job.error,
                ),
            )

        self.connection.commit()

    def get(self, job_id: str) -> Job | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    job_id,
                    status,
                    events,
                    result,
                    error
                FROM jobs
                WHERE job_id = %s
                """,
                (job_id,),
            )

            row = cursor.fetchone()

        if row is None:
            return None

        return Job(
            job_id=row[0],
            events=row[2],
            status=JobStatus(row[1]),
            result=self._deserialize_result(row[3]),
            error=row[4],
        )

    @staticmethod
    def _deserialize_result(
        data: dict[str, Any] | str | None,
    ) -> AnalysisResult | None:
        if data is None:
            return None

        if isinstance(data, str):
            data = json.loads(data)

        correlations = data.get("correlations")

        typed_correlations = None

        if correlations is not None:
            typed_correlations = [
                CorrelationResult(
                    sequence=item["sequence"],
                    source=item["source"],
                    events=item["events"],
                    time_difference_seconds=item[
                        "time_difference_seconds"
                    ],
                )
                for item in correlations
            ]

        return AnalysisResult(
            prediction=data["prediction"],
            confidence=data["confidence"],
            threat_level=data["threat_level"],
            attack_type=data["attack_type"],
            agreement=data["agreement"],
            explanation=data["explanation"],
            severity=data["severity"],
            features=data["features"],
            correlations=typed_correlations,
            attack_chain=data.get("attack_chain"),
        )
