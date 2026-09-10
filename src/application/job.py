from dataclasses import dataclass
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Job:
    """
    Application-level representation of an asynchronous analysis job.
    """

    job_id: str
    events: list[dict[str, Any]]
    status: JobStatus = JobStatus.PENDING
    result: Any | None = None
    error: str | None = None
