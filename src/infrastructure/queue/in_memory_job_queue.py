from collections import deque
from typing import Any

from src.application.job_queue import JobQueuePort


class InMemoryJobQueue(JobQueuePort):
    """
    In-memory implementation of the job queue.

    Useful for tests and local development.
    """

    def __init__(self) -> None:
        self._queue: deque[dict[str, Any]] = deque()

    def enqueue(
        self,
        job: dict[str, Any],
    ) -> None:
        self._queue.append(job)

    def dequeue(self) -> dict[str, Any] | None:
        if not self._queue:
            return None

        return self._queue.popleft()

    def size(self) -> int:
        return len(self._queue)
