from abc import ABC, abstractmethod

from src.application.job import Job


class JobRepositoryPort(ABC):
    """
    Application-level interface for job persistence.
    """

    @abstractmethod
    def save(self, job: Job) -> None:
        raise NotImplementedError

    @abstractmethod
    def get(self, job_id: str) -> Job | None:
        raise NotImplementedError
