from abc import ABC, abstractmethod


class AnalysisWorkerPort(ABC):
    """
    Application-level interface for asynchronous analysis workers.
    """

    @abstractmethod
    def process_next(self) -> bool:
        """
        Process the next available analysis job.

        Returns True when a job was processed,
        otherwise False when the queue is empty.
        """
        raise NotImplementedError
