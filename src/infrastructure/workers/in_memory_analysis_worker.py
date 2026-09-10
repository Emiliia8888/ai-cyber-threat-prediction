from src.application.analysis_worker import AnalysisWorkerPort
from src.application.threat_analysis import ThreatAnalysis


class InMemoryAnalysisWorker(AnalysisWorkerPort):
    """
    In-memory analysis worker.

    Processes jobs from the queue through ThreatAnalysis.
    """

    def __init__(
        self,
        analysis: ThreatAnalysis,
    ) -> None:
        self.analysis = analysis

    def process_next(self) -> bool:
        result = self.analysis.process_next_job()

        return result is not None
