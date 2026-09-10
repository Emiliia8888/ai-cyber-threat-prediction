from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.composition import create_pipeline
from src.pipeline.threat_pipeline import ThreatPipeline


class ThreatAnalysis:
    """
    Application use case for complete cyber threat analysis.

    This class coordinates the application pipeline and provides
    a stable entry point for consumers such as the CLI, API,
    background workers, or future application interfaces.
    """

    def __init__(
        self,
        pipeline: ThreatPipeline | None = None,
    ) -> None:
        self.pipeline = pipeline or create_pipeline()

    def analyze_file(
        self,
        file_path: str,
    ) -> AnalysisResult:
        """
        Analyze security events loaded from a file.
        """
        return self.pipeline.run(file_path)

    def analyze_events(
        self,
        events: list[dict[str, Any]],
    ) -> AnalysisResult:
        """
        Analyze already loaded legacy event dictionaries.

        This method preserves compatibility with the existing
        run_from_events application path.
        """
        return self.pipeline.run_from_events(events)
