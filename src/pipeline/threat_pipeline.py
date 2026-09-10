from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.application.prediction_ports import PredictionEnginePort
from src.preprocessing.normalize import (
    add_time_differences,
    normalize_events,
)


class ThreatPipeline:
    """
    Application pipeline coordinating ingestion,
    preprocessing, feature extraction, ML prediction,
    and risk assessment.

    Dependencies are provided through application-level
    ports and are created by the composition root.
    """

    def __init__(
        self,
        event_source: EventSourcePort,
        feature_engine: FeatureEnginePort,
        prediction_engine: PredictionEnginePort,
        risk_engine: RiskEnginePort,
    ) -> None:
        self.event_source = event_source
        self.feature_engine = feature_engine
        self.prediction_engine = prediction_engine
        self.risk_engine = risk_engine

    def run(self, file_path: str) -> AnalysisResult:
        """
        Run the complete application pipeline from
        an input JSON file.
        """
        domain_events = self.event_source.load(file_path)

        raw_events = [
            {
                "type": event.event_type,
                "source": event.source,
                "timestamp": event.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for event in domain_events
        ]

        normalize_events(raw_events)
        add_time_differences(raw_events)

        features = self.feature_engine.extract_from_domain_events(
            domain_events
        )

        prediction, confidence = self.prediction_engine.predict(
            features
        )

        risk = self.risk_engine.assess(
            raw_events,
            prediction,
        )

        return AnalysisResult(
            prediction=prediction,
            confidence=confidence,
            threat_level=risk.threat_level,
            attack_type=risk.attack_type,
            agreement=risk.agreement,
            explanation=risk.explanation,
            severity=risk.severity,
            features=features,
            correlations=risk.correlations,
            attack_chain=risk.attack_chain,
        )

    def run_from_events(
        self,
        events: list[dict[str, Any]],
    ) -> AnalysisResult:
        """
        Backward-compatible execution path for already
        loaded legacy event dictionaries.
        """
        normalize_events(events)
        add_time_differences(events)

        features = self.feature_engine.extract(events)

        prediction, confidence = self.prediction_engine.predict(
            features
        )

        risk = self.risk_engine.assess(
            events,
            prediction,
        )

        return AnalysisResult(
            prediction=prediction,
            confidence=confidence,
            threat_level=risk.threat_level,
            attack_type=risk.attack_type,
            agreement=risk.agreement,
            explanation=risk.explanation,
            severity=risk.severity,
            features=features,
            correlations=risk.correlations,
            attack_chain=risk.attack_chain,
        )
