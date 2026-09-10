from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.application.preprocessing_ports import PreprocessingPort
from src.application.prediction_ports import PredictionEnginePort
from src.domain.event import Event


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
        preprocessing: PreprocessingPort,
        feature_engine: FeatureEnginePort,
        prediction_engine: PredictionEnginePort,
        risk_engine: RiskEnginePort,
    ) -> None:
        self.event_source = event_source
        self.preprocessing = preprocessing
        self.feature_engine = feature_engine
        self.prediction_engine = prediction_engine
        self.risk_engine = risk_engine

    def run(self, file_path: str) -> AnalysisResult:
        """
        Run the complete application pipeline from
        an input JSON file.
        """
        domain_events = self.event_source.load(file_path)

        raw_events = self._domain_events_to_raw(
            domain_events
        )

        processed_events = self.preprocessing.preprocess(
            raw_events
        )

        features = self.feature_engine.extract_from_domain_events(
            domain_events
        )

        prediction, confidence = self.prediction_engine.predict(
            features
        )

        risk = self.risk_engine.assess(
            processed_events,
            prediction,
        )

        return self._build_result(
            prediction,
            confidence,
            risk,
            features,
        )

    def run_from_events(
        self,
        events: list[dict[str, Any]],
    ) -> AnalysisResult:
        """
        Backward-compatible execution path for already
        loaded legacy event dictionaries.
        """
        processed_events = self.preprocessing.preprocess(
            events
        )

        domain_events = [
            Event.from_dict(event)
            for event in processed_events
        ]

        features = self.feature_engine.extract(
            processed_events
        )

        prediction, confidence = self.prediction_engine.predict(
            features
        )

        risk = self.risk_engine.assess(
            processed_events,
            prediction,
        )

        return self._build_result(
            prediction,
            confidence,
            risk,
            features,
        )

    @staticmethod
    def _domain_events_to_raw(
        events: list[Event],
    ) -> list[dict[str, Any]]:
        return [
            {
                "type": event.event_type,
                "source": event.source,
                "timestamp": event.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            for event in events
        ]

    @staticmethod
    def _build_result(
        prediction: str,
        confidence: float,
        risk: Any,
        features: dict[str, Any],
    ) -> AnalysisResult:
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
