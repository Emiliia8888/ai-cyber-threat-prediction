from typing import Any

from src.application.analysis_result import AnalysisResult
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.features.feature_engine import FeatureEngine
from src.features.legacy_feature_engine import LegacyFeatureEngine
from src.ingestion.json_event_source import JsonEventSource
from src.prediction.features import features_to_vector
from src.prediction.model import (
    build_model,
    predict_threat_with_confidence,
)
from src.preprocessing.normalize import (
    add_time_differences,
    normalize_events,
)
from src.risk.legacy_risk_engine import LegacyRiskEngine


class ThreatPipeline:
    """
    Application pipeline coordinating ingestion,
    preprocessing, feature extraction, ML prediction,
    and risk assessment.

    The pipeline uses application-level ports for the
    new architecture while preserving the existing
    legacy execution path.
    """

    def __init__(
        self,
        event_source: EventSourcePort | None = None,
        feature_engine: FeatureEnginePort | None = None,
        risk_engine: RiskEnginePort | None = None,
    ) -> None:
        self.event_source = (
            event_source
            if event_source is not None
            else JsonEventSource()
        )

        self.feature_engine = (
            feature_engine
            if feature_engine is not None
            else LegacyFeatureEngine()
        )

        self.risk_engine = (
            risk_engine
            if risk_engine is not None
            else LegacyRiskEngine()
        )

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

        model = build_model()

        prediction, confidence = predict_threat_with_confidence(
            model,
            features_to_vector(features),
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

        This method intentionally preserves the existing
        preprocessing, feature extraction, ML prediction,
        and risk assessment behavior.
        """
        normalize_events(events)
        add_time_differences(events)

        features = FeatureEngine().extract(events)

        model = build_model()

        prediction, confidence = predict_threat_with_confidence(
            model,
            features_to_vector(features),
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
