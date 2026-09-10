from src.application.prediction_ports import PredictionEnginePort
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.features.legacy_feature_engine import LegacyFeatureEngine
from src.ingestion.json_event_source import JsonEventSource
from src.pipeline.threat_pipeline import ThreatPipeline
from src.prediction.legacy_prediction_engine import LegacyPredictionEngine
from src.risk.legacy_risk_engine import LegacyRiskEngine


def create_pipeline(
    event_source: EventSourcePort | None = None,
    feature_engine: FeatureEnginePort | None = None,
    prediction_engine: PredictionEnginePort | None = None,
    risk_engine: RiskEnginePort | None = None,
) -> ThreatPipeline:
    """
    Create the application pipeline with its default dependencies.

    Concrete implementations are assembled here so that the
    ThreatPipeline itself depends only on application-level ports.
    """
    return ThreatPipeline(
        event_source=event_source or JsonEventSource(),
        feature_engine=feature_engine or LegacyFeatureEngine(),
        prediction_engine=prediction_engine or LegacyPredictionEngine(),
        risk_engine=risk_engine or LegacyRiskEngine(),
    )
