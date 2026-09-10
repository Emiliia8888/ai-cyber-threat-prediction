from src.application.composition import create_pipeline
from src.features.legacy_feature_engine import LegacyFeatureEngine
from src.ingestion.json_event_source import JsonEventSource
from src.pipeline.threat_pipeline import ThreatPipeline
from src.prediction.legacy_prediction_engine import LegacyPredictionEngine
from src.risk.legacy_risk_engine import LegacyRiskEngine


def test_create_pipeline_builds_default_dependencies():
    pipeline = create_pipeline()

    assert isinstance(pipeline, ThreatPipeline)
    assert isinstance(pipeline.event_source, JsonEventSource)
    assert isinstance(pipeline.feature_engine, LegacyFeatureEngine)
    assert isinstance(pipeline.prediction_engine, LegacyPredictionEngine)
    assert isinstance(pipeline.risk_engine, LegacyRiskEngine)

def test_create_pipeline_accepts_custom_dependencies():
    event_source = JsonEventSource()
    feature_engine = LegacyFeatureEngine()
    prediction_engine = LegacyPredictionEngine()
    risk_engine = LegacyRiskEngine()

    pipeline = create_pipeline(
        event_source=event_source,
        feature_engine=feature_engine,
        prediction_engine=prediction_engine,
        risk_engine=risk_engine,
    )

    assert pipeline.event_source is event_source
    assert pipeline.feature_engine is feature_engine
    assert pipeline.prediction_engine is prediction_engine
    assert pipeline.risk_engine is risk_engine
