from src.application.composition import create_pipeline
from src.attack_chain.legacy_attack_chain_engine import (
    LegacyAttackChainEngine,
)
from src.correlation.legacy_correlation_engine import (
    LegacyCorrelationEngine,
)
from src.ingestion.json_event_source import JsonEventSource
from src.prediction.legacy_prediction_engine import (
    LegacyPredictionEngine,
)
from src.features.legacy_feature_engine import (
    LegacyFeatureEngine,
)
from src.risk.legacy_risk_engine import LegacyRiskEngine


def test_create_pipeline_returns_default_pipeline():
    pipeline = create_pipeline()

    assert pipeline is not None
    assert isinstance(
        pipeline.event_source,
        JsonEventSource,
    )
    assert isinstance(
        pipeline.feature_engine,
        LegacyFeatureEngine,
    )
    assert isinstance(
        pipeline.prediction_engine,
        LegacyPredictionEngine,
    )
    assert isinstance(
        pipeline.risk_engine,
        LegacyRiskEngine,
    )


def test_create_pipeline_accepts_custom_dependencies():
    event_source = JsonEventSource()
    feature_engine = LegacyFeatureEngine()
    prediction_engine = LegacyPredictionEngine()

    correlation_engine = LegacyCorrelationEngine()
    attack_chain_engine = LegacyAttackChainEngine()

    risk_engine = LegacyRiskEngine(
        correlation_engine=correlation_engine,
        attack_chain_engine=attack_chain_engine,
    )

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

from src.application.composition import create_event_repository
from src.infrastructure.persistence.in_memory_event_repository import (
    InMemoryEventRepository,
)


def test_create_event_repository_returns_default_repository():
    repository = create_event_repository()

    assert isinstance(repository, InMemoryEventRepository)
