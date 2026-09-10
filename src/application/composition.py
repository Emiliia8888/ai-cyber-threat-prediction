from src.application.alert_ports import AlertEnginePort
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.application.prediction_ports import PredictionEnginePort
from src.attack_chain.legacy_attack_chain_engine import (
    LegacyAttackChainEngine,
)
from src.alerts.legacy_alert_engine import LegacyAlertEngine
from src.correlation.legacy_correlation_engine import (
    LegacyCorrelationEngine,
)
from src.features.legacy_feature_engine import LegacyFeatureEngine
from src.ingestion.json_event_source import JsonEventSource
from src.pipeline.threat_pipeline import ThreatPipeline
from src.prediction.legacy_prediction_engine import (
    LegacyPredictionEngine,
)
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
    ThreatPipeline and RiskEngine depend only on application-level ports.
    """

    correlation_engine = LegacyCorrelationEngine()
    attack_chain_engine = LegacyAttackChainEngine()

    return ThreatPipeline(
        event_source=event_source or JsonEventSource(),
        feature_engine=feature_engine or LegacyFeatureEngine(),
        prediction_engine=prediction_engine or LegacyPredictionEngine(),
        risk_engine=risk_engine
        or LegacyRiskEngine(
            correlation_engine=correlation_engine,
            attack_chain_engine=attack_chain_engine,
        ),
    )


def create_alert_engine() -> AlertEnginePort:
    """
    Create the default alert engine.

    Concrete alert implementations are assembled here so that
    application entrypoints depend only on the AlertEnginePort.
    """

    return LegacyAlertEngine()
