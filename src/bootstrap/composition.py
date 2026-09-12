from typing import Any, TYPE_CHECKING

from src.application.alert_ports import AlertEnginePort
from src.application.analysis_worker import AnalysisWorkerPort
from src.application.event_repository import EventRepositoryPort
from src.application.interfaces import (
    EventSourcePort,
    FeatureEnginePort,
    RiskEnginePort,
)
from src.application.job_queue import JobQueuePort
from src.application.job_repository import JobRepositoryPort
from src.application.preprocessing_ports import PreprocessingPort
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

from src.infrastructure.persistence.in_memory_event_repository import (
    InMemoryEventRepository,
)
from src.infrastructure.persistence.in_memory_job_repository import (
    InMemoryJobRepository,
)
from src.infrastructure.persistence.postgres_connection import (
    PostgresConnectionFactory,
)
from src.infrastructure.persistence.postgres_job_repository import (
    PostgresJobRepository,
)
from src.infrastructure.queue.in_memory_job_queue import (
    InMemoryJobQueue,
)
from src.infrastructure.workers.in_memory_analysis_worker import (
    InMemoryAnalysisWorker,
)

from src.config.settings import DEFAULT_SETTINGS, Settings
from src.pipeline.threat_pipeline import ThreatPipeline
from src.prediction.legacy_prediction_engine import (
    LegacyPredictionEngine,
)
from src.preprocessing.legacy_preprocessor import LegacyPreprocessor
from src.risk.legacy_risk_engine import LegacyRiskEngine


if TYPE_CHECKING:
    from src.application.threat_analysis import ThreatAnalysis


def create_pipeline(
    event_source: EventSourcePort | None = None,
    preprocessing: PreprocessingPort | None = None,
    feature_engine: FeatureEnginePort | None = None,
    prediction_engine: PredictionEnginePort | None = None,
    risk_engine: RiskEnginePort | None = None,
) -> ThreatPipeline:
    correlation_engine = LegacyCorrelationEngine()
    attack_chain_engine = LegacyAttackChainEngine()

    return ThreatPipeline(
        event_source=event_source or JsonEventSource(),
        preprocessing=preprocessing or LegacyPreprocessor(),
        feature_engine=feature_engine or LegacyFeatureEngine(),
        prediction_engine=prediction_engine
        or LegacyPredictionEngine(),
        risk_engine=risk_engine
        or LegacyRiskEngine(
            correlation_engine=correlation_engine,
            attack_chain_engine=attack_chain_engine,
        ),
    )


def create_alert_engine() -> AlertEnginePort:
    return LegacyAlertEngine()


def create_event_repository() -> EventRepositoryPort:
    return InMemoryEventRepository()


def create_job_queue() -> JobQueuePort:
    return InMemoryJobQueue()


def create_job_repository(
    settings: Settings = DEFAULT_SETTINGS,
    connection: Any | None = None,
) -> JobRepositoryPort:
    if settings.use_postgres_jobs:
        if connection is None:
            connection = PostgresConnectionFactory(settings).create()

        return PostgresJobRepository(connection)

    return InMemoryJobRepository()


def create_analysis_worker(
    analysis: "ThreatAnalysis",
) -> AnalysisWorkerPort:
    return InMemoryAnalysisWorker(analysis)


def create_threat_analysis(
    settings: Settings = DEFAULT_SETTINGS,
) -> "ThreatAnalysis":
    from src.application.threat_analysis import ThreatAnalysis

    return ThreatAnalysis(
        pipeline=create_pipeline(),
        event_repository=create_event_repository(),
        job_queue=create_job_queue(),
        job_repository=create_job_repository(settings),
    )
