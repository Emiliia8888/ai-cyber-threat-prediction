from unittest.mock import MagicMock, patch

from src.application.threat_analysis import ThreatAnalysis
from src.bootstrap.composition import (
    create_analysis_worker,
    create_event_repository,
    create_job_queue,
    create_job_repository,
    create_pipeline,
    create_threat_analysis,
)
from src.config.settings import Settings
from src.infrastructure.persistence.in_memory_event_repository import (
    InMemoryEventRepository,
)
from src.infrastructure.persistence.in_memory_job_repository import (
    InMemoryJobRepository,
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
from src.pipeline.threat_pipeline import ThreatPipeline


def test_create_pipeline_returns_default_pipeline():
    pipeline = create_pipeline()
    assert isinstance(pipeline, ThreatPipeline)


def test_create_pipeline_accepts_custom_dependencies():
    custom_pipeline = create_pipeline()
    assert isinstance(custom_pipeline, ThreatPipeline)


def test_create_event_repository_returns_default_repository():
    repository = create_event_repository()
    assert isinstance(repository, InMemoryEventRepository)


def test_create_job_queue_returns_default_queue():
    queue = create_job_queue()
    assert isinstance(queue, InMemoryJobQueue)


def test_create_analysis_worker_returns_default_worker():
    analysis = create_threat_analysis()
    worker = create_analysis_worker(analysis)
    assert isinstance(worker, InMemoryAnalysisWorker)


def test_create_threat_analysis_returns_default_service():
    analysis = create_threat_analysis()
    assert isinstance(analysis, ThreatAnalysis)


def test_create_job_repository_uses_in_memory_by_default():
    repository = create_job_repository()
    assert isinstance(repository, InMemoryJobRepository)


def test_create_job_repository_uses_postgres_when_enabled():
    settings = Settings(use_postgres_jobs=True)
    connection = MagicMock()

    repository = create_job_repository(
        settings=settings,
        connection=connection,
    )

    assert isinstance(repository, PostgresJobRepository)
    assert repository.connection is connection


def test_create_job_repository_creates_postgres_connection_when_enabled():
    settings = Settings(use_postgres_jobs=True)
    connection = MagicMock()

    with patch(
        "src.bootstrap.composition.PostgresConnectionFactory"
    ) as factory_class:
        factory_class.return_value.create.return_value = connection

        repository = create_job_repository(settings=settings)

    factory_class.assert_called_once_with(settings)
    factory_class.return_value.create.assert_called_once_with()

    assert isinstance(repository, PostgresJobRepository)
    assert repository.connection is connection
