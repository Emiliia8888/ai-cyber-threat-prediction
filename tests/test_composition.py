from src.application.composition import (
    create_analysis_worker,
    create_event_repository,
    create_job_queue,
    create_pipeline,
    create_threat_analysis,
)
from src.application.threat_analysis import ThreatAnalysis
from src.infrastructure.persistence.in_memory_event_repository import (
    InMemoryEventRepository,
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
    analysis = ThreatAnalysis()
    worker = create_analysis_worker(analysis)

    assert isinstance(worker, InMemoryAnalysisWorker)

def test_create_threat_analysis_returns_default_service():

    analysis = create_threat_analysis()

    assert isinstance(analysis, ThreatAnalysis)
