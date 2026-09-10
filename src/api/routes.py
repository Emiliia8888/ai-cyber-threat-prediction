from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from src.api.dependencies import get_threat_analysis
from src.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    JobResponse,
)
from src.application.job import Job, JobStatus
from src.application.threat_analysis import ThreatAnalysis


router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    request: AnalyzeRequest,
    analysis: ThreatAnalysis = Depends(get_threat_analysis),
) -> AnalyzeResponse:
    events = [
        event.model_dump()
        for event in request.events
    ]

    result = analysis.analyze_events(events)

    return AnalyzeResponse(
        **result.to_dict()
    )


@router.post("/jobs", response_model=JobResponse)
def create_job(
    request: AnalyzeRequest,
    analysis: ThreatAnalysis = Depends(get_threat_analysis),
) -> JobResponse:
    events = [
        event.model_dump()
        for event in request.events
    ]

    job = Job(
        job_id=str(uuid4()),
        events=events,
        status=JobStatus.PENDING,
    )

    analysis.enqueue_analysis(job)

    return JobResponse(
        job_id=job.job_id,
        status=job.status.value,
    )


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(
    job_id: str,
    analysis: ThreatAnalysis = Depends(get_threat_analysis),
) -> JobResponse:
    job = analysis.get_job(job_id)

    if job is None:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    result = None

    if job.result is not None:
        result = AnalyzeResponse(
            **job.result.to_dict()
        )

    return JobResponse(
        job_id=job.job_id,
        status=job.status.value,
        result=result,
        error=job.error,
    )
