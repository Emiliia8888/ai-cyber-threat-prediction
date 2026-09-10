from fastapi import APIRouter

from src.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
)
from src.application.threat_analysis import ThreatAnalysis


router = APIRouter()

analysis = ThreatAnalysis()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    events = [
        event.model_dump()
        for event in request.events
    ]

    result = analysis.analyze_events(events)

    return AnalyzeResponse(
        **result.to_dict()
    )
