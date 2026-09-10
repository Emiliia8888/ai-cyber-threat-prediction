from typing import Any

from pydantic import BaseModel, Field


class EventRequest(BaseModel):
    type: str
    source: str
    timestamp: str


class AnalyzeRequest(BaseModel):
    events: list[EventRequest] = Field(min_length=1)


class AnalyzeResponse(BaseModel):
    prediction: str
    confidence: float
    threat_level: str
    attack_type: str
    agreement: bool
    explanation: list[str]
    severity: list[dict[str, Any]]
    features: dict[str, Any]
    correlations: list[dict[str, Any]] | None = None
    attack_chain: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    status: str
