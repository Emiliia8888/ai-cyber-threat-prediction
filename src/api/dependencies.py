from fastapi import Request

from src.application.threat_analysis import ThreatAnalysis


def get_threat_analysis(request: Request) -> ThreatAnalysis:
    return request.app.state.analysis
