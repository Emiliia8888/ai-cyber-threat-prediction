from src.application.correlation_result import CorrelationResult
from src.application.risk_assessment import RiskAssessment


def test_risk_assessment_to_dict():

    correlation = CorrelationResult(
        sequence="port_scan -> failed_login",
        source="server_01",
        events=[],
        time_difference_seconds=60,
    )

    assessment = RiskAssessment(
        threat_level="medium",
        attack_type="port_scanning",
        agreement=True,
        explanation=["Port scan activity detected"],
        severity=[
            {
                "level": "MEDIUM",
                "message": "Port scan activity detected",
            }
        ],
        correlations=[correlation],
        attack_chain=None,
    )

    result = assessment.to_dict()

    assert result["threat_level"] == "medium"
    assert result["attack_type"] == "port_scanning"
    assert result["agreement"] is True
    assert result["correlations"][0]["sequence"] == (
        "port_scan -> failed_login"
    )
    assert result["attack_chain"] is None


def test_risk_assessment_supports_item_access():

    assessment = RiskAssessment(
        threat_level="high",
        attack_type="multi_stage_attack",
        agreement=True,
        explanation=[],
        severity=[],
        correlations=[],
        attack_chain=None,
    )

    assert assessment["threat_level"] == "high"
    assert assessment["attack_type"] == "multi_stage_attack"
