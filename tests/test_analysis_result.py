from src.application.analysis_result import AnalysisResult


def test_analysis_result_to_dict():
    result = AnalysisResult(
        prediction="high",
        confidence=1.0,
        threat_level="high",
        attack_type="multi_stage_attack",
        agreement=True,
        explanation=["Suspicious activity detected"],
        severity=[
            {
                "level": "HIGH",
                "message": "Successful login after failed attempts detected",
            }
        ],
        features={
            "port_scan_count": 1,
            "failed_login_count": 2,
            "successful_login_count": 1,
            "port_scan_followed_by_failed_login": 1,
        },
    )

    data = result.to_dict()

    assert data["prediction"] == "high"
    assert data["confidence"] == 1.0
    assert data["threat_level"] == "high"
    assert data["attack_type"] == "multi_stage_attack"
    assert data["agreement"] is True
    assert data["features"]["failed_login_count"] == 2
