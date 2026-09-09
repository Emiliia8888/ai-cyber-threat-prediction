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


def test_analysis_result_serializes_typed_correlations():
    from src.application.correlation_result import CorrelationResult

    correlation = CorrelationResult(
        sequence="port_scan -> failed_login",
        source="server_01",
        events=[],
        time_difference_seconds=30,
    )

    result = AnalysisResult(
        prediction="medium",
        confidence=0.9,
        threat_level="medium",
        attack_type="port_scanning",
        agreement=True,
        explanation=[],
        severity=[],
        features={},
        correlations=[correlation],
    )

    data = result.to_dict()

    assert data["correlations"][0]["sequence"] == (
        "port_scan -> failed_login"
    )
    assert data["correlations"][0]["source"] == "server_01"
    assert data["correlations"][0]["time_difference_seconds"] == 30
