from src.pipeline.threat_pipeline import ThreatPipeline


def test_threat_pipeline_runs_end_to_end():
    pipeline = ThreatPipeline()

    result = pipeline.run("data/events.json")

    assert result["prediction"] == "high"
    assert result["confidence"] == 1.0

    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"
    assert result["agreement"] is True

    assert result["features"]["port_scan_count"] == 1
    assert result["features"]["failed_login_count"] == 1
    assert result["features"]["successful_login_count"] == 1
    assert result["features"]["port_scan_followed_by_failed_login"] == 1

    assert len(result["explanation"]) > 0
    assert len(result["severity"]) > 0
