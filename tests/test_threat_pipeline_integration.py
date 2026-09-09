from datetime import datetime, timedelta

from src.pipeline.threat_pipeline import ThreatPipeline


def test_pipeline_returns_attack_chain():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start.strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": (
                start + timedelta(seconds=20)
            ).strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": (
                start + timedelta(seconds=40)
            ).strftime("%Y-%m-%d %H:%M:%S"),
        },
    ]

    result = ThreatPipeline().run_from_events(events)

    assert result["prediction"] == "high"
    assert result["threat_level"] == "high"
    assert result["attack_type"] == "multi_stage_attack"

    assert result["attack_chain"] is not None
    assert result["attack_chain"]["chain_type"] == "multi_stage_attack"
    assert result["attack_chain"]["stage_count"] == 3

    stages = result["attack_chain"]["stages"]

    assert stages[0]["stage"] == "reconnaissance"
    assert stages[1]["stage"] == "credential_attack"
    assert stages[2]["stage"] == "initial_access"


def test_pipeline_returns_no_attack_chain_for_incomplete_sequence():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start.strftime("%Y-%m-%d %H:%M:%S"),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": (
                start + timedelta(seconds=20)
            ).strftime("%Y-%m-%d %H:%M:%S"),
        },
    ]

    result = ThreatPipeline().run_from_events(events)

    assert result["attack_chain"] is None
