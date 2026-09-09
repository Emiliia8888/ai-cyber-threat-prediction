from src.attack_chain.attack_chain_engine import AttackChainEngine


def test_build_chain_from_correlations():

    correlations = [
        {
            "sequence": "port_scan -> failed_login",
            "source": "server_01",
            "events": [
                {
                    "type": "port_scan",
                    "source": "server_01",
                    "timestamp": "2026-09-02 16:18:00",
                },
                {
                    "type": "failed_login",
                    "source": "server_01",
                    "timestamp": "2026-09-02 16:19:00",
                },
            ],
            "time_difference_seconds": 60,
        },
        {
            "sequence": "failed_login -> successful_login",
            "source": "server_01",
            "events": [
                {
                    "type": "failed_login",
                    "source": "server_01",
                    "timestamp": "2026-09-02 16:19:00",
                },
                {
                    "type": "successful_login",
                    "source": "server_01",
                    "timestamp": "2026-09-02 16:20:00",
                },
            ],
            "time_difference_seconds": 60,
        },
    ]

    engine = AttackChainEngine()

    result = engine.build_chain_from_correlations(correlations)

    assert result is not None
    assert result["chain_type"] == "multi_stage_attack"
    assert result["stage_count"] == 3
    assert result["duration_seconds"] == 120
    assert result["chain_score"] == 55
