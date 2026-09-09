from datetime import datetime, timedelta

from src.attack_chain.attack_chain_engine import AttackChainEngine


def test_build_multi_stage_attack_chain():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=20),
        },
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=40),
        },
    ]

    chain = AttackChainEngine().build_chain(events)

    assert chain is not None
    assert chain["chain_type"] == "multi_stage_attack"
    assert chain["stage_count"] == 3

    assert chain["stages"][0]["stage"] == "reconnaissance"
    assert chain["stages"][1]["stage"] == "credential_attack"
    assert chain["stages"][2]["stage"] == "initial_access"


def test_return_none_when_chain_is_incomplete():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=20),
        },
    ]

    chain = AttackChainEngine().build_chain(events)

    assert chain is None


def test_return_none_when_events_are_in_wrong_order():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "failed_login",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=20),
        },
        {
            "type": "port_scan",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=40),
        },
    ]

    chain = AttackChainEngine().build_chain(events)

    assert chain is None


def test_ignore_unrelated_events():
    start = datetime(2026, 9, 2, 16, 18, 0)

    events = [
        {
            "type": "successful_login",
            "source": "server_01",
            "timestamp": start,
        },
        {
            "type": "normal_event",
            "source": "server_01",
            "timestamp": start + timedelta(seconds=20),
        },
    ]

    chain = AttackChainEngine().build_chain(events)

    assert chain is None


def test_empty_events_return_none():
    chain = AttackChainEngine().build_chain([])

    assert chain is None
