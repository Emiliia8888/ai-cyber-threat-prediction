from datetime import datetime

from src.ingestion.ssh_log_parser import SSHLogParser


def test_parse_failed_password():
    parser = SSHLogParser()

    log = (
        "Oct  7 14:32:11 server sshd[1234]: "
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    )

    event = parser.parse(log, year=2026)

    assert event.event_type == "failed_login"
    assert event.source == "192.168.1.50"
    assert event.timestamp == datetime(2026, 10, 7, 14, 32, 11)


def test_parse_successful_password():
    parser = SSHLogParser()

    log = (
        "Oct  7 14:35:20 server sshd[1234]: "
        "Accepted password for emiliia from 192.168.1.50 port 22 ssh2"
    )

    event = parser.parse(log, year=2026)

    assert event.event_type == "successful_login"
    assert event.source == "192.168.1.50"
    assert event.timestamp == datetime(2026, 10, 7, 14, 35, 20)


def test_parse_unsupported_event():
    parser = SSHLogParser()

    log = (
        "Oct  7 14:36:10 server sshd[1234]: "
        "Connection closed by 192.168.1.50 port 22"
    )

    try:
        parser.parse(log, year=2026)
    except ValueError as exc:
        assert str(exc) == "Unsupported SSH log format"
    else:
        raise AssertionError("Expected ValueError")


def test_parse_unknown_ssh_event_type():
    parser = SSHLogParser()

    log = (
        "Oct  7 14:36:10 server sshd[1234]: "
        "Connection reset from 192.168.1.50 port 22"
    )

    try:
        parser.parse(log, year=2026)
    except ValueError as exc:
        assert str(exc) == "Unsupported SSH event type"
    else:
        raise AssertionError("Expected ValueError")


def test_parse_invalid_user():
    parser = SSHLogParser()

    log = (
        "Oct  7 14:37:10 server sshd[1234]: "
        "Invalid user admin from 192.168.1.50 port 22"
    )

    event = parser.parse(log, year=2026)

    assert event.event_type == "failed_login"
    assert event.source == "192.168.1.50"
    assert event.timestamp == datetime(2026, 10, 7, 14, 37, 10)
