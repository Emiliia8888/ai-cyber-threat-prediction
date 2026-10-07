from datetime import datetime

from src.ingestion.ssh_log_event_source import SSHLogEventSource


def test_load_ssh_log_file(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Oct  7 14:32:11 server sshd[1234]: "
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2\n"
        "Oct  7 14:35:20 server sshd[1234]: "
        "Accepted password for emiliia from 192.168.1.50 port 22 ssh2\n"
        "Oct  7 14:36:10 server sshd[1234]: "
        "Connection reset from 192.168.1.50 port 22\n",
        encoding="utf-8",
    )

    source = SSHLogEventSource(year=2026)

    events = source.load(log_file)

    assert len(events) == 2

    assert events[0].event_type == "failed_login"
    assert events[0].source == "192.168.1.50"
    assert events[0].timestamp == datetime(2026, 10, 7, 14, 32, 11)

    assert events[1].event_type == "successful_login"
    assert events[1].source == "192.168.1.50"
    assert events[1].timestamp == datetime(2026, 10, 7, 14, 35, 20)
