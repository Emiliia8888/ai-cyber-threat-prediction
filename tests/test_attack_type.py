from src.detection.attack_type import detect_attack_type

def test_detect_attack_type_normal():
    events = []

    result = detect_attack_type(events)

    assert result == "normal"

def test_detect_attack_type_brute_force():
    events = [
        {"type": "failed_login"},
        {"type": "failed_login"},
        {"type": "failed_login"},
    ]

    result = detect_attack_type(events)

    assert result == "brute_force"

def test_detect_attack_type_port_scanning():
    events = [
        {"type": "port_scan"},
    ]

    result = detect_attack_type(events)

    assert result == "port_scanning"

def test_detect_attack_type_credential_compromise():
    events = [
        {"type": "failed_login"},
        {"type": "successful_login"},
    ]

    result = detect_attack_type(events)

    assert result == "credential_compromise"

def test_detect_attack_type_multi_stage_attack():
    events = [
        {"type": "port_scan"},
        {"type": "failed_login"},
        {"type": "successful_login"},
    ]

    result = detect_attack_type(events)

    assert result == "multi_stage_attack"
