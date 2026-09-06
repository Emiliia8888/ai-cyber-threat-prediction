def detect_attack_type(events):
    if (
        any(event["type"] == "port_scan" for event in events)
        and any(event["type"] == "failed_login" for event in events)
        and any(event["type"] == "successful_login" for event in events)
    ):
        return "multi_stage_attack"

    if any(
        event["type"] == "failed_login"
        for event in events
    ) and any(
        event["type"] == "successful_login"
        for event in events
    ):
        return "credential_compromise"

    if any(
        event["type"] == "port_scan"
        for event in events
    ):
        return "port_scanning"

    if sum(
        event["type"] == "failed_login"
        for event in events
    ) >= 3:
        return "brute_force"

    return "normal"
