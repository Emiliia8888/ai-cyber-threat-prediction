def detect_port_scan_followed_by_failed_login(events):
    for i in range(len(events) - 1):
        current = events[i]
        next_event = events[i + 1]

        if (
            current["type"] == "port_scan"
            and next_event["type"] == "failed_login"
	    and current["source"] == next_event["source"]
            and next_event["time_since_previous"].total_seconds() <= 60
        ):
            return True

    return False

def detect_failed_login_followed_by_successful_login(events):
    for i in range(len(events) - 1):
        current = events[i]
        next_event = events[i + 1]

        if (
            current["type"] == "failed_login"
            and next_event["type"] == "successful_login"
	    and current["source"] == next_event["source"]
            and next_event["time_since_previous"].total_seconds() <= 60
        ):
            return True

    return False


def assess_threat_level(events):
    if (
        detect_port_scan_followed_by_failed_login(events)
        and detect_failed_login_followed_by_successful_login(events)
    ):
        return "high"

    elif detect_port_scan_followed_by_failed_login(events):
        return "medium"

    elif detect_failed_login_followed_by_successful_login(events):
        return "low"

    return "normal"
