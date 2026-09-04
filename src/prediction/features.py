def count_failed_logins(events):
    count = 0

    for event in events:
        if event["type"] == "failed_login":
            count += 1

    return count


def count_port_scans(events):
    count = 0

    for event in events:
        if event["type"] == "port_scan":
            count += 1

    return count


def count_successful_logins(events):
    count = 0

    for event in events:
        if event["type"] == "successful_login":
            count += 1

    return count

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
            return 1

    return 0

def extract_features(events):
    return {
        "port_scan_count": count_port_scans(events),
        "failed_login_count": count_failed_logins(events),
        "successful_login_count": count_successful_logins(events),
        "port_scan_followed_by_failed_login":
            detect_port_scan_followed_by_failed_login(events),
    }

def features_to_vector(features):
    return [
        features["port_scan_count"],
        features["failed_login_count"],
        features["successful_login_count"],
        features["port_scan_followed_by_failed_login"],
    ]
