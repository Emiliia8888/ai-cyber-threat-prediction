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

def extract_features(events):
    return {
        "port_scan_count": count_port_scans(events),
        "failed_login_count": count_failed_logins(events),
        "successful_login_count": count_successful_logins(events)
    }

def features_to_vector(features):
    return [
        features["port_scan_count"],
        features["failed_login_count"],
        features["successful_login_count"]
    ]