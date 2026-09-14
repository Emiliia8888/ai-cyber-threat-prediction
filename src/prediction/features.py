from datetime import datetime

def count_events(events, event_type):
    return sum(1 for event in events if event["type"] == event_type)


def count_failed_logins(events):
    return count_events(events, "failed_login")


def count_port_scans(events):
    return count_events(events, "port_scan")


def count_successful_logins(events):
    return count_events(events, "successful_login")


def get_time_since_previous(event, previous_event):
    time_difference = event.get("time_since_previous")

    if time_difference is not None:
        return time_difference.total_seconds()

    current_timestamp = event["timestamp"]
    previous_timestamp = previous_event["timestamp"]

    if isinstance(current_timestamp, str):
        current_timestamp = datetime.strptime(
            current_timestamp,
            "%Y-%m-%d %H:%M:%S",
        )

    if isinstance(previous_timestamp, str):
        previous_timestamp = datetime.strptime(
            previous_timestamp,
            "%Y-%m-%d %H:%M:%S",
        )

    return (current_timestamp - previous_timestamp).total_seconds()


def count_unique_sources(events):
    return len({event["source"] for event in events})


def calculate_time_span(events):
    if len(events) < 2:
        return 0.0

    timestamps = []

    for event in events:
        timestamp = event["timestamp"]

        if isinstance(timestamp, str):
            timestamp = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S",
            )

        timestamps.append(timestamp)

    return (max(timestamps) - min(timestamps)).total_seconds()


def calculate_event_rate(count, time_span_seconds):
    if time_span_seconds <= 0:
        return 0.0

    return count / time_span_seconds


def count_rapid_failed_logins(events, threshold_seconds=60):
    count = 0

    for i in range(1, len(events)):
        current = events[i]
        previous = events[i - 1]

        if (
            current["type"] == "failed_login"
            and previous["type"] == "failed_login"
            and current["source"] == previous["source"]
            and get_time_since_previous(current, previous)
            <= threshold_seconds
        ):
            count += 1

    return count


def detect_port_scan_followed_by_failed_login(
    events,
    threshold_seconds=60,
):
    for i in range(len(events) - 1):
        current = events[i]
        next_event = events[i + 1]

        if (
            current["type"] == "port_scan"
            and next_event["type"] == "failed_login"
            and current["source"] == next_event["source"]
            and get_time_since_previous(next_event, current)
            <= threshold_seconds
        ):
            return 1

    return 0


def detect_failed_login_followed_by_successful_login(
    events,
    threshold_seconds=60,
):
    for i in range(len(events) - 1):
        current = events[i]
        next_event = events[i + 1]

        if (
            current["type"] == "failed_login"
            and next_event["type"] == "successful_login"
            and current["source"] == next_event["source"]
            and get_time_since_previous(next_event, current)
            <= threshold_seconds
        ):
            return 1

    return 0


def extract_features(events):
    port_scan_count = count_port_scans(events)
    failed_login_count = count_failed_logins(events)
    successful_login_count = count_successful_logins(events)

    event_count = len(events)
    unique_source_count = count_unique_sources(events)
    time_span_seconds = calculate_time_span(events)

    failed_login_rate = calculate_event_rate(
        failed_login_count,
        time_span_seconds,
    )

    successful_login_rate = calculate_event_rate(
        successful_login_count,
        time_span_seconds,
    )

    return {
        "port_scan_count": port_scan_count,
        "failed_login_count": failed_login_count,
        "successful_login_count": successful_login_count,
        "event_count": event_count,
        "unique_source_count": unique_source_count,
        "time_span_seconds": time_span_seconds,
        "failed_login_rate": failed_login_rate,
        "successful_login_rate": successful_login_rate,
        "rapid_failed_login_count": count_rapid_failed_logins(events),
        "port_scan_followed_by_failed_login":
            detect_port_scan_followed_by_failed_login(events),
        "failed_login_followed_by_successful_login":
            detect_failed_login_followed_by_successful_login(events),
    }


def features_to_vector(features):
    return [
        features["port_scan_count"],
        features["failed_login_count"],
        features["successful_login_count"],
        features["event_count"],
        features["unique_source_count"],
        features["time_span_seconds"],
        features["failed_login_rate"],
        features["successful_login_rate"],
        features["rapid_failed_login_count"],
        features["port_scan_followed_by_failed_login"],
        features["failed_login_followed_by_successful_login"],
    ]
