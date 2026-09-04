def calculate_event_severity(events):
    severity = []

    event_types = [event["type"] for event in events]

    if "port_scan" in event_types:
        severity.append(
            {
                "level": "MEDIUM",
                "message": "Port scan activity detected",
            }
        )

    if "failed_login" in event_types:
        severity.append(
            {
                "level": "LOW",
                "message": "Failed login attempts detected",
            }
        )

    if (
        "failed_login" in event_types
        and "successful_login" in event_types
    ):
        severity.append(
            {
                "level": "HIGH",
                "message": "Successful login after failed attempts detected",
            }
        )

    if not severity:
        severity.append(
            {
                "level": "LOW",
                "message": "No significant suspicious activity detected",
            }
        )

    return severity

