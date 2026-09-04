def explain_risk(events):
    explanations = []

    event_types = [event["type"] for event in events]

    if "port_scan" in event_types:
        explanations.append(
            "Port scan activity detected"
        )

    if "failed_login" in event_types:
        explanations.append(
            "Failed login attempts detected"
        )

    if (
        "failed_login" in event_types
        and "successful_login" in event_types
    ):
        explanations.append(
            "Successful login after failed attempts detected"
        )

    if not explanations:
        explanations.append(
            "No significant suspicious activity detected"
        )

    return explanations

