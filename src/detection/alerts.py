
def generate_alert(attack_type, threat_level, confidence):
    if threat_level == "high":
        return (
            "\U0001f6a8 CRITICAL SECURITY ALERT: "
            f"{attack_type} detected "
            f"(confidence: {confidence:.0%})"
        )

    if threat_level == "medium":
        return (
            "\u26a0\ufe0f SECURITY ALERT: "
            f"{attack_type} detected "
            f"(confidence: {confidence:.0%})"
        )

    if threat_level == "low":
        return (
            "\u26a0\ufe0f SECURITY WARNING: "
            f"{attack_type} detected "
            f"(confidence: {confidence:.0%})"
        )

    return (
        "No significant security threat detected"
    )
