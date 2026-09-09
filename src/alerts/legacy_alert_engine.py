from src.application.alert_ports import AlertEnginePort
from src.detection.alerts import generate_alert


class LegacyAlertEngine(AlertEnginePort):

    """
    Adapter connecting the application alert interface
    with the existing alert implementation.
    """

    def generate(
        self,
        attack_type: str,
        threat_level: str,
        confidence: float,
    ) -> str:
        return generate_alert(
            attack_type,
            threat_level,
            confidence,
        )
