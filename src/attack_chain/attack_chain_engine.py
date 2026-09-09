from datetime import datetime
from typing import Any


class AttackChainEngine:
    """
    Detects multi-stage attack chains from security events.

    The engine builds higher-level attack chains from
    ordered and temporally related security events.
    """

    STAGE_MAPPING = {
        "port_scan": "reconnaissance",
        "service_enumeration": "reconnaissance",
        "failed_login": "credential_attack",
        "brute_force": "credential_attack",
        "successful_login": "initial_access",
        "privilege_escalation": "privilege_escalation",
        "lateral_movement": "lateral_movement",
    }

    def __init__(self, max_chain_window: int = 300) -> None:
        """
        Configure the maximum allowed duration of an attack chain.

        Default: 300 seconds (5 minutes).
        """
        self.max_chain_window = max_chain_window

    def build_chain(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Build a multi-stage attack chain from security events.

        The chain must contain:

            reconnaissance
                ->
            credential_attack
                ->
            initial_access

        Optional later stages:

            privilege_escalation
                ->
            lateral_movement

        The complete chain must occur within max_chain_window.
        """

        if not events:
            return None

        stages: list[dict[str, Any]] = []

        for event in events:
            event_type = event["type"]

            stage = self.STAGE_MAPPING.get(event_type)

            if stage is None:
                continue

            stages.append(
                {
                    "stage": stage,
                    "event_type": event_type,
                    "source": event["source"],
                    "timestamp": event["timestamp"],
                }
            )

        if len(stages) < 3:
            return None

        stage_names = [stage["stage"] for stage in stages]

        required_stages = [
            "reconnaissance",
            "credential_attack",
            "initial_access",
        ]

        if not self._contains_ordered_sequence(
            stage_names,
            required_stages,
        ):
            return None

        timestamps = [
            self._parse_timestamp(stage["timestamp"])
            for stage in stages
        ]

        duration_seconds = (
            timestamps[-1] - timestamps[0]
        ).total_seconds()

        if duration_seconds > self.max_chain_window:
            return None

        chain_type = "multi_stage_attack"

        if self._contains_ordered_sequence(
            stage_names,
            [
                "reconnaissance",
                "credential_attack",
                "initial_access",
                "privilege_escalation",
                "lateral_movement",
            ],
        ):
            chain_type = "advanced_multi_stage_attack"

        return {
            "chain_type": chain_type,
            "stages": stages,
            "stage_count": len(stages),
            "duration_seconds": duration_seconds,
        }

    @staticmethod
    def _contains_ordered_sequence(
        stages: list[str],
        required: list[str],
    ) -> bool:
        """
        Check whether the required stages occur in order.
        """

        required_index = 0

        for stage in stages:
            if stage == required[required_index]:
                required_index += 1

                if required_index == len(required):
                    return True

        return False

    @staticmethod
    def _parse_timestamp(timestamp: datetime | str) -> datetime:
        """
        Convert a legacy timestamp string to datetime.
        """

        if isinstance(timestamp, datetime):
            return timestamp

        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        )
