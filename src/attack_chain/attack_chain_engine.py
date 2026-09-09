from datetime import datetime
from typing import Any

from src.application.correlation_result import CorrelationResult


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

    STAGE_SCORES = {
        "reconnaissance": 10,
        "credential_attack": 20,
        "initial_access": 25,
        "privilege_escalation": 20,
        "lateral_movement": 25,
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

        chain_score = self._calculate_chain_score(stage_names)

        return {
            "chain_type": chain_type,
            "stages": stages,
            "stage_count": len(stages),
            "duration_seconds": duration_seconds,
            "chain_score": chain_score,
        }

    def build_chain_from_correlations(
        self,
        correlations: list[CorrelationResult | dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Build an attack chain from structured correlation results.

        CorrelationResult is the preferred application-level format.

        Legacy dictionaries are also supported for backward compatibility.
        The existing build_chain(events) method remains unchanged.
        """
        if not correlations:
            return None

        events: list[dict[str, Any]] = []

        for correlation in correlations:
            if isinstance(correlation, CorrelationResult):
                correlation_events = correlation.events
            else:
                correlation_events = correlation["events"]

            for event in correlation_events:
                if event not in events:
                    events.append(event)

        events.sort(
            key=lambda event: self._parse_timestamp(event["timestamp"])
        )

        return self.build_chain(events)

    @classmethod
    def _calculate_chain_score(
        cls,
        stages: list[str],
    ) -> int:
        """
        Calculate the attack chain score.

        Each unique attack stage contributes to the score.
        Repeated stages do not add additional points.
        """
        unique_stages = set(stages)

        return sum(
            cls.STAGE_SCORES.get(stage, 0)
            for stage in unique_stages
        )

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
    def _parse_timestamp(
        timestamp: datetime | str,
    ) -> datetime:
        """
        Convert a legacy timestamp string to datetime.
        """
        if isinstance(timestamp, datetime):
            return timestamp

        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        )
