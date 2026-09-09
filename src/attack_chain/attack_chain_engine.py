from typing import Any


class AttackChainEngine:
    """
    Detects multi-stage attack chains from security events.

    The engine builds higher-level attack chains from
    ordered security events.

    Supported event types include:

        port_scan
        service_enumeration
        failed_login
        brute_force
        successful_login
        privilege_escalation
        lateral_movement
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

    def build_chain(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Build a multi-stage attack chain from security events.

        Supported chain:

            reconnaissance
                ->
            credential_attack
                ->
            initial_access
                ->
            privilege_escalation
                ->
            lateral_movement

        The reconnaissance stage may be represented by
        port_scan or service_enumeration.

        The credential_attack stage may be represented by
        failed_login or brute_force.

        Returns None when the required sequence is not present.
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
