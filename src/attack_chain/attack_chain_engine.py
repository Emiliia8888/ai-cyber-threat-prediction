from typing import Any


class AttackChainEngine:
    """
    Detects multi-stage attack chains from correlated events.

    The engine builds a higher-level attack chain from
    already ordered security events.

    Existing event types remain supported:
        port_scan
        failed_login
        successful_login
    """

    def build_chain(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Build a multi-stage attack chain from security events.

        Currently supported chain:

            port_scan
                ->
            failed_login
                ->
            successful_login

        Returns None when the required sequence is not present.
        """

        if not events:
            return None

        stages: list[dict[str, Any]] = []

        stage_mapping = {
            "port_scan": "reconnaissance",
            "failed_login": "credential_attack",
            "successful_login": "initial_access",
        }

        for event in events:
            event_type = event["type"]

            if event_type not in stage_mapping:
                continue

            stages.append(
                {
                    "stage": stage_mapping[event_type],
                    "event_type": event_type,
                    "source": event["source"],
                    "timestamp": event["timestamp"],
                }
            )

        if len(stages) < 2:
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

        return {
            "chain_type": "multi_stage_attack",
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
