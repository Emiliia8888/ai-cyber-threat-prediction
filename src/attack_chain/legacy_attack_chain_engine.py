from typing import Any

from src.application.attack_chain_ports import AttackChainEnginePort
from src.attack_chain.attack_chain_engine import AttackChainEngine


class LegacyAttackChainEngine(AttackChainEnginePort):
    """
    Adapter connecting the application attack chain interface
    with the existing AttackChainEngine implementation.
    """

    def __init__(self) -> None:
        self._engine = AttackChainEngine()

    def build_chain(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        return self._engine.build_chain(events)
