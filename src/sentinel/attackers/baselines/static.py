"""Static attacker: replays the scenario's predefined payloads in order."""

from __future__ import annotations

from sentinel.attackers.interface import Attacker, AttackMutation, AttackRequest


class StaticAttacker(Attacker):
    name = "static"

    def __init__(self) -> None:
        self._next = 0

    def next_mutation(self, request: AttackRequest) -> AttackMutation | None:
        if request.budget_remaining <= 0 or self._next >= len(request.seed_payloads):
            return None
        payload = request.seed_payloads[self._next]
        self._next += 1
        return AttackMutation(surface_id=payload.surface_id, operation=payload.operation, text=payload.text)
