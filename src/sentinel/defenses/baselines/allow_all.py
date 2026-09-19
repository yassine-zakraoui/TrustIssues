"""Baseline A: allow everything. Maximum utility, zero protection."""

from __future__ import annotations

from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.baselines.common import decision
from sentinel.defenses.interface import Defense, DefenseRequest


class AllowAllDefense(Defense):
    name = "allow_all"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        return decision(Decision.ALLOW, 0.0, 0.5, ["ALLOW_ALL"])
