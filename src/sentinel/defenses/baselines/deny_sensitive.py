"""Baseline B: block every sensitive or consequential tool. Safe but over-restrictive."""

from __future__ import annotations

from sentinel.core.actions import ActionType, Decision, DefenseDecision
from sentinel.defenses.baselines.common import decision, is_consequential, target_action
from sentinel.defenses.interface import Defense, DefenseRequest

SENSITIVE_TOOLS = frozenset(
    {
        "email_send",
        "ticket_update",
        "payment_confirm",
        "payment_execute",
        "incident_update",
        "remediation_execute",
    }
)


class DenySensitiveDefense(Defense):
    name = "deny_sensitive"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        action = target_action(request)
        if action.type is ActionType.TOOL_CALL and (
            action.tool in SENSITIVE_TOOLS or is_consequential(request, action)
        ):
            return decision(Decision.BLOCK, 0.9, 0.6, ["SENSITIVE_TOOL_DENIED"], f"{action.tool} is on the deny list")
        return decision(Decision.ALLOW, 0.1, 0.5, ["NOT_SENSITIVE"])
