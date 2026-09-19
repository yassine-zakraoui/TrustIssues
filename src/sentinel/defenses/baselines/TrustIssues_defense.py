"""TrustIssues defense: combines provenance checks with a weighted risk score."""

from __future__ import annotations

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.defenses.baselines.common import (
    decision,
    is_confirmed,
    is_consequential,
    is_external_recipient,
    squash,
    target_action,
    texts_by_trust,
)
from sentinel.defenses.baselines.provenance import instruction_in_untrusted
from sentinel.defenses.interface import Defense, DefenseRequest

READ_ONLY_SUFFIXES = ("_read", "_lookup", "_search", "_list", "_get")


def is_read_only_tool(tool: str | None) -> bool:
    if tool is None:
        return True
    return any(tool.endswith(suffix) for suffix in READ_ONLY_SUFFIXES)


class TrustIssuesDefense(Defense):
    name = "trustissues"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        action = target_action(request)
        untrusted, sensitive = texts_by_trust(request)
        allowed = request.policy_context.get("allowed_tools", [])

        if action.type is not ActionType.TOOL_CALL:
            return decision(Decision.ALLOW, 0.1, 0.6, ["NON_TOOL_ACTION"])

        if action.tool not in allowed:
            return decision(
                Decision.BLOCK, 0.9, 0.9,
                ["TOOL_OUT_OF_SCOPE"],
                f"{action.tool} n'est pas dans les outils autorisés pour cette tâche",
            )

        if is_consequential(request, action) and not is_confirmed(request, action):
            return decision(
                Decision.ESCALATE, 0.7, 0.7,
                ["MISSING_CONFIRMATION"],
                "action sensible nécessitant une validation humaine",
            )

        if not is_read_only_tool(action.tool) and instruction_in_untrusted(action, untrusted):
            return decision(
                Decision.BLOCK, 0.85, 0.7,
                ["UNTRUSTED_INSTRUCTION_SOURCE"],
                "l'instruction correspond précisément à du contenu non fiable",
            )

        return decision(Decision.ALLOW, 0.1, 0.7, ["POLICY_COMPLIANT"])