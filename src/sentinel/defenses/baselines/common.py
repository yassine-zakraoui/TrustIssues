"""Shared helpers for baseline defenses. Only request-visible information is used."""

from __future__ import annotations

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import DefenseRequest

UNTRUSTED = {TrustLevel.UNTRUSTED_INTERNAL, TrustLevel.UNTRUSTED_EXTERNAL, TrustLevel.ADVERSARY_CONTROLLED}
SENSITIVE = {Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED}
STATUS_CONSEQUENTIAL = {"ticket_update": {"closed", "resolved"}, "incident_update": {"closed"}}
OUTBOUND_TOOLS = {"email_send", "email_draft"}


def decision(
    kind: Decision,
    risk: float,
    confidence: float,
    codes: list[str],
    explanation: str | None = None,
    rewritten: CandidateAction | None = None,
) -> DefenseDecision:
    return DefenseDecision(
        decision=kind,
        risk_score=round(min(1.0, max(0.0, risk)), 4),
        confidence=confidence,
        reason_codes=codes,
        explanation=explanation,
        rewritten_action=rewritten,
    )


def target_action(request: DefenseRequest) -> CandidateAction:
    action = request.candidate_action
    if action.type is ActionType.REQUEST_CONFIRMATION and action.confirmation_for is not None:
        return action.confirmation_for
    return action


def is_consequential(request: DefenseRequest, action: CandidateAction) -> bool:
    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return False
    if action.tool in request.policy_context.get("consequential_tools", []):
        return True
    status = action.arguments.get("status")
    return isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set())


def is_confirmed(request: DefenseRequest, action: CandidateAction) -> bool:
    return action.digest() in request.history_digest.confirmations_granted


def is_external_recipient(request: DefenseRequest, action: CandidateAction) -> bool:
    if action.tool not in OUTBOUND_TOOLS:
        return False
    recipient = str(action.arguments.get("to", "")).lower()
    internal = [d.lower() for d in request.policy_context.get("internal_email_domains", [])]
    return not any(recipient.endswith("@" + domain) for domain in internal)


def texts_by_trust(request: DefenseRequest) -> tuple[list[str], list[str]]:
    """Split conversation content into (untrusted texts, sensitive texts) using provenance."""
    records = {record.id: record.provenance for record in request.provenance}
    untrusted: list[str] = []
    sensitive: list[str] = []
    for item in request.conversation:
        provs = [records[pid] for pid in item.provenance_ids if pid in records]
        if any(p.trust_level in UNTRUSTED for p in provs):
            untrusted.append(item.content)
        if any(p.sensitivity in SENSITIVE for p in provs):
            sensitive.append(item.content)
    return untrusted, sensitive


def squash(text: str) -> str:
    return " ".join(text.split()).lower()
