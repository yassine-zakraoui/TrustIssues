import copy

import pytest

from sentinel.attackers.interface import AttackMutation
from sentinel.attackers.validator import AttackMutationValidator
from sentinel.core.scenario import MutationOperation, parse_scenario
from sentinel.evaluator.scenario_checks import check_scenario
from tests.conftest import ROOT, load, minimal_scenario, state_for

pytestmark = pytest.mark.security


def test_mutations_only_touch_the_declared_field() -> None:
    scenario = load("enterprise_poisoned_invoice")
    state = state_for("enterprise_poisoned_invoice")
    before = copy.deepcopy(state.collections)
    validator = AttackMutationValidator(scenario, state)
    assert validator.apply(
        AttackMutation(surface_id="delivery_note_body", operation=MutationOperation.REPLACE_TEXT, text="changed")
    ).accepted
    changed = [
        (c, rid, field)
        for c, table in state.collections.items()
        for rid, record in table.items()
        for field, value in record.items()
        if before[c][rid].get(field) != value
    ]
    assert changed == [("documents", "DOC-3102", "body")]
    assert state.tool_output_overrides == {} and state.effects == []


def test_undeclared_surfaces_and_other_records_are_unreachable() -> None:
    scenario = load("enterprise_poisoned_invoice")
    state = state_for("enterprise_poisoned_invoice")
    validator = AttackMutationValidator(scenario, state)
    for surface_id in ("wiki_WK-001_content", "documents/DOC-3103/body", "memory", "DOC-3102"):
        outcome = validator.apply({"surface_id": surface_id, "operation": "replace_text", "text": "x"})
        assert not outcome.accepted
    assert "{{" not in str(state.get("wiki", "WK-001"))
    assert state.get("documents", "DOC-3103")["body"].startswith("Customer and partner")  # type: ignore[index]


def attack_scenario(surface: dict[str, object]):  # type: ignore[no-untyped-def]
    return parse_scenario(
        minimal_scenario(
            attack={"present": True, "family": "indirect_prompt_injection", "objective": "x", "surfaces": [surface]},
            security_properties=["no_forbidden_effect"],
        )
    )


@pytest.mark.parametrize(
    ("surface", "message"),
    [
        (
            {"id": "s", "kind": "document", "target": "documents/DOC-9999/body", "operations": ["append_text"]},
            "not in fixture",
        ),
        (
            {"id": "s", "kind": "email", "target": "emails/EM-2001/attachments", "operations": ["append_text"]},
            "not a text field",
        ),
        (
            {
                "id": "s",
                "kind": "tool_output",
                "target": "tool_output/email_read/body",
                "operations": ["set_tool_text"],
            },
            "not an untrusted text field",
        ),
        (
            {"id": "s", "kind": "tool_output", "target": "tool_output/http_get/body", "operations": ["set_tool_text"]},
            "unknown tool",
        ),
    ],
)
def test_semantic_checks_reject_unsafe_surfaces(surface: dict[str, object], message: str) -> None:
    problems = check_scenario(attack_scenario(surface), ROOT)
    assert any(message in p for p in problems), problems


def test_memory_surface_cannot_target_other_collections() -> None:
    with pytest.raises(ValueError, match="memory targets"):
        attack_scenario({"id": "s", "kind": "memory", "target": "wiki/WK-001/content", "operations": ["write_memory"]})


def test_validator_rechecks_field_type_at_apply_time() -> None:
    scenario = load("enterprise_poisoned_invoice")
    state = state_for("enterprise_poisoned_invoice")
    state.get("documents", "DOC-3102")["body"] = ["not", "text"]  # type: ignore[index]
    outcome = AttackMutationValidator(scenario, state).apply(
        {"surface_id": "delivery_note_body", "operation": "append_text", "text": "x"}
    )
    assert not outcome.accepted and "not a text field" in outcome.reason
