import pytest

from sentinel.attackers.baselines import MutationAttacker, StaticAttacker, get_attacker
from sentinel.attackers.interface import AttackMutation, AttackRequest, SeedPayload
from sentinel.attackers.validator import AttackMutationValidator
from sentinel.core.scenario import MutationOperation
from tests.conftest import load, state_for


def validator(scenario_id: str) -> AttackMutationValidator:
    return AttackMutationValidator(load(scenario_id), state_for(scenario_id))


def request_for(v: AttackMutationValidator, round_: int = 0) -> AttackRequest:
    scenario = v.scenario
    return AttackRequest(
        scenario_id=scenario.id,
        domain=scenario.domain.value,
        round=round_,
        step_id=1,
        objective=scenario.attack.objective,
        surfaces=v.surface_views(),
        seed_payloads=[
            SeedPayload(surface_id=p.surface, operation=p.operation, text=p.text) for p in scenario.attack.payloads
        ],
        budget_remaining=v.budget_remaining,
    )


def test_append_and_replace_apply_to_declared_text_field() -> None:
    v = validator("enterprise_poisoned_invoice")
    original = v.state.get("documents", "DOC-3102")["body"]  # type: ignore[index]
    assert v.apply(
        AttackMutation(surface_id="delivery_note_body", operation=MutationOperation.APPEND_TEXT, text="extra")
    ).accepted
    assert v.state.get("documents", "DOC-3102")["body"] == f"{original}\nextra"  # type: ignore[index]
    assert v.apply({"surface_id": "delivery_note_body", "operation": "replace_text", "text": "new"}).accepted
    assert v.state.get("documents", "DOC-3102")["body"] == "new"  # type: ignore[index]


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ({"surface_id": "unknown", "operation": "append_text", "text": "x"}, "undeclared surface"),
        ({"surface_id": "delivery_note_body", "operation": "set_tool_text", "text": "x"}, "not allowed"),
        ({"surface_id": "delivery_note_body", "operation": "append_text", "text": "x" * 1501}, "max_chars"),
        ({"surface_id": "delivery_note_body", "operation": "append_text", "text": "a\x00b"}, "control"),
        ({"surface_id": "delivery_note_body", "operation": "delete_record", "text": "x"}, "malformed"),
        (
            {"surface_id": "delivery_note_body", "operation": "append_text", "text": "x", "target": "wiki/WK-001"},
            "malformed",
        ),
    ],
)
def test_invalid_mutations_are_rejected(raw: dict[str, str], reason: str) -> None:
    v = validator("enterprise_poisoned_invoice")
    before = dict(v.state.get("documents", "DOC-3102") or {})
    outcome = v.apply(raw)
    assert not outcome.accepted and reason in outcome.reason
    assert v.state.get("documents", "DOC-3102") == before


def test_budget_is_enforced() -> None:
    v = validator("enterprise_poisoned_invoice")
    mutation = AttackMutation(surface_id="delivery_note_body", operation=MutationOperation.APPEND_TEXT, text="x")
    results = [v.apply(mutation).accepted for _ in range(4)]
    assert results == [True, True, True, False]


def test_tool_output_surface_sets_override() -> None:
    v = validator("enterprise_val_ticket_comment")
    assert v.apply({"surface_id": "requester_comment", "operation": "set_tool_text", "text": "hi"}).accepted
    assert v.state.tool_output_overrides[("ticket_read", "latest_comment")] == "hi"


def test_benign_scenarios_accept_no_mutations() -> None:
    v = validator("enterprise_project_status")
    assert not v.apply({"surface_id": "x", "operation": "append_text", "text": "x"}).accepted


def test_static_attacker_replays_payloads_in_order() -> None:
    v = validator("finance_split_settlement")
    attacker = StaticAttacker()
    first = attacker.next_mutation(request_for(v))
    second = attacker.next_mutation(request_for(v, 1))
    assert first is not None and second is not None
    assert (first.surface_id, second.surface_id) == ("inquiry_body", "invoice_body")
    assert attacker.next_mutation(request_for(v, 2)) is None


def test_mutation_attacker_is_deterministic_and_valid() -> None:
    def sequence() -> list[AttackMutation]:
        v = validator("finance_split_settlement")
        attacker = get_attacker("mutation")
        out = []
        for round_ in range(3):
            mutation = attacker.next_mutation(request_for(v, round_))
            assert mutation is not None
            assert v.validate(mutation)[0].accepted
            out.append(mutation)
        return out

    first, second = sequence(), sequence()
    assert first == second
    assert isinstance(get_attacker("mutation"), MutationAttacker)
