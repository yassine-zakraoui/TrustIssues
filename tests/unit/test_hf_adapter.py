import pytest

from sentinel.core.actions import ActionType
from sentinel.models.base import ModelError
from sentinel.models.hf_adapter import (
    DEFAULT_MODEL,
    SYSTEM_PROMPT,
    parse_action,
    resolve_runtime,
    tool_card,
)


def test_default_reference_model_is_qwen3_8b() -> None:
    assert DEFAULT_MODEL == "Qwen/Qwen3-8B"


@pytest.mark.parametrize(
    ("device", "dtype", "cuda", "expected"),
    [
        ("auto", "auto", True, ("cuda", "auto")),
        ("auto", "auto", False, ("cpu", "float32")),  # bf16 on CPU is unusably slow
        ("auto", "bfloat16", False, ("cpu", "bfloat16")),  # an explicit choice is respected
        ("cuda:1", "auto", False, ("cuda:1", "auto")),
        ("cpu", "auto", True, ("cpu", "float32")),
    ],
)
def test_resolve_runtime(device: str, dtype: str, cuda: bool, expected: tuple[str, str]) -> None:
    assert resolve_runtime(device, dtype, cuda) == expected


def test_tool_card_keeps_the_argument_schema_the_model_must_satisfy() -> None:
    from sentinel.domains.finance.tools import PaymentConfirm, PaymentPrepare

    card = tool_card(PaymentPrepare().spec())
    assert card["name"] == "payment_prepare"
    # preparing does not move money; confirming does, and the model is told which is which
    assert card["consequential"] is False
    assert tool_card(PaymentConfirm().spec())["consequential"] is True
    # the model has to produce these names, and account/beneficiary ids have to match their patterns
    assert set(card["arguments"]) == {"account_id", "beneficiary_id", "amount", "reference"}
    assert set(card["required"]) == {"account_id", "beneficiary_id", "amount", "reference"}
    assert card["arguments"]["account_id"]["pattern"] == r"^ACC-\d{4}$"


def test_system_prompt_tells_the_agent_to_finish_the_work_first() -> None:
    # a real model with no reference plan will otherwise answer from the goal text and stop
    # before it ever opens the record the attack was injected into
    assert "before you finish" in SYSTEM_PROMPT
    assert "exact argument names" in SYSTEM_PROMPT


def test_parse_action_reads_a_plain_json_action() -> None:
    action = parse_action('{"type": "tool_call", "tool": "policy_search", "arguments": {"query": "refunds"}}')
    assert action.type is ActionType.TOOL_CALL and action.tool == "policy_search"


def test_parse_action_ignores_a_thinking_block() -> None:
    raw = (
        '<think>The user wants {"type": "respond"} but I should check policy first.</think>\n'
        '{"type": "tool_call", "tool": "policy_search", "arguments": {"query": "refunds"}}'
    )
    action = parse_action(raw)
    assert action.tool == "policy_search"


def test_parse_action_ignores_prose_after_the_action() -> None:
    action = parse_action('{"type": "respond", "content": "done", "final": true}\nI hope that helps! {oops}')
    assert action.type is ActionType.RESPOND and action.content == "done"


def test_parse_action_rejects_a_truncated_thinking_budget() -> None:
    with pytest.raises(ModelError, match="enable_thinking=False"):
        parse_action("<think>Let me work through the provenance of this document step by step")


def test_parse_action_reads_a_tool_name_written_into_the_type_field() -> None:
    # what Qwen3-8B emits constantly; the intent is unambiguous when the name is a real tool
    raw = '{"type": "incident_create", "alert_id": "AL-3003", "title": "Rare outbound domain"}'
    action = parse_action(raw, known_tools={"incident_create", "alert_read"})
    assert action.type is ActionType.TOOL_CALL and action.tool == "incident_create"
    assert action.arguments["alert_id"] == "AL-3003"


def test_parse_action_reads_that_shape_with_nested_arguments_too() -> None:
    raw = '{"type": "alert_read", "arguments": {"alert_id": "AL-3003"}}'
    action = parse_action(raw, known_tools={"alert_read"})
    assert action.tool == "alert_read" and action.arguments == {"alert_id": "AL-3003"}


def test_parse_action_will_not_invent_a_tool_that_does_not_exist() -> None:
    # coercing this would fabricate a call to a tool the scenario never allowed, which the gateway
    # would then record as an attempted unauthorized tool - a finding the team did not cause
    with pytest.raises(ModelError, match="invalid action"):
        parse_action('{"type": "definitely_not_a_tool", "foo": 1}', known_tools={"alert_read"})


def test_parse_action_without_a_tool_list_coerces_nothing() -> None:
    with pytest.raises(ModelError, match="invalid action"):
        parse_action('{"type": "incident_create", "alert_id": "AL-3003"}')


def test_parse_action_rejects_a_malformed_action() -> None:
    with pytest.raises(ModelError, match="invalid action"):
        parse_action('{"type": "not_a_real_action"}')
