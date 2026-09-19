import pytest

from sentinel.core.actions import ActionType
from sentinel.models.base import ModelError
from sentinel.models.hf_adapter import DEFAULT_MODEL, parse_action, resolve_runtime


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


def test_parse_action_rejects_a_malformed_action() -> None:
    with pytest.raises(ModelError, match="invalid action"):
        parse_action('{"type": "not_a_real_action"}')
