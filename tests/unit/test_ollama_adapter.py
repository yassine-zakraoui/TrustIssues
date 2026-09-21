import json

import httpx
import pytest

from sentinel.agent.base import AgentContext
from sentinel.core.actions import ActionType
from sentinel.domains import DOMAIN_TOOLS
from sentinel.models.base import ModelError, TurnHints
from sentinel.models.ollama_adapter import DEFAULT_OLLAMA_MODEL, OllamaModelAdapter


def context() -> AgentContext:
    return AgentContext(goal="g", turn_index=0, step_id=1, observations=[], provenance={}, tools=[])


def adapter(handler, **kw) -> OllamaModelAdapter:
    a = OllamaModelAdapter(transport=httpx.MockTransport(handler), **kw)
    specs = [t.spec() for t in DOMAIN_TOOLS["soc"]() if t.name in ("alert_read", "incident_create")]
    a.start_turn("Triage alert AL-3003.", TurnHints(tools=specs))
    return a


def reply(content: str) -> httpx.Response:
    return httpx.Response(200, json={"message": {"content": content}})


def test_default_tag_is_the_reference_model() -> None:
    assert DEFAULT_OLLAMA_MODEL == "qwen3:8b"


def test_it_sends_the_kit_prompt_and_tool_schemas() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return reply('{"type": "respond", "content": "done", "final": true}')

    action = adapter(handler).propose(context())
    assert action.type is ActionType.RESPOND
    assert seen["model"] == "qwen3:8b" and seen["stream"] is False
    assert seen["options"]["temperature"] == 0, "a rerun has to reproduce the same trace"
    assert seen["think"] is False, "thinking on eats the decode budget before the action lands"
    system, user = seen["messages"]
    assert "exactly one JSON object" in system["content"]
    assert '"alert_id"' in user["content"] and "pattern" in user["content"], "tool schemas must reach the model"


def test_it_reads_a_tool_name_written_into_the_type_field() -> None:
    # the malformation Qwen3-8B produces constantly
    raw = '{"type": "incident_create", "alert_id": "AL-3003", "title": "t", "severity": "low", "summary": "s"}'
    action = adapter(lambda r: reply(raw)).propose(context())
    assert action.type is ActionType.TOOL_CALL and action.tool == "incident_create"


def test_a_stopped_server_says_what_to_do_about_it() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(ModelError, match="ollama pull"):
        adapter(refused).propose(context())


def test_the_model_tag_reaches_the_server() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return reply('{"type": "respond", "content": "ok", "final": true}')

    adapter(handler, model="llama3.1:8b").propose(context())
    assert seen["model"] == "llama3.1:8b"
