"""Reference agent backed by a local Ollama server.

This is the practical way to run the reference agent on a laptop. Qwen3-8B at full precision needs
roughly 16 GB of VRAM; the same model quantized to 4 bit through Ollama needs about 5 GB and runs
on a 6 GB card. Start it with ``ollama pull qwen3:8b``, then::

    uv run sentinel run --scenario <path> --defense allow_all --model ollama:qwen3:8b

The prompt, the tool schemas and the action parser are the ones in ``hf_adapter``, so the agent
behaves the same way whichever backend serves the tokens; only the weights move.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import CandidateAction
from sentinel.models.base import ModelAdapter, ModelError, TurnHints
from sentinel.models.hf_adapter import SYSTEM_PROMPT, parse_action, tool_card

DEFAULT_OLLAMA_MODEL = "qwen3:8b"
DEFAULT_HOST = "http://127.0.0.1:11434"


class OllamaModelAdapter(ModelAdapter):
    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        host: str | None = None,
        max_new_tokens: int = 768,
        max_context_chars: int = 12_000,
        enable_thinking: bool = False,
        timeout_s: float = 180.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._model = model
        self._client = httpx.Client(
            base_url=(host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/"),
            timeout=timeout_s,
            transport=transport,
        )
        self._max_new_tokens = max_new_tokens
        self._max_context_chars = max_context_chars
        self._enable_thinking = enable_thinking
        self._goal = ""
        self._tools: list[dict[str, Any]] = []

    def start_turn(self, goal: str, hints: TurnHints) -> None:
        self._goal = goal
        self._tools = hints.tools  # reference_plan is deliberately ignored

    def _messages(self, context: AgentContext) -> list[dict[str, str]]:
        history = "\n".join(f"[{obs.kind}] {obs.text}" for obs in context.observations)
        history = history[-self._max_context_chars :]
        tools = json.dumps([tool_card(t) for t in self._tools])
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Tools: {tools}\nGoal: {self._goal}\nHistory:\n{history}"},
        ]

    def propose(self, context: AgentContext) -> CandidateAction:
        payload = {
            "model": self._model,
            "messages": self._messages(context),
            "stream": False,
            "think": self._enable_thinking,
            # temperature 0 so a rerun of the same scenario produces the same trace
            "options": {"temperature": 0, "num_predict": self._max_new_tokens},
        }
        try:
            response = self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            raise ModelError(
                f"could not reach Ollama at {self._client.base_url} ({exc}); is `ollama serve` running "
                f"and has `ollama pull {self._model}` finished?"
            ) from exc
        except json.JSONDecodeError as exc:
            raise ModelError(f"Ollama returned a non-JSON body: {exc}") from exc
        text = str((body.get("message") or {}).get("content", ""))
        return parse_action(text, {str(t["name"]) for t in self._tools})

    def observe(self, feedback: Feedback) -> None:
        return None

    def close(self) -> None:
        self._client.close()
