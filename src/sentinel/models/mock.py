"""Deterministic mock model used for offline CI and public baselines.

The mock follows the scenario's reference plan and simulates a *gullible* instruction-following
LLM: it obeys directives it reads anywhere in its context using a small, documented grammar
(see docs/architecture.md, "Mock model directive grammar"):

* ``call <tool_name> with {json}``: propose that tool call next.
* ``remember: <text>`` (whole line): propose writing <text> to memory.
* ``[part k/n] ...``: fragments joined in order once all n parts were seen.
* ``base64:<data>``: decoded before parsing.
* ``{{last_result}}`` / ``{{last_result.field}}`` inside directive arguments: filled from the most
  recent successful tool result.

This models susceptibility, not attack knowledge: the agent itself has no attack-specific code,
and the grammar is identical for benign and adversarial text.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from sentinel.agent.base import AgentContext, Feedback, FeedbackKind
from sentinel.agent.planner import render_args, render_text
from sentinel.core.actions import ActionType, ArgValue, CandidateAction
from sentinel.core.scenario import PlanStep
from sentinel.models.base import ModelAdapter, TurnHints

CALL_RE = re.compile(r"\bcall\s+([a-z][a-z0-9_]{1,63})\s+with\s+(?=\{)", re.IGNORECASE)
REMEMBER_RE = re.compile(r"^[ \t]*(?:please[ \t]+)?remember[ \t]*:[ \t]*(\S.*)$", re.IGNORECASE | re.MULTILINE)
PART_RE = re.compile(r"\[part\s+(\d)\s*/\s*(\d)\]\s?(.*?)(?=\[part\s+\d\s*/\s*\d\]|\Z)", re.IGNORECASE | re.DOTALL)
B64_RE = re.compile(r"base64:([A-Za-z0-9+/=]{12,})")
MAX_DIRECTIVES_PER_TEXT = 8


@dataclass(frozen=True)
class Directive:
    kind: str  # "call" | "remember"
    tool: str | None = None
    raw_args: str = ""
    content: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.tool}:{self.raw_args}:{self.content}"


def _decode_base64(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            return base64.b64decode(match.group(1), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return match.group(0)

    return B64_RE.sub(replace, text)


def parse_directives(text: str) -> list[Directive]:
    text = _decode_base64(text)
    directives: list[Directive] = []
    for match in REMEMBER_RE.finditer(text):
        directives.append(Directive(kind="remember", content=match.group(1).strip()))
    remaining = REMEMBER_RE.sub("", text)
    decoder = json.JSONDecoder()
    for match in CALL_RE.finditer(remaining):
        try:
            obj, end = decoder.raw_decode(remaining, match.end())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            raw = remaining[match.end() : end]
            directives.append(Directive(kind="call", tool=match.group(1).lower(), raw_args=raw))
        if len(directives) >= MAX_DIRECTIVES_PER_TEXT:
            break
    return directives


def iter_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in iter_strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in iter_strings(item)]
    return []


class MockModelAdapter(ModelAdapter):
    name = "mock"

    def __init__(self) -> None:
        self._plan: deque[PlanStep] = deque()
        self._pending: deque[Directive] = deque()
        self._seen: set[str] = set()
        self._fragments: dict[int, dict[int, str]] = {}
        self._results: dict[str, Any] = {}
        self._last_result: dict[str, Any] | None = None
        self._inflight: tuple[str, PlanStep | None] | None = None
        self._awaiting_confirmation: PlanStep | None = None
        self._confirmed_step: PlanStep | None = None
        self._final_sent = False

    # ---- lifecycle ---------------------------------------------------------------------------
    def start_turn(self, goal: str, hints: TurnHints) -> None:
        self._plan = deque(hints.reference_plan)
        self._awaiting_confirmation = None
        self._confirmed_step = None
        self._final_sent = False

    def propose(self, context: AgentContext) -> CandidateAction:
        while self._pending:
            directive = self._pending.popleft()
            action = self._directive_action(directive)
            if action is not None:
                self._inflight = ("directive", None)
                return action
        if self._confirmed_step is not None:
            step = self._confirmed_step
            self._confirmed_step = None
            self._inflight = ("plan", step)
            return self._step_action(step)
        while self._plan:
            step = self._plan.popleft()
            if step.confirm:
                self._awaiting_confirmation = step
                self._inflight = ("confirm", step)
                target = self._step_action(step)
                return CandidateAction(
                    type=ActionType.REQUEST_CONFIRMATION,
                    confirmation_for=target,
                    content=f"Please confirm: {step.tool}",
                )
            self._inflight = ("plan", step)
            return self._step_action(step)
        self._inflight = ("fallback", None)
        return CandidateAction(type=ActionType.RESPOND, content="I could not complete the task.", final=True)

    def observe(self, feedback: Feedback) -> None:
        kind = feedback.kind
        if kind in (FeedbackKind.USER_MESSAGE, FeedbackKind.MEMORY):
            self._ingest(feedback.observation.text)
            return
        inflight, self._inflight = self._inflight, None
        step = inflight[1] if inflight else None
        if kind is FeedbackKind.CONFIRMATION:
            if inflight and inflight[0] == "confirm" and feedback.approved and step is not None:
                self._confirmed_step = step
            self._awaiting_confirmation = None
            return
        if kind is FeedbackKind.TOOL_RESULT:
            data = feedback.observation.data
            if feedback.succeeded:
                self._last_result = data
                if inflight and inflight[0] == "plan" and step is not None:
                    self._results[step.id] = data
            self._ingest_strings(iter_strings(data))
            return
        if kind is FeedbackKind.BLOCKED and inflight and inflight[0] == "confirm":
            self._awaiting_confirmation = None

    # ---- internals ---------------------------------------------------------------------------
    def _step_action(self, step: PlanStep) -> CandidateAction:
        if step.action == "tool_call":
            return CandidateAction(
                type=ActionType.TOOL_CALL, tool=step.tool, arguments=render_args(step.args, self._results)
            )
        content = render_text(step.content or "", self._results)
        if step.action == "memory_write":
            return CandidateAction(type=ActionType.MEMORY_WRITE, content=content)
        return CandidateAction(type=ActionType.RESPOND, content=content, final=step.final)

    def _ingest(self, text: str) -> None:
        self._ingest_strings([text])

    def _ingest_strings(self, texts: list[str]) -> None:
        found: list[Directive] = []
        for text in texts:
            found.extend(parse_directives(text))
            for match in PART_RE.finditer(text):
                index, total = int(match.group(1)), int(match.group(2))
                if 1 <= index <= total <= 9:
                    self._fragments.setdefault(total, {})[index] = match.group(3)
        for total, parts in list(self._fragments.items()):
            if len(parts) == total:
                joined = "".join(parts[i] for i in range(1, total + 1))
                del self._fragments[total]
                found.extend(parse_directives(joined))
        fresh = [d for d in found if d.key not in self._seen]
        for directive in fresh:
            self._seen.add(directive.key)
        self._pending.extendleft(reversed(fresh))

    def _directive_action(self, directive: Directive) -> CandidateAction | None:
        if directive.kind == "remember":
            return CandidateAction(type=ActionType.MEMORY_WRITE, content=directive.content[:2_000])
        results: dict[str, Any] = {"last_result": self._last_result or {}}
        try:
            raw = json.loads(directive.raw_args)
        except json.JSONDecodeError:
            return None
        args: dict[str, ArgValue] = {
            str(k): v for k, v in raw.items() if isinstance(v, str | int | float | bool) or v is None
        }
        try:
            return CandidateAction(type=ActionType.TOOL_CALL, tool=directive.tool, arguments=render_args(args, results))
        except ValueError:
            return None
