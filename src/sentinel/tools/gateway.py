"""The only path from an approved action to simulator state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.state import WorldState
from sentinel.tools.base import Sink, Tool, ToolContext, ToolOutcome, tool_field_provenance
from sentinel.tools.registry import ToolRegistry


@dataclass
class GatewayResult:
    tool: Tool | None
    outcome: ToolOutcome
    sink: Sink | None


class ToolGateway:
    def __init__(self, registry: ToolRegistry, state: WorldState) -> None:
        self.registry = registry
        self.state = state

    def execute(self, action: CandidateAction, step_id: int, timestamp: datetime) -> GatewayResult:
        if action.type is not ActionType.TOOL_CALL or action.tool is None:
            return GatewayResult(None, ToolOutcome.failure("gateway only executes tool calls"), None)
        tool = self.registry.get(action.tool)
        if tool is None:
            return GatewayResult(None, ToolOutcome.failure(f"unknown tool {action.tool!r}"), None)
        try:
            args = tool.args_model.model_validate(action.arguments)
        except ValidationError as exc:
            problems = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors())
            return GatewayResult(tool, ToolOutcome.failure(f"invalid arguments: {problems}"), None)

        ctx = ToolContext(state=self.state, step_id=step_id, timestamp=timestamp)
        sink = tool.sink(args, ctx)
        outcome = tool.run(args, ctx)
        if outcome.succeeded:
            self._attach_untrusted_fields(tool, outcome, ctx)
            for name, details in outcome.effects:
                self.state.record_effect(step_id, name, tool.name, details)
        else:
            sink = None
        return GatewayResult(tool, outcome, sink)

    def _attach_untrusted_fields(self, tool: Tool, outcome: ToolOutcome, ctx: ToolContext) -> None:
        for field_name, origin in tool.untrusted_text_fields.items():
            override = self.state.tool_output_overrides.get((tool.name, field_name))
            if override is not None:
                outcome.result[field_name] = override
            if field_name in outcome.result:
                outcome.provenance.append(tool_field_provenance(tool.name, field_name, origin, ctx))
