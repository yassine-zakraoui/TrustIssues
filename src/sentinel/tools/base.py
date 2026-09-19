"""Tool abstraction for the simulator. Tools only ever read or write synthetic WorldState."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from sentinel.core.actions import ArgValue
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.core.state import WorldState

# Capabilities a tool may declare. "network" is intentionally absent: the official
# benchmark never exposes tools that reach real networks.
ALLOWED_CAPABILITIES = frozenset({"read", "write", "draft", "message", "state_change"})


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=False)


@dataclass(frozen=True)
class Sink:
    """A place where text leaves the agent (for data-flow checks)."""

    name: str
    destination: TrustLevel
    text: str


@dataclass(frozen=True)
class ToolContext:
    state: WorldState
    step_id: int
    timestamp: datetime


@dataclass
class ToolOutcome:
    result: dict[str, Any] = field(default_factory=dict)
    provenance: list[Provenance] = field(default_factory=list)
    effects: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None

    @classmethod
    def failure(cls, message: str) -> ToolOutcome:
        return cls(result={"error": message}, error=message)


class Tool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    args_model: ClassVar[type[ToolArgs]]
    consequential: ClassVar[bool] = False
    capabilities: ClassVar[frozenset[str]] = frozenset({"read"})
    # Result fields that carry text from outside the organization, with their origin actor.
    untrusted_text_fields: ClassVar[dict[str, str]] = {}

    def is_consequential(self, arguments: dict[str, ArgValue]) -> bool:
        return self.consequential

    def sink(self, args: ToolArgs, ctx: ToolContext) -> Sink | None:
        return None

    @abstractmethod
    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome: ...

    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "consequential": self.consequential,
            "capabilities": sorted(self.capabilities),
            "parameters": self.args_model.model_json_schema(),
        }


# ---- helpers shared by domain tools -----------------------------------------------------------

_TOKEN = re.compile(r"[a-z0-9]+")


def tokens(text: str) -> set[str]:
    return {tok for tok in _TOKEN.findall(text.lower()) if len(tok) > 1}


def search_records(
    state: WorldState, collection: str, query: str, fields: tuple[str, ...], limit: int
) -> list[dict[str, Any]]:
    wanted = tokens(query)
    if not wanted:
        return []
    matches = []
    for record in state.collections.get(collection, {}).values():
        haystack = tokens(" ".join(str(record.get(name, "")) for name in fields))
        if wanted <= haystack:
            matches.append(record)
    return sorted(matches, key=lambda r: str(r["id"]))[:limit]


def record_outcome(
    state: WorldState,
    ctx: ToolContext,
    tool_name: str,
    collection: str,
    records: list[dict[str, Any]],
    result: dict[str, Any],
) -> ToolOutcome:
    provenance = [state.provenance_for(collection, str(record["id"]), tool_name, ctx.timestamp) for record in records]
    return ToolOutcome(result=result, provenance=provenance)


def tool_field_provenance(tool_name: str, field_name: str, origin: str, ctx: ToolContext) -> Provenance:
    return Provenance(
        source_type=SourceType.TOOL_OUTPUT,
        source_id=f"{tool_name}.{field_name}",
        trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
        origin_actor=origin,
        retrieved_via=tool_name,
        sensitivity=Sensitivity.INTERNAL,
        timestamp=ctx.timestamp,
    )


def recipient_trust(state: WorldState, address: str) -> TrustLevel:
    domain = address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""
    internal = str(state.settings.get("internal_email_domain", "")).lower()
    if internal and domain == internal:
        return TrustLevel.TRUSTED_INTERNAL
    return TrustLevel.UNTRUSTED_EXTERNAL
