"""Candidate actions proposed by the agent and decisions returned by defenses."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ArgValue = str | int | float | bool | None

MAX_ARG_CHARS = 8_000
MAX_CONTENT_CHARS = 16_000
MAX_METADATA_BYTES = 4_096
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"


class ActionType(StrEnum):
    RESPOND = "respond"
    TOOL_CALL = "tool_call"
    MEMORY_WRITE = "memory_write"
    REQUEST_CONFIRMATION = "request_confirmation"


class CandidateAction(BaseModel):
    """An action the agent wants to take. Nothing happens until a defense and the gateway agree."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: ActionType
    tool: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,63}$")
    arguments: dict[str, ArgValue] = Field(default_factory=dict)
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    final: bool = False
    confirmation_for: CandidateAction | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_arguments(cls, value: dict[str, ArgValue]) -> dict[str, ArgValue]:
        if len(value) > 32:
            raise ValueError("at most 32 arguments are allowed")
        for key, item in value.items():
            if not key.isidentifier() or len(key) > 64:
                raise ValueError(f"invalid argument name: {key!r}")
            if isinstance(item, str) and len(item) > MAX_ARG_CHARS:
                raise ValueError(f"argument {key!r} exceeds {MAX_ARG_CHARS} characters")
        return value

    @model_validator(mode="after")
    def _shape_matches_type(self) -> Self:
        if self.type is ActionType.TOOL_CALL:
            if self.tool is None:
                raise ValueError("tool_call actions require 'tool'")
            if self.content is not None or self.confirmation_for is not None:
                raise ValueError("tool_call actions take 'arguments' only")
        elif self.type in (ActionType.RESPOND, ActionType.MEMORY_WRITE):
            if self.content is None:
                raise ValueError(f"{self.type} actions require 'content'")
            if self.tool is not None or self.arguments or self.confirmation_for is not None:
                raise ValueError(f"{self.type} actions take 'content' only")
        elif self.type is ActionType.REQUEST_CONFIRMATION:
            target = self.confirmation_for
            if target is None or target.type is not ActionType.TOOL_CALL:
                raise ValueError("request_confirmation requires a tool_call in 'confirmation_for'")
            if self.tool is not None or self.arguments:
                raise ValueError("request_confirmation takes 'confirmation_for' and 'content' only")
        if self.final and self.type is not ActionType.RESPOND:
            raise ValueError("only respond actions can be final")
        return self

    def digest(self) -> str:
        """Stable identity used for confirmations and plan matching."""
        payload = {
            "type": self.type.value,
            "tool": self.tool,
            "arguments": {k: _canonical(v) for k, v in sorted(self.arguments.items())},
            "content": self.content if self.type is not ActionType.TOOL_CALL else None,
        }
        if self.confirmation_for is not None:
            payload["confirmation_for"] = self.confirmation_for.digest()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()[:24]

    def text_payload(self) -> str:
        """All free text carried by the action, for leak and taint checks."""
        parts: list[str] = []
        if self.content:
            parts.append(self.content)
        parts.extend(str(v) for v in self.arguments.values() if v is not None)
        if self.confirmation_for is not None:
            parts.append(self.confirmation_for.text_payload())
        return "\n".join(parts)


def _canonical(value: ArgValue) -> ArgValue:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"
    REWRITE = "rewrite"


class DefenseDecision(BaseModel):
    """What a defense returns for one candidate action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: list[str]) -> list[str]:
        import re

        for code in codes:
            if not re.fullmatch(REASON_CODE_PATTERN, code):
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(metadata))
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return metadata

    @model_validator(mode="after")
    def _rewrite_consistency(self) -> Self:
        if self.decision is Decision.REWRITE and self.rewritten_action is None:
            raise ValueError("rewrite decisions require 'rewritten_action'")
        if self.decision is not Decision.REWRITE and self.rewritten_action is not None:
            raise ValueError("'rewritten_action' is only valid with decision 'rewrite'")
        return self
