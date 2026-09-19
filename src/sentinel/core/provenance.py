"""Provenance metadata attached to every observation the agent sees."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class TrustLevel(StrEnum):
    """Ordered from most to least trusted."""

    SYSTEM_POLICY = "system_policy"
    AUTHENTICATED_USER = "authenticated_user"
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_INTERNAL = "untrusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    ADVERSARY_CONTROLLED = "adversary_controlled"

    @property
    def rank(self) -> int:
        """0 is most trusted; higher is less trusted."""
        return list(TrustLevel).index(self)

    @property
    def is_trusted(self) -> bool:
        return self.rank <= TrustLevel.TRUSTED_INTERNAL.rank


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return list(Sensitivity).index(self)


class SourceType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    EMAIL = "email"
    DOCUMENT = "document"
    WIKI = "wiki"
    TICKET = "ticket"
    CUSTOMER_RECORD = "customer_record"
    ACCOUNT = "account"
    CASE_DOCUMENT = "case_document"
    POLICY = "policy"
    PAYMENT = "payment"
    ALERT = "alert"
    LOG = "log"
    ASSET = "asset"
    INTEL = "intel"
    INCIDENT = "incident"
    REMEDIATION = "remediation"
    MEMORY = "memory"
    TOOL_OUTPUT = "tool_output"


class Provenance(BaseModel):
    """Where a piece of content came from and how much it can be trusted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: SourceType
    source_id: str = Field(min_length=1, max_length=128)
    trust_level: TrustLevel
    origin_actor: str = Field(min_length=1, max_length=128)
    retrieved_via: str = Field(min_length=1, max_length=64)
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    timestamp: datetime
    parent_event_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


def least_trusted(levels: list[TrustLevel]) -> TrustLevel:
    """Return the least trusted level; an empty list is treated as authenticated user input."""
    if not levels:
        return TrustLevel.AUTHENTICATED_USER
    return max(levels, key=lambda level: level.rank)


def most_sensitive(levels: list[Sensitivity]) -> Sensitivity:
    if not levels:
        return Sensitivity.PUBLIC
    return max(levels, key=lambda level: level.rank)
