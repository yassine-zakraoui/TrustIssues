"""Seeded synthetic secrets (canaries) that are safe to leak and easy to detect."""

from __future__ import annotations

import re
import string
from collections.abc import Iterator
from dataclasses import dataclass, field

from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.core.scenario import CanarySpec, child_rng

PLACEHOLDER = re.compile(r"\{\{canary:([a-z][a-z0-9_]{1,47})\}\}")


@dataclass(frozen=True)
class Canary:
    name: str
    kind: str
    value: str
    sensitivity: Sensitivity
    allowed_destinations: frozenset[TrustLevel]

    def allowed_at(self, destination: TrustLevel) -> bool:
        return destination in self.allowed_destinations


def _generate_value(kind: str, seed: int, name: str) -> str:
    rng = child_rng(seed, "canary", name)
    upper_hex = "0123456789ABCDEF"
    alnum = string.ascii_letters + string.digits
    if kind == "secret_token":
        return "SENTINEL_SECRET_" + "".join(rng.choice(upper_hex) for _ in range(16))
    if kind == "account_id":
        return "SYNTN" + "".join(rng.choice(string.digits) for _ in range(18))
    if kind == "access_token":
        return "sntl_tok_" + "".join(rng.choice(alnum) for _ in range(24))
    if kind == "contract_ref":
        return "CTR-SYN-" + "".join(rng.choice(upper_hex) for _ in range(10))
    raise ValueError(f"unknown canary kind {kind!r}")


@dataclass
class CanaryRegistry:
    seed: int
    canaries: dict[str, Canary] = field(default_factory=dict)

    @classmethod
    def from_specs(cls, seed: int, specs: list[CanarySpec]) -> CanaryRegistry:
        registry = cls(seed=seed)
        for spec in specs:
            registry.canaries[spec.name] = Canary(
                name=spec.name,
                kind=spec.kind,
                value=_generate_value(spec.kind, seed, spec.name),
                sensitivity=spec.sensitivity,
                allowed_destinations=frozenset(spec.allowed_destinations),
            )
        return registry

    def substitute(self, text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in self.canaries:
                raise KeyError(f"fixture references undeclared canary {name!r}")
            return self.canaries[name].value

        return PLACEHOLDER.sub(replace, text)

    def __iter__(self) -> Iterator[Canary]:
        return iter(self.canaries.values())

    def __len__(self) -> int:
        return len(self.canaries)
