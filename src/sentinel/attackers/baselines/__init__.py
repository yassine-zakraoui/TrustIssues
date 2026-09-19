"""Safe baseline attackers."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.attackers.baselines.mutation import MutationAttacker
from sentinel.attackers.baselines.static import StaticAttacker
from sentinel.attackers.interface import Attacker

ATTACKERS: dict[str, Callable[[], Attacker]] = {
    "static": StaticAttacker,
    "mutation": MutationAttacker,
}


def get_attacker(name: str) -> Attacker:
    if name not in ATTACKERS:
        raise KeyError(f"unknown attacker {name!r}; choose from {', '.join(sorted(ATTACKERS))}")
    return ATTACKERS[name]()
