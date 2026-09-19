"""Tool registry. Refuses tools with capabilities outside the offline allow-list."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from sentinel.tools.base import ALLOWED_CAPABILITIES, Tool


class ToolRegistryError(ValueError):
    pass


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ToolRegistryError(f"duplicate tool {tool.name!r}")
        extra = set(tool.capabilities) - ALLOWED_CAPABILITIES
        if extra:
            raise ToolRegistryError(
                f"tool {tool.name!r} declares disallowed capabilities {sorted(extra)}; "
                "the official benchmark is offline and has no network tools"
            )
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def names(self) -> list[str]:
        return sorted(self._tools)

    def as_dict(self) -> dict[str, Tool]:
        return dict(self._tools)


def registry_for_domain(domain: str) -> ToolRegistry:
    from sentinel.domains import DOMAIN_TOOLS

    try:
        factory = DOMAIN_TOOLS[domain]
    except KeyError as exc:
        raise ToolRegistryError(f"unknown domain {domain!r}") from exc
    return ToolRegistry(factory())
