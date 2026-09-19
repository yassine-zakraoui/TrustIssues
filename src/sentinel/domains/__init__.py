"""Synthetic domains. Each exposes a factory returning its tools."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.domains.enterprise.tools import enterprise_tools
from sentinel.domains.finance.tools import finance_tools
from sentinel.domains.soc.tools import soc_tools
from sentinel.tools.base import Tool

DOMAIN_TOOLS: dict[str, Callable[[], list[Tool]]] = {
    "enterprise": enterprise_tools,
    "finance": finance_tools,
    "soc": soc_tools,
}
