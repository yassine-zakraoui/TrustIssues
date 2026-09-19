"""Template rendering for reference plans: ``{{step_id.path.to.field}}``."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from sentinel.core.actions import ArgValue

TEMPLATE = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)((?:\.[A-Za-z0-9_]+)*)\s*(?:\|\s*(base64|hex|reverse)\s*)?\}\}")


class MissingValue(LookupError):
    pass


def lookup(results: dict[str, Any], name: str, path: str) -> Any:
    if name not in results:
        raise MissingValue(name)
    value: Any = results[name]
    for part in [p for p in path.split(".") if p]:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise MissingValue(f"{name}{path}")
    return value


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def apply_filter(text: str, name: str | None) -> str:
    """Text transforms a (simulated) model can be instructed to apply."""
    if name == "base64":
        return base64.b64encode(text.encode()).decode()
    if name == "hex":
        return text.encode().hex()
    if name == "reverse":
        return text[::-1]
    return text


def render_text(template: str, results: dict[str, Any], missing: str = "") -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            value = _stringify(lookup(results, match.group(1), match.group(2)))
            return apply_filter(value, match.group(3))
        except MissingValue:
            return missing

    return TEMPLATE.sub(replace, template)


def is_templated(value: ArgValue) -> bool:
    return isinstance(value, str) and bool(TEMPLATE.search(value))


def render_args(args: dict[str, ArgValue], results: dict[str, Any]) -> dict[str, ArgValue]:
    rendered: dict[str, ArgValue] = {}
    for key, value in args.items():
        if isinstance(value, str):
            whole = TEMPLATE.fullmatch(value.strip())
            if whole and whole.group(3) is None:
                try:
                    resolved = lookup(results, whole.group(1), whole.group(2))
                    rendered[key] = resolved if isinstance(resolved, str | int | float | bool) else _stringify(resolved)
                    continue
                except MissingValue:
                    rendered[key] = ""
                    continue
            rendered[key] = render_text(value, results)
        else:
            rendered[key] = value
    return rendered
