"""Semantic scenario validation that needs fixtures, policies, and domain tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sentinel.core.policies import load_policy
from sentinel.core.scenario import (
    CustomCondition,
    Scenario,
    ScenarioError,
    Split,
    SurfaceKind,
    load_scenario,
)
from sentinel.core.state import StateError, WorldState
from sentinel.evaluator.task_graders import custom_grader_names
from sentinel.tools.registry import ToolRegistryError, registry_for_domain


@dataclass
class CheckReport:
    path: str
    scenario_id: str | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def check_scenario(scenario: Scenario, root: Path, path: Path | None = None) -> list[str]:
    problems: list[str] = []
    try:
        policy = load_policy(root, scenario.policy_profile)
        if policy.domain != scenario.domain.value:
            problems.append(f"policy_profile {scenario.policy_profile!r} is for domain {policy.domain!r}")
    except ScenarioError as exc:
        problems.extend(exc.problems)
    try:
        registry = registry_for_domain(scenario.domain.value)
    except ToolRegistryError as exc:
        return [*problems, str(exc)]
    for tool_name in scenario.allowed_tools:
        if tool_name not in registry:
            problems.append(
                f"allowed_tools: {tool_name!r} is not a {scenario.domain} tool (known: {', '.join(registry.names())})"
            )
    try:
        state = WorldState.from_scenario(scenario, root)
    except (StateError, KeyError, ValueError) as exc:
        return [*problems, f"fixture: {exc}"]
    for surface in scenario.attack.surfaces:
        first, second, field_name = surface.target.split("/")
        if surface.kind is SurfaceKind.TOOL_OUTPUT:
            tool = registry.get(second)
            if tool is None:
                problems.append(f"surface {surface.id!r}: unknown tool {second!r}")
            elif field_name not in tool.untrusted_text_fields:
                problems.append(
                    f"surface {surface.id!r}: {second}.{field_name} is not an untrusted "
                    f"text field (allowed: {sorted(tool.untrusted_text_fields)})"
                )
        elif surface.kind is not SurfaceKind.MEMORY:
            record = state.get(first, second)
            if record is None:
                problems.append(f"surface {surface.id!r}: record {first}/{second} not in fixture")
            elif not isinstance(record.get(field_name), str):
                problems.append(f"surface {surface.id!r}: {surface.target} is not a text field")
    for condition in scenario.success_conditions:
        if isinstance(condition, CustomCondition) and condition.grader not in custom_grader_names():
            problems.append(f"success_conditions: unknown custom grader {condition.grader!r}")
    if path is not None:
        parts = set(path.resolve().parts)
        if scenario.split is Split.PUBLIC and "validation" in parts:
            problems.append("public scenarios must not live under a validation directory")
        if scenario.split is Split.VALIDATION and "public" in parts:
            problems.append("validation scenarios must not live under a public directory")
    return problems


def check_path(path: Path, root: Path) -> CheckReport:
    report = CheckReport(path=str(path))
    try:
        scenario = load_scenario(path)
    except ScenarioError as exc:
        report.problems.extend(exc.problems)
        return report
    report.scenario_id = scenario.id
    report.problems.extend(check_scenario(scenario, root, path))
    return report
