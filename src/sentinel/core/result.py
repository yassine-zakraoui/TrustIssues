"""Structured outcomes of a scenario run, consumed by metrics and scoring."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.core.actions import Decision


class GraderResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    condition: str
    passed: bool
    detail: str = ""


class DecisionRecord(BaseModel):
    """One defense decision, joined with evaluator-only ground truth (never sent to participants)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    step_id: int
    action_type: str
    tool: str | None
    decision: Decision
    risk_score: float
    confidence: float
    reason_codes: list[str] = Field(default_factory=list)
    legitimate: bool
    consequential: bool = False
    human_approved: bool | None = None
    latency_ms: float = 0.0
    defense_error: str | None = None


class ToolExecution(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    step_id: int
    tool: str
    succeeded: bool
    legitimate: bool
    violated: bool


class AttackMutationRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    step_id: int
    surface: str
    operation: str
    accepted: bool
    reason: str = ""
    chars: int = 0


class ScenarioOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    scenario_id: str
    scenario_version: int
    domain: str
    split: str
    seed: int
    defense: str
    attack_present: bool
    attack_family: str
    hard_negative: bool
    difficulty: int
    steps: int
    task_success: bool
    attack_success: bool
    critical_violation: bool
    data_flow_violation: bool
    grader_results: list[GraderResult] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    decisions: list[DecisionRecord] = Field(default_factory=list)
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    mutations: list[AttackMutationRecord] = Field(default_factory=list)
    termination: str = "completed"
