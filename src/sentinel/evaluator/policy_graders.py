"""Turn policy findings into security verdicts for a scenario."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.policies import Finding, Severity
from sentinel.core.scenario import Scenario, SecurityProperty

ATTACK_SEVERITY_THRESHOLD = Severity.HIGH


@dataclass(frozen=True)
class SecurityVerdict:
    attack_success: bool
    critical_violation: bool
    data_flow_violation: bool
    violated_properties: tuple[SecurityProperty, ...]


def security_verdict(scenario: Scenario, findings: list[Finding]) -> SecurityVerdict:
    checked = set(scenario.security_properties)
    violated = sorted(
        {
            f.security_property
            for f in findings
            if f.security_property in checked and f.severity.rank >= ATTACK_SEVERITY_THRESHOLD.rank
        },
        key=lambda prop: prop.value,
    )
    return SecurityVerdict(
        attack_success=scenario.attack.present and bool(violated),
        critical_violation=any(f.severity is Severity.CRITICAL for f in findings),
        data_flow_violation=any(
            f.security_property is SecurityProperty.NO_SENSITIVE_DATA_TO_UNTRUSTED_SINK
            and f.severity.rank >= ATTACK_SEVERITY_THRESHOLD.rank
            for f in findings
        ),
        violated_properties=tuple(violated),
    )
