from sentinel.core.policies import Leak, PolicyEngine, Severity, load_policy
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.core.scenario import SecurityProperty
from sentinel.core.state import Effect
from sentinel.tools.registry import registry_for_domain
from tests.conftest import ROOT, load, tool_call


def engine(scenario_id: str) -> PolicyEngine:
    scenario = load(scenario_id)
    return PolicyEngine(load_policy(ROOT, scenario.policy_profile), scenario)


def test_policies_load_for_all_domains() -> None:
    for profile in ("enterprise_standard", "finance_standard", "soc_standard"):
        assert load_policy(ROOT, profile).rules


def test_tool_permission_severity_depends_on_consequence() -> None:
    eng = engine("finance_false_approval")
    tools = registry_for_domain("finance")
    execute = tools.get("payment_execute")
    lookup = tools.get("account_summary")
    assert execute is not None and lookup is not None
    critical = eng.check_attempt(tool_call("payment_execute", payment_id="PAY-0001"), execute, 3)
    high = eng.check_attempt(tool_call("account_summary", account_id="ACC-1001"), lookup, 4)
    assert {f.rule_id: f.severity for f in critical}["TOOL_PERMISSION"] is Severity.CRITICAL
    assert critical[0].security_property is SecurityProperty.NO_UNAUTHORIZED_TOOL
    assert any(f.rule_id == "PAYMENT_EXECUTE_SEQUENCE" for f in critical)
    assert high[0].severity is Severity.HIGH


def test_confirmation_rule_only_fires_without_confirmation() -> None:
    eng = engine("finance_refund_confirmed")
    confirm = registry_for_domain("finance").get("payment_confirm")
    assert confirm is not None
    action = tool_call("payment_confirm", payment_id="PAY-0001")
    assert eng.check_executed(action, confirm, confirmed=True, step=2) == []
    findings = eng.check_executed(action, confirm, confirmed=False, step=2)
    assert [f.rule_id for f in findings] == ["PAYMENT_CONFIRMATION"]


def test_forbidden_effects_and_leaks() -> None:
    eng = engine("finance_false_approval")
    effects = [Effect(1, "payment_prepare", "payment_prepare", {}), Effect(2, "payment_execute", "payment_execute", {})]
    assert [f.message for f in eng.check_effects(effects)] == [
        "forbidden effect 'payment_execute' caused by 'payment_execute'"
    ]
    leaks = [
        Leak("iban", Sensitivity.CONFIDENTIAL, "email", TrustLevel.UNTRUSTED_EXTERNAL, "plain"),
        Leak("note", Sensitivity.INTERNAL, "email", TrustLevel.UNTRUSTED_EXTERNAL, "base64"),
    ]
    severities = [f.severity for f in eng.check_leaks(leaks, 3)]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM]


def test_defense_context_contains_no_ground_truth() -> None:
    eng = engine("finance_false_approval")
    context = eng.defense_context(registry_for_domain("finance").as_dict())
    assert set(context) == {
        "policy_id",
        "policy_version",
        "allowed_tools",
        "confirmation_required_tools",
        "consequential_tools",
        "rules",
    }
    assert "payment_confirm" in context["consequential_tools"]
    scenario = load("finance_false_approval")
    text = str(context)
    for payload in scenario.attack.payloads:
        assert payload.text not in text
    assert "APR-2231" not in text and scenario.turns[0].reference_plan[-1].content not in text
