from datetime import UTC, datetime

import pytest

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import TrustLevel
from sentinel.domains import DOMAIN_TOOLS
from sentinel.tools.base import ALLOWED_CAPABILITIES, Tool, ToolArgs, ToolContext, ToolOutcome
from sentinel.tools.gateway import ToolGateway
from sentinel.tools.registry import ToolRegistry, ToolRegistryError, registry_for_domain
from tests.conftest import state_for, tool_call

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def gateway(scenario_id: str) -> ToolGateway:
    state = state_for(scenario_id)
    return ToolGateway(registry_for_domain(state.domain), state)


def run(gw: ToolGateway, action: CandidateAction, step: int = 1):  # type: ignore[no-untyped-def]
    return gw.execute(action, step, NOW)


def test_domain_tool_sets() -> None:
    assert set(registry_for_domain("enterprise").names()) == {
        "email_search",
        "email_read",
        "email_draft",
        "email_send",
        "document_search",
        "document_read",
        "wiki_search",
        "ticket_read",
        "ticket_update",
    }
    assert set(registry_for_domain("finance").names()) == {
        "customer_lookup",
        "account_summary",
        "case_document_read",
        "case_note_create",
        "policy_search",
        "payment_prepare",
        "payment_confirm",
        "payment_execute",
    }
    assert set(registry_for_domain("soc").names()) == {
        "alert_search",
        "alert_read",
        "asset_lookup",
        "intel_search",
        "incident_create",
        "incident_update",
        "remediation_prepare",
        "remediation_execute",
    }


def test_email_send_marks_external_effect_and_sink() -> None:
    gw = gateway("enterprise_security_digest")
    external = run(gw, tool_call("email_send", to="x@partner.example", subject="s", body="b"))
    internal = run(gw, tool_call("email_send", to="leila.mansour@atlas.example", subject="s", body="b"))
    assert external.sink is not None and external.sink.destination is TrustLevel.UNTRUSTED_EXTERNAL
    assert internal.sink is not None and internal.sink.destination is TrustLevel.TRUSTED_INTERNAL
    assert [e.name for e in gw.state.effects] == ["external_message_send", "internal_message_send"]


def test_ticket_update_close_is_consequential() -> None:
    tool = registry_for_domain("enterprise").get("ticket_update")
    assert tool is not None
    assert tool.is_consequential({"ticket_id": "TCK-501", "status": "closed"})
    assert not tool.is_consequential({"ticket_id": "TCK-501", "note": "hi"})


def test_payment_lifecycle_prepare_confirm_execute() -> None:
    gw = gateway("finance_refund_confirmed")
    execute = tool_call("payment_execute", payment_id="PAY-0001")
    assert not run(gw, execute).outcome.succeeded  # nothing prepared
    prepared = run(
        gw, tool_call("payment_prepare", account_id="ACC-1001", beneficiary_id="BEN-01", amount=1250, reference="r")
    )
    assert prepared.outcome.result == {"payment_id": "PAY-0001", "status": "prepared"}
    failed = run(gw, execute)
    assert not failed.outcome.succeeded and "requires 'confirmed'" in (failed.outcome.error or "")
    assert run(gw, tool_call("payment_confirm", payment_id="PAY-0001")).outcome.succeeded
    assert not run(gw, tool_call("payment_confirm", payment_id="PAY-0001")).outcome.succeeded
    assert run(gw, execute).outcome.succeeded
    assert gw.state.get("payments", "PAY-0001")["status"] == "executed"  # type: ignore[index]
    assert [e.name for e in gw.state.effects] == ["payment_prepare", "payment_confirm", "payment_execute"]


def test_payment_prepare_validates_references() -> None:
    gw = gateway("finance_refund_confirmed")
    bad = run(gw, tool_call("payment_prepare", account_id="ACC-9999", beneficiary_id="BEN-01", amount=1, reference="r"))
    assert not bad.outcome.succeeded
    negative = run(
        gw, tool_call("payment_prepare", account_id="ACC-1001", beneficiary_id="BEN-01", amount=-5, reference="r")
    )
    assert "invalid arguments" in (negative.outcome.error or "")


def test_soc_remediation_only_changes_simulator_state() -> None:
    gw = gateway("soc_confirmed_isolation")
    rem = run(gw, tool_call("remediation_prepare", asset_id="SRV-22", action="disable_monitoring"))
    assert rem.outcome.result["remediation_id"] == "REM-0001"
    assert run(gw, tool_call("remediation_execute", remediation_id="REM-0001")).outcome.succeeded
    assert gw.state.get("assets", "SRV-22")["monitoring_enabled"] is False  # type: ignore[index]
    assert {e.name for e in gw.state.effects} >= {"remediation_execute", "monitoring_disable"}


def test_incident_close_effect() -> None:
    gw = gateway("soc_direct_monitoring_off")
    result = run(gw, tool_call("incident_update", incident_id="INC-0101", status="closed"))
    assert result.outcome.succeeded and gw.state.has_effect("incident_close")


def test_gateway_rejects_unknown_tool_and_bad_args() -> None:
    gw = gateway("enterprise_project_status")
    assert "unknown tool" in (run(gw, tool_call("shell_exec", cmd="ls")).outcome.error or "")
    assert "invalid arguments" in (run(gw, tool_call("email_read", email_id="../../etc")).outcome.error or "")
    assert "invalid arguments" in (run(gw, tool_call("email_read", email_id="EM-2001", extra=1)).outcome.error or "")


def test_search_and_provenance() -> None:
    gw = gateway("soc_intel_correlation")
    result = run(gw, tool_call("intel_search", query="cdn-update-check.example"))
    ids = [r["id"] for r in result.outcome.result["results"]]
    assert ids == ["TI-01", "TI-02"]
    trust = {p.source_id: p.trust_level for p in result.outcome.provenance}
    assert trust == {"TI-01": TrustLevel.TRUSTED_INTERNAL, "TI-02": TrustLevel.UNTRUSTED_EXTERNAL}


def test_tool_output_override_and_untrusted_field_provenance() -> None:
    gw = gateway("enterprise_val_ticket_comment")
    gw.state.tool_output_overrides[("ticket_read", "latest_comment")] = "injected text"
    result = run(gw, tool_call("ticket_read", ticket_id="TCK-501"))
    assert result.outcome.result["latest_comment"] == "injected text"
    assert any(
        p.source_id == "ticket_read.latest_comment" and p.trust_level is TrustLevel.UNTRUSTED_EXTERNAL
        for p in result.outcome.provenance
    )


def test_registry_refuses_network_capability() -> None:
    class Fetch(Tool):
        name = "http_fetch"
        description = "not allowed"
        args_model = ToolArgs
        capabilities = frozenset({"network"})

        def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
            raise AssertionError

    with pytest.raises(ToolRegistryError, match="disallowed capabilities"):
        ToolRegistry([Fetch()])
    for factory in DOMAIN_TOOLS.values():
        for tool in factory():
            assert tool.capabilities <= ALLOWED_CAPABILITIES
