"""Financial-services sandbox. Every customer, account, and payment is fictional."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field

from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.core.state import RecordMeta, WorldState
from sentinel.tools.base import (
    Sink,
    Tool,
    ToolArgs,
    ToolContext,
    ToolOutcome,
    record_outcome,
    search_records,
)


class CustomerLookupArgs(ToolArgs):
    customer_id: str = Field(pattern=r"^CU-\d{4}$")


class CustomerLookup(Tool):
    name = "customer_lookup"
    description = "Look up a synthetic customer profile and their account ids."
    args_model = CustomerLookupArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, CustomerLookupArgs)
        customer = ctx.state.get("customers", args.customer_id)
        if customer is None:
            return ToolOutcome.failure(f"customer {args.customer_id} not found")
        accounts = ctx.state.find("accounts", {"customer_id": args.customer_id})
        result = WorldState.public_view(customer)
        result["accounts"] = [{"account_id": a["id"], "iban": a["iban"]} for a in accounts]
        outcome = record_outcome(ctx.state, ctx, self.name, "customers", [customer], result)
        outcome.provenance.extend(
            ctx.state.provenance_for("accounts", str(a["id"]), self.name, ctx.timestamp) for a in accounts
        )
        return outcome


class AccountSummaryArgs(ToolArgs):
    account_id: str = Field(pattern=r"^ACC-\d{4}$")


class AccountSummary(Tool):
    name = "account_summary"
    description = "Balance and recent transactions for one account, plus partner advisories."
    args_model = AccountSummaryArgs
    untrusted_text_fields: ClassVar[dict[str, str]] = {"advisory": "partner_risk_feed"}

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, AccountSummaryArgs)
        account = ctx.state.get("accounts", args.account_id)
        if account is None:
            return ToolOutcome.failure(f"account {args.account_id} not found")
        return record_outcome(ctx.state, ctx, self.name, "accounts", [account], WorldState.public_view(account))


class CaseDocumentReadArgs(ToolArgs):
    case_id: str = Field(pattern=r"^CASE-\d{4}$")
    doc_id: str = Field(pattern=r"^CD-\d{2,4}$")


class CaseDocumentRead(Tool):
    name = "case_document_read"
    description = "Read a document attached to a case file."
    args_model = CaseDocumentReadArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, CaseDocumentReadArgs)
        doc = ctx.state.get("case_documents", args.doc_id)
        if doc is None or doc.get("case_id") != args.case_id:
            return ToolOutcome.failure(f"document {args.doc_id} not found in {args.case_id}")
        return record_outcome(ctx.state, ctx, self.name, "case_documents", [doc], WorldState.public_view(doc))


class CaseNoteArgs(ToolArgs):
    case_id: str = Field(pattern=r"^CASE-\d{4}$")
    text: str = Field(min_length=1, max_length=4_000)


class CaseNoteCreate(Tool):
    name = "case_note_create"
    description = "Add an internal note to a case file."
    args_model = CaseNoteArgs
    capabilities = frozenset({"write"})

    def sink(self, args: ToolArgs, ctx: ToolContext) -> Sink | None:
        assert isinstance(args, CaseNoteArgs)
        return Sink("case_note", TrustLevel.TRUSTED_INTERNAL, args.text)

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, CaseNoteArgs)
        if ctx.state.get("cases", args.case_id) is None:
            return ToolOutcome.failure(f"case {args.case_id} not found")
        meta = RecordMeta(SourceType.CASE_DOCUMENT, TrustLevel.TRUSTED_INTERNAL, "agent", Sensitivity.CONFIDENTIAL)
        note_id = ctx.state.insert("case_notes", "NOTE", {"case_id": args.case_id, "text": args.text}, meta)
        return ToolOutcome(result={"note_id": note_id}, effects=[("case_note_create", {"case_id": args.case_id})])


class PolicySearchArgs(ToolArgs):
    query: str = Field(min_length=1, max_length=200)


class PolicySearch(Tool):
    name = "policy_search"
    description = "Search the bank's internal operating policies."
    args_model = PolicySearchArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, PolicySearchArgs)
        found = search_records(ctx.state, "policies", args.query, ("title", "text"), 3)
        return record_outcome(
            ctx.state, ctx, self.name, "policies", found, {"results": [WorldState.public_view(r) for r in found]}
        )


class PaymentPrepareArgs(ToolArgs):
    account_id: str = Field(pattern=r"^ACC-\d{4}$")
    beneficiary_id: str = Field(pattern=r"^BEN-\d{2,4}$")
    amount: float = Field(gt=0, le=1_000_000)
    reference: str = Field(min_length=1, max_length=140)


class PaymentPrepare(Tool):
    name = "payment_prepare"
    description = "Prepare a payment for review. Prepared payments do not move money."
    args_model = PaymentPrepareArgs
    capabilities = frozenset({"write"})

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, PaymentPrepareArgs)
        if ctx.state.get("accounts", args.account_id) is None:
            return ToolOutcome.failure(f"account {args.account_id} not found")
        if ctx.state.get("beneficiaries", args.beneficiary_id) is None:
            return ToolOutcome.failure(f"beneficiary {args.beneficiary_id} not found")
        meta = RecordMeta(SourceType.PAYMENT, TrustLevel.TRUSTED_INTERNAL, "agent", Sensitivity.CONFIDENTIAL)
        payment_id = ctx.state.insert(
            "payments",
            "PAY",
            {
                "account_id": args.account_id,
                "beneficiary_id": args.beneficiary_id,
                "amount": args.amount,
                "reference": args.reference,
                "status": "prepared",
            },
            meta,
        )
        return ToolOutcome(
            result={"payment_id": payment_id, "status": "prepared"},
            effects=[("payment_prepare", {"payment_id": payment_id})],
        )


class PaymentIdArgs(ToolArgs):
    payment_id: str = Field(pattern=r"^PAY-\d{4}$")


class _PaymentTransition(Tool):
    args_model = PaymentIdArgs
    consequential = True
    capabilities = frozenset({"state_change"})
    from_status: ClassVar[str]
    to_status: ClassVar[str]

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, PaymentIdArgs)
        payment: dict[str, Any] | None = ctx.state.get("payments", args.payment_id)
        if payment is None:
            return ToolOutcome.failure(f"payment {args.payment_id} not found")
        if payment["status"] != self.from_status:
            return ToolOutcome.failure(
                f"payment {args.payment_id} is {payment['status']!r}; {self.name} requires {self.from_status!r}"
            )
        payment["status"] = self.to_status
        return ToolOutcome(
            result={"payment_id": args.payment_id, "status": self.to_status},
            effects=[(self.name, {"payment_id": args.payment_id, "amount": payment["amount"]})],
        )


class PaymentConfirm(_PaymentTransition):
    name = "payment_confirm"
    description = "Record approval of a prepared payment. Consequential."
    from_status = "prepared"
    to_status = "confirmed"


class PaymentExecute(_PaymentTransition):
    name = "payment_execute"
    description = "Execute a confirmed payment in the simulator. Consequential."
    from_status = "confirmed"
    to_status = "executed"


def finance_tools() -> list[Tool]:
    return [
        CustomerLookup(),
        AccountSummary(),
        CaseDocumentRead(),
        CaseNoteCreate(),
        PolicySearch(),
        PaymentPrepare(),
        PaymentConfirm(),
        PaymentExecute(),
    ]
