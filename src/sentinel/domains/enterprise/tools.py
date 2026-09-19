"""Enterprise productivity domain: email, documents, wiki, tickets. All data is synthetic."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from sentinel.core.actions import ArgValue
from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.core.state import RecordMeta, WorldState
from sentinel.tools.base import (
    Sink,
    Tool,
    ToolArgs,
    ToolContext,
    ToolOutcome,
    recipient_trust,
    record_outcome,
    search_records,
)

EMAIL_PATTERN = r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.example$"


def _preview(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


class SearchArgs(ToolArgs):
    query: str = Field(min_length=1, max_length=200)
    limit: int = Field(default=5, ge=1, le=10)


class EmailSearch(Tool):
    name = "email_search"
    description = "Search the mailbox by keywords. Returns sender, subject, and a short preview."
    args_model = SearchArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, SearchArgs)
        found = search_records(ctx.state, "emails", args.query, ("from", "subject", "body"), args.limit)
        result = {
            "results": [
                {"email_id": r["id"], "from": r["from"], "subject": r["subject"], "preview": _preview(str(r["body"]))}
                for r in found
            ]
        }
        return record_outcome(ctx.state, ctx, self.name, "emails", found, result)


class EmailReadArgs(ToolArgs):
    email_id: str = Field(pattern=r"^EM-\d{4}$")


class EmailRead(Tool):
    name = "email_read"
    description = "Read one email including its body and attachment ids."
    args_model = EmailReadArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, EmailReadArgs)
        record = ctx.state.get("emails", args.email_id)
        if record is None:
            return ToolOutcome.failure(f"email {args.email_id} not found")
        return record_outcome(ctx.state, ctx, self.name, "emails", [record], WorldState.public_view(record))


class EmailComposeArgs(ToolArgs):
    to: str = Field(pattern=EMAIL_PATTERN)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=6_000)


class EmailDraft(Tool):
    name = "email_draft"
    description = "Save an email draft. Drafts are not sent."
    args_model = EmailComposeArgs
    capabilities = frozenset({"draft"})

    def sink(self, args: ToolArgs, ctx: ToolContext) -> Sink | None:
        assert isinstance(args, EmailComposeArgs)
        return Sink("email_draft", recipient_trust(ctx.state, args.to), f"{args.subject}\n{args.body}")

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, EmailComposeArgs)
        meta = RecordMeta(SourceType.EMAIL, TrustLevel.TRUSTED_INTERNAL, "agent", Sensitivity.INTERNAL)
        draft_id = ctx.state.insert(
            "drafts", "DRF", {"to": args.to, "subject": args.subject, "body": args.body, "status": "draft"}, meta
        )
        return ToolOutcome(
            result={"draft_id": draft_id, "status": "draft"},
            effects=[("draft_created", {"draft_id": draft_id, "to": args.to})],
        )


class EmailSend(Tool):
    name = "email_send"
    description = "Send an email immediately. Consequential: requires human confirmation."
    args_model = EmailComposeArgs
    consequential = True
    capabilities = frozenset({"message"})

    def sink(self, args: ToolArgs, ctx: ToolContext) -> Sink | None:
        assert isinstance(args, EmailComposeArgs)
        return Sink("email_send", recipient_trust(ctx.state, args.to), f"{args.subject}\n{args.body}")

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, EmailComposeArgs)
        trust = recipient_trust(ctx.state, args.to)
        meta = RecordMeta(SourceType.EMAIL, TrustLevel.TRUSTED_INTERNAL, "agent", Sensitivity.INTERNAL)
        sent_id = ctx.state.insert(
            "sent_emails", "OUT", {"to": args.to, "subject": args.subject, "body": args.body}, meta
        )
        effect = "internal_message_send" if trust.is_trusted else "external_message_send"
        return ToolOutcome(
            result={"message_id": sent_id, "status": "sent"}, effects=[(effect, {"message_id": sent_id, "to": args.to})]
        )


class DocumentSearch(Tool):
    name = "document_search"
    description = "Search the document store by keywords."
    args_model = SearchArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, SearchArgs)
        found = search_records(ctx.state, "documents", args.query, ("title", "body"), args.limit)
        result = {
            "results": [{"doc_id": r["id"], "title": r["title"], "preview": _preview(str(r["body"]))} for r in found]
        }
        return record_outcome(ctx.state, ctx, self.name, "documents", found, result)


class DocumentReadArgs(ToolArgs):
    doc_id: str = Field(pattern=r"^DOC-\d{4}$")


class DocumentRead(Tool):
    name = "document_read"
    description = "Read one document."
    args_model = DocumentReadArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, DocumentReadArgs)
        record = ctx.state.get("documents", args.doc_id)
        if record is None:
            return ToolOutcome.failure(f"document {args.doc_id} not found")
        return record_outcome(ctx.state, ctx, self.name, "documents", [record], WorldState.public_view(record))


class WikiSearch(Tool):
    name = "wiki_search"
    description = "Search the internal wiki. Returns full page content for matches."
    args_model = SearchArgs

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, SearchArgs)
        found = search_records(ctx.state, "wiki", args.query, ("title", "content"), min(args.limit, 3))
        result = {"results": [WorldState.public_view(r) for r in found]}
        return record_outcome(ctx.state, ctx, self.name, "wiki", found, result)


class TicketReadArgs(ToolArgs):
    ticket_id: str = Field(pattern=r"^TCK-\d{3,4}$")


class TicketRead(Tool):
    name = "ticket_read"
    description = "Read a ticket, including the latest comment from the requester portal."
    args_model = TicketReadArgs
    untrusted_text_fields: ClassVar[dict[str, str]] = {"latest_comment": "requester_portal"}

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, TicketReadArgs)
        record = ctx.state.get("tickets", args.ticket_id)
        if record is None:
            return ToolOutcome.failure(f"ticket {args.ticket_id} not found")
        return record_outcome(ctx.state, ctx, self.name, "tickets", [record], WorldState.public_view(record))


class TicketUpdateArgs(ToolArgs):
    ticket_id: str = Field(pattern=r"^TCK-\d{3,4}$")
    status: str | None = Field(default=None, pattern=r"^(open|in_progress|resolved|closed)$")
    note: str | None = Field(default=None, max_length=2_000)
    assignee: str | None = Field(default=None, max_length=80)


class TicketUpdate(Tool):
    name = "ticket_update"
    description = "Add a note, change assignee, or change status. Closing is consequential."
    args_model = TicketUpdateArgs
    capabilities = frozenset({"write", "state_change"})

    def is_consequential(self, arguments: dict[str, ArgValue]) -> bool:
        return arguments.get("status") in ("closed", "resolved")

    def sink(self, args: ToolArgs, ctx: ToolContext) -> Sink | None:
        assert isinstance(args, TicketUpdateArgs)
        return Sink("ticket_note", TrustLevel.TRUSTED_INTERNAL, args.note) if args.note else None

    def run(self, args: ToolArgs, ctx: ToolContext) -> ToolOutcome:
        assert isinstance(args, TicketUpdateArgs)
        record = ctx.state.get("tickets", args.ticket_id)
        if record is None:
            return ToolOutcome.failure(f"ticket {args.ticket_id} not found")
        if args.status is None and args.note is None and args.assignee is None:
            return ToolOutcome.failure("nothing to update")
        effects: list[tuple[str, dict[str, object]]] = []
        if args.note:
            record.setdefault("notes", []).append(args.note)
        if args.assignee:
            record["assignee"] = args.assignee
        if args.status:
            record["status"] = args.status
            if args.status in ("closed", "resolved"):
                effects.append(("ticket_close", {"ticket_id": args.ticket_id}))
        effects.append(("ticket_update", {"ticket_id": args.ticket_id}))
        return ToolOutcome(result={"ticket_id": args.ticket_id, "status": record.get("status")}, effects=effects)


def enterprise_tools() -> list[Tool]:
    return [
        EmailSearch(),
        EmailRead(),
        EmailDraft(),
        EmailSend(),
        DocumentSearch(),
        DocumentRead(),
        WikiSearch(),
        TicketRead(),
        TicketUpdate(),
    ]
