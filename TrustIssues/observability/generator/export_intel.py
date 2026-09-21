"""Capture the real value-flow internals of every TrustIssues v2 decision.

Wraps decide() without altering it: the wrapper calls the original first, then
recomputes the same intermediates for display. Decisions are therefore
untouched -- the digest must still match the baseline run.
"""
import json
import sys

from sentinel.core.actions import ActionType
from sentinel.core.provenance import Sensitivity
from sentinel.defenses.baselines import TrustIssues_defense_v2 as M
from sentinel.defenses.baselines.common import (
    OUTBOUND_TOOLS,
    is_confirmed,
    is_consequential,
    is_external_recipient,
    target_action,
    texts_by_trust,
)

OUT = sys.argv[1]
CAPTURED = []
_orig = M.TrustIssuesDefense.decide


def patched(self, request):
    result = _orig(self, request)
    action = target_action(request)
    rec = {
        "step": request.step_id,
        "tool": action.tool,
        "type": action.type.value if hasattr(action.type, "value") else str(action.type),
        "decision": str(result.decision).split(".")[-1].lower(),
        "codes": list(result.reason_codes),
        "risk": result.risk_score,
    }
    if action.type is ActionType.TOOL_CALL:
        untrusted, sensitive = texts_by_trust(request)
        atext = M._action_text(action)
        argv = M._values(atext)
        trustedv = M._values(M._trusted_text(request))
        observed = M._values(" ".join(untrusted)) | M._values(" ".join(sensitive))
        sensv = M._values(" ".join(sensitive))
        restv = M._values(" ".join(M._texts_at_least(request, Sensitivity.RESTRICTED)))
        unc = argv - trustedv
        opaque = {v for v in unc if M._is_opaque(v)}
        rec.update(
            {
                "args": {k: (v if isinstance(v, str) else str(v))[:400]
                         for k, v in (getattr(action, "arguments", None) or {}).items()},
                "atext": atext,
                "argv": sorted(argv),
                "n_arg_values": len(argv),
                "uncorroborated": sorted(unc)[:12],
                "opaque": sorted(opaque),
                "restricted_hit": sorted(opaque & restv),
                "contaminated": sorted(unc & observed & sensv)[:8],
                "readonly": M.is_read_only_tool(action.tool),
                "consequential": is_consequential(request, action),
                "confirmed": is_confirmed(request, action),
                "outbound": action.tool in OUTBOUND_TOOLS,
                "external_recipient": (
                    is_external_recipient(request, action)
                    if action.tool in OUTBOUND_TOOLS else None
                ),
            }
        )
    CAPTURED.append(rec)
    return result


M.TrustIssuesDefense.decide = patched

# Tag each captured decision with the scenario it belongs to.
from sentinel.evaluator import runner as _runner  # noqa: E402

_orig_run = _runner.run_scenario


def run_tagged(scenario, *a, **kw):
    start = len(CAPTURED)
    out = _orig_run(scenario, *a, **kw)
    sid = getattr(scenario, "id", None) or getattr(scenario, "scenario_id", None)
    for rec in CAPTURED[start:]:
        rec["scenario"] = sid
    return out


_runner.run_scenario = run_tagged

from sentinel.cli import app  # noqa: E402

sys.argv = ["sentinel", "eval", "public", "--defense", "trustissues_v2"]
try:
    app()
except SystemExit:
    pass

json.dump(CAPTURED, open(OUT, "w", encoding="utf-8"), indent=0)
print(f"\ncaptured {len(CAPTURED)} decisions -> {OUT}", file=sys.stderr)
