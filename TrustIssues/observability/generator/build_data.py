"""Join our captured internals with baseline counterfactuals and ablation outcomes."""
import glob
import io
import json
import os
import sys

SP = sys.argv[1]
ROOT = "artifacts/scorecards"
DEC = {"allow": "a", "block": "b", "escalate": "e", "rewrite": "r"}

# Scorecards are selected by deterministic digest, never by timestamp:
# ablation runs share the baseline's filename pattern.
BASELINES = {
    "allow_all": "a9aa03e1ebc66985",
    "keyword": "7ba9abae889ac9f0",
    "deny_sensitive": "5e6c1b09399e545d",
    "heuristic_risk": "8f8db315a2dd8741",
    "provenance": "7e9ab1696a87101c",
    "trustissues_v2": "563f184f2093fc14",
}
ABLATIONS = {
    "baseline": "563f184f2093fc14",
    "rule3_off": "c92563337587c585",
    "rule4_off": "563f184f2093fc14",
    "rules34_off": "68d2d00f14cdc505",
    "no_restricted_gate": "b5dd6a2285fb6c6a",
    "no_restricted_gate_and_rule4_off": "4dcc2155302c42fe",
    "keys_on": "26bf0a8227dc4563",
}

cards = {}
for p in glob.glob(os.path.join(ROOT, "*.json")):
    try:
        s = json.load(io.open(p, encoding="utf-8"))
    except Exception:
        continue
    if s.get("split") != "public" or s.get("scenario_count") != 40:
        continue
    cards[s.get("deterministic_digest", "")[:16]] = s


def need(dig, label):
    if dig not in cards:
        raise SystemExit(f"missing 40-scenario public scorecard for {label} ({dig})")
    return cards[dig]


# ---- our internals, keyed by scenario -------------------------------------
intel = json.load(io.open(os.path.join(SP, "intel.json"), encoding="utf-8"))
steps = {}
for r in intel:
    steps.setdefault(r.pop("scenario"), []).append(r)

# ---- counterfactual: every defense, step by step, plus what leaked --------
counter = {}
for name, dig in BASELINES.items():
    card = need(dig, name)
    for o in card["outcomes"]:
        sid = o["scenario_id"]
        entry = counter.setdefault(sid, {})
        entry[name] = {
            "seq": "".join(DEC.get(d["decision"], "?") for d in o["decisions"]),
            "tools": [d["tool"] or "respond" for d in o["decisions"]],
            "atk": bool(o.get("attack_success")),
            "crit": bool(o.get("critical_violation")),
            "dfv": bool(o.get("data_flow_violation")),
            "task": bool(o.get("task_success")),
            "leaks": [
                {
                    "step": f.get("step_id"),
                    "msg": f.get("message", "")[:220],
                    "rule": f.get("rule_id"),
                    "sev": f.get("severity"),
                }
                for f in (o.get("findings") or [])
                if f.get("severity") in ("critical", "high")
            ],
        }

# ---- ablations: which scenarios flip to attack-success --------------------
base_card = need(ABLATIONS["baseline"], "baseline")
base_atk = {o["scenario_id"]: bool(o.get("attack_success")) for o in base_card["outcomes"]}
base_fb = {}
for o in base_card["outcomes"]:
    n = sum(1 for d in o["decisions"] if d["decision"] != "allow" and d.get("legitimate"))
    base_fb[o["scenario_id"]] = n

ablation = {}
for name, dig in ABLATIONS.items():
    card = need(dig, name)
    m = card["metrics"]
    flips, fbr_delta = [], []
    for o in card["outcomes"]:
        sid = o["scenario_id"]
        if bool(o.get("attack_success")) and not base_atk.get(sid):
            flips.append(sid)
        n = sum(1 for d in o["decisions"] if d["decision"] != "allow" and d.get("legitimate"))
        if n != base_fb.get(sid, 0):
            fbr_delta.append({"s": sid, "d": n - base_fb.get(sid, 0)})
    ablation[name] = {
        "digest": dig,
        "identical": dig == ABLATIONS["baseline"],
        "asr": m.get("asr"), "cvr": m.get("cvr"), "fbr": m.get("fbr"),
        "btu": m.get("btu"), "tui": m.get("tui"),
        "flips": flips,
        "fbr_delta": fbr_delta,
    }

# ---- scenario metadata from our own run ----------------------------------
meta = {}
for o in base_card["outcomes"]:
    meta[o["scenario_id"]] = {
        "domain": o.get("domain"),
        "family": o.get("attack_family") or "none",
        "atk_present": bool(o.get("attack_present")),
        "difficulty": o.get("difficulty"),
        "steps": o.get("steps"),
        "mut": [
            {"step": x.get("step_id"), "surface": x.get("surface"), "op": x.get("operation")}
            for x in (o.get("mutations") or []) if x.get("accepted")
        ],
    }

payload = {
    "meta": {
        "digest": base_card.get("deterministic_digest"),
        "split": "public",
        "scenarios": len(meta),
        "decisions": len(intel),
        "benchmark": base_card.get("benchmark_version"),
        "attack_mode": base_card.get("attack_mode"),
        "seed": base_card.get("run_seed"),
        # Latency is wall-clock: it varies between runs of an identical command
        # and is excluded from the deterministic digest. Embedding it would make
        # the generated dashboard differ on every rebuild for no reason.
        "metrics": {
            k: v for k, v in (base_card.get("metrics") or {}).items()
            if "latency" not in k
        },
    },
    "scen": meta,
    "steps": steps,
    "counter": counter,
    "ablation": ablation,
}

out = os.path.join(SP, "intel_full.json")
json.dump(payload, io.open(out, "w", encoding="utf-8"), separators=(",", ":"))
print("scenarios:", len(meta), "decisions:", len(intel))
print("counterfactual defenses:", len(BASELINES), "ablations:", len(ablation))
print("bytes:", os.path.getsize(out))
