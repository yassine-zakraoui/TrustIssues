"""Assemble one payload for the redesigned dashboard: scenarios, KPIs,
aggregates and the baseline comparison."""
import glob
import io
import json
import os
from collections import Counter, defaultdict

SP = os.path.dirname(os.path.abspath(__file__))
ROOT = "artifacts/scorecards"

# Selected by deterministic digest, never by timestamp.
BASELINES = [
    ("allow_all",      "a9aa03e1ebc66985"),
    ("keyword",        "7ba9abae889ac9f0"),
    ("deny_sensitive", "5e6c1b09399e545d"),
    ("heuristic_risk", "8f8db315a2dd8741"),
    ("provenance",     "7e9ab1696a87101c"),
    ("trustissues_v2", "563f184f2093fc14"),
]

cards = {}
for p in glob.glob(os.path.join(ROOT, "*.json")):
    try:
        s = json.load(io.open(p, encoding="utf-8"))
    except Exception:
        continue
    if s.get("split") == "public" and s.get("scenario_count") == 40:
        cards[s.get("deterministic_digest", "")[:16]] = s

scen = json.load(io.open(os.path.join(SP, "scenarios.json"), encoding="utf-8"))

ours = cards["563f184f2093fc14"]
m = ours["metrics"]

# --- aggregates -------------------------------------------------------
dec = Counter(st["decision"] for s in scen for st in s["steps"])
codes = Counter(c for s in scen for st in s["steps"] for c in st["codes"])
fam = Counter(s["family"] for s in scen)
dom = Counter(s["domain"] for s in scen)

# Decisions by step position: how deep into a run interception happens.
maxstep = max(len(s["steps"]) for s in scen)
allowed = [0] * maxstep
stopped = [0] * maxstep
for s in scen:
    for st in s["steps"]:
        i = st["step"] - 1
        if 0 <= i < maxstep:
            (allowed if st["decision"] == "ALLOW" else stopped)[i] += 1

# Per-domain metric rollup.
by_dom = defaultdict(lambda: {"scen": 0, "atk": 0, "steps": 0, "blocks": 0, "fbr": 0})
for s in scen:
    d = by_dom[s["domain"]]
    d["scen"] += 1
    d["atk"] += 1 if s["family"] != "none" else 0
    d["steps"] += len(s["steps"])
    d["blocks"] += sum(1 for st in s["steps"] if st["decision"] == "BLOCK")
    d["fbr"] += sum(1 for st in s["steps"] if st.get("fbr"))

payload = {
    "meta": {
        "digest": ours.get("deterministic_digest", "")[:16],
        "split": "public", "benchmark": ours.get("benchmark_version"),
        "attackMode": ours.get("attack_mode"), "seed": ours.get("run_seed"),
        "defense": "trustissues_v2",
    },
    "kpi": {
        "asr": m.get("asr"), "cvr": m.get("cvr"), "btu": m.get("btu"),
        "fbr": m.get("fbr"), "uer": m.get("uer"), "tui": m.get("tui"), "dfi": m.get("dfi"),
        "attacks": sum(1 for s in scen if s["family"] != "none"),
        "benign": sum(1 for s in scen if s["family"] == "none"),
        "decisions": sum(dec.values()),
        "falseBlocks": sum(1 for s in scen for st in s["steps"] if st.get("fbr")),
    },
    "decisions": [
        {"k": "ALLOW", "v": dec["ALLOW"], "role": "good"},
        {"k": "BLOCK", "v": dec["BLOCK"], "role": "critical"},
        {"k": "ESCALATE", "v": dec["ESCALATE"], "role": "warning"},
    ],
    "codes": [{"k": k, "v": v} for k, v in codes.most_common()],
    "families": [{"k": k, "v": v} for k, v in fam.most_common()],
    "domains": [
        {"k": k, "scen": v["scen"], "atk": v["atk"], "steps": v["steps"],
         "blocks": v["blocks"], "fbr": v["fbr"]}
        for k, v in sorted(by_dom.items())
    ],
    "stepProfile": {
        "labels": [str(i + 1) for i in range(maxstep)],
        "allowed": allowed, "stopped": stopped,
    },
    "baselines": [
        {"k": name,
         "asr": cards[d]["metrics"].get("asr"),
         "cvr": cards[d]["metrics"].get("cvr"),
         "fbr": cards[d]["metrics"].get("fbr"),
         "btu": cards[d]["metrics"].get("btu"),
         "ours": name == "trustissues_v2"}
        for name, d in BASELINES if d in cards
    ],
    "scenarios": scen,
}

out = os.path.join(SP, "dash_payload.json")
json.dump(payload, io.open(out, "w", encoding="utf-8"), separators=(",", ":"))
print("scenarios :", len(scen))
print("decisions :", payload["kpi"]["decisions"], dict(dec))
print("codes     :", len(payload["codes"]))
print("baselines :", len(payload["baselines"]))
print("maxstep   :", maxstep)
print("bytes     :", os.path.getsize(out))
