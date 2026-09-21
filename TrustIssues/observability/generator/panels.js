
/* ===================== Counterfactual Lab ===================== */
(function () {
  var P = window.INTEL;
  if (!P) return;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* --- Faithful port of the Python extractor -------------------------
     _VALUE_RE / _norm / _values / _is_opaque from
     src/sentinel/defenses/baselines/TrustIssues_defense_v2.py             */
  var VALUE_RE = /[A-Za-z0-9][A-Za-z0-9_@.\-]{5,}/g;
  var STRIP = ".,;:!?\"'()[]{}";

  function norm(tok) {
    var t = tok.trim(), a = 0, b = t.length;
    while (a < b && STRIP.indexOf(t[a]) >= 0) a++;
    while (b > a && STRIP.indexOf(t[b - 1]) >= 0) b--;
    return t.slice(a, b).toLowerCase();
  }
  function values(text) {
    var out = [];
    if (!text) return out;
    var m = text.match(VALUE_RE) || [];
    for (var i = 0; i < m.length; i++) {
      var t = norm(m[i]);
      if (t.length < 6) continue;
      if (/[0-9]/.test(t) || t.indexOf("@") >= 0 || t.indexOf("-") >= 0 || t.indexOf("_") >= 0) {
        if (out.indexOf(t) < 0) out.push(t);
      }
    }
    return out;
  }
  function isOpaque(t) {
    if (t.length < 16 || t.indexOf("@") >= 0 || t.indexOf(".") >= 0) return false;
    var body = t.split("_").join("").split("-").join("");
    return body.length > 0 && /^[a-z0-9]+$/.test(body) && /[0-9]/.test(body) && /[a-z]/.test(body);
  }

  /* --- Port self-test against Python ground truth --------------------- */
  var allSteps = [];
  Object.keys(P.steps).forEach(function (sid) {
    P.steps[sid].forEach(function (s) { s._sid = sid; allSteps.push(s); });
  });

  (function verifyPort() {
    var n = 0, ok = 0;
    allSteps.forEach(function (s) {
      if (s.atext === undefined) return;
      n++;
      var got = values(s.atext).slice().sort();
      var want = (s.argv || []).slice().sort();
      if (got.length === want.length && got.every(function (v, i) { return v === want[i]; })) ok++;
    });
    var el = document.getElementById("portBadge");
    var nEl = document.getElementById("portN");
    if (nEl) nEl.textContent = String(n);
    if (!el) return;
    if (ok === n && n > 0) {
      el.textContent = "JS port verified ✓ " + ok + "/" + n + " decisions match Python";
    } else {
      el.className = "port-badge fail";
      el.textContent = "port mismatch: " + ok + "/" + n;
    }
  })();

  /* --- Tab switching --------------------------------------------------- */
  var tabs = document.querySelectorAll(".lab-tab");
  Array.prototype.forEach.call(tabs, function (t) {
    t.addEventListener("click", function () {
      Array.prototype.forEach.call(tabs, function (x) { x.classList.remove("active"); });
      t.classList.add("active");
      Array.prototype.forEach.call(document.querySelectorAll(".lab-panel"), function (p) {
        p.classList.remove("active");
      });
      var panel = document.getElementById("lab-" + t.dataset.lab);
      if (panel) panel.classList.add("active");
    });
  });

  var DEF_ORDER = ["allow_all", "keyword", "deny_sensitive", "heuristic_risk", "provenance", "trustissues_v2"];
  var DEF_LABEL = {
    allow_all: "allow_all", keyword: "keyword", deny_sensitive: "deny_sensitive",
    heuristic_risk: "heuristic_risk", provenance: "provenance", trustissues_v2: "TrustIssues v2"
  };
  var DEC_LETTER = { a: "A", b: "B", e: "E", r: "R" };

  function ourStep(sid, step) {
    var arr = P.steps[sid] || [];
    for (var i = 0; i < arr.length; i++) if (arr[i].step === step) return arr[i];
    return null;
  }

  /* --- Panel 1: Interception Ledger ----------------------------------- */
  (function ledger() {
    var rows = [];
    Object.keys(P.counter).forEach(function (sid) {
      var aa = P.counter[sid].allow_all;
      if (!aa) return;
      aa.leaks.forEach(function (f) { rows.push({ sid: sid, f: f }); });
    });
    rows.sort(function (x, y) {
      if (x.f.sev !== y.f.sev) return x.f.sev === "critical" ? -1 : 1;
      return x.sid < y.sid ? -1 : 1;
    });

    var nCrit = rows.filter(function (r) { return r.f.sev === "critical"; }).length;
    var nScen = Object.keys(P.counter).filter(function (s) { return P.counter[s].allow_all.leaks.length; }).length;
    var stopped = rows.filter(function (r) {
      var d = ourStep(r.sid, r.f.step);
      return d && d.decision !== "allow";
    }).length;

    document.getElementById("ledgerStats").innerHTML = [
      ['red', rows.length, 'findings under allow_all'],
      ['red', nCrit, 'critical severity'],
      ['amber', nScen, 'scenarios affected'],
      ['green', '0', 'findings under ours'],
      ['violet', stopped, 'stopped at the exact step']
    ].map(function (s) {
      return '<div class="stat ' + s[0] + '"><div class="stat-n">' + esc(s[1]) +
        '</div><div class="stat-l">' + esc(s[2]) + '</div></div>';
    }).join("");

    document.getElementById("ledgerList").innerHTML = rows.map(function (r) {
      var d = ourStep(r.sid, r.f.step);
      var stop;
      if (d && d.decision !== "allow") {
        stop = '<div class="leak-stop">✓ we returned <code>' + esc(d.decision.toUpperCase()) +
          "</code> at step " + esc(r.f.step) + " &mdash; <code>" + esc((d.codes || []).join(", ")) + "</code></div>";
      } else if (d) {
        stop = '<div class="leak-stop" style="color:#fcd34d">ℹ we allowed this step; the leak is prevented ' +
          "upstream or the value never reaches a sink under our run</div>";
      } else {
        stop = '<div class="leak-stop" style="color:#9ca3af">ℹ this step does not occur in our run</div>';
      }
      return '<div class="leak"><div class="leak-top"><span class="leak-scen">' + esc(r.sid) +
        '</span><span class="leak-tags"><span class="chip step">step ' + esc(r.f.step) +
        '</span><span class="chip ' + (r.f.sev === "critical" ? "crit" : "high") + '">' + esc(r.f.sev) +
        '</span><span class="chip ok">' + esc(r.f.rule) + "</span></span></div>" +
        '<div class="leak-msg">' + esc(r.f.msg) + "</div>" + stop + "</div>";
    }).join("");
  })();

  /* --- Panel 2: Defense Race ------------------------------------------ */
  (function race() {
    var filters = [["broken", "Where baselines break"], ["all", "All 40"], ["fbr", "Our disputed blocks"]];
    var mode = "broken";

    function scenarioList() {
      var ids = Object.keys(P.counter).sort();
      if (mode === "all") return ids;
      if (mode === "fbr") {
        return ids.filter(function (s) {
          return (P.steps[s] || []).some(function (d) {
            return d.decision === "block" && (d.codes || []).indexOf("OPAQUE_VALUE_EGRESS") >= 0;
          }) && (P.scen[s] || {}).family === "data_exfiltration";
        });
      }
      return ids.filter(function (s) {
        return DEF_ORDER.some(function (d) {
          return d !== "trustissues_v2" && P.counter[s][d] && P.counter[s][d].leaks.length;
        });
      });
    }

    function render() {
      document.getElementById("raceFilter").innerHTML = filters.map(function (f) {
        return '<button data-m="' + f[0] + '" style="' +
          (f[0] === mode ? "background:rgba(167,139,250,.15);color:#c4b5fd;border-color:rgba(167,139,250,.5)" : "") +
          '">' + esc(f[1]) + "</button>";
      }).join("");
      Array.prototype.forEach.call(document.querySelectorAll("#raceFilter button"), function (b) {
        b.addEventListener("click", function () { mode = b.dataset.m; render(); });
      });

      document.getElementById("raceList").innerHTML = scenarioList().map(function (sid) {
        var meta = P.scen[sid] || {};
        var rows = DEF_ORDER.map(function (d) {
          var c = P.counter[sid][d];
          if (!c) return "";
          var leakSteps = {};
          c.leaks.forEach(function (f) { leakSteps[f.step] = 1; });
          var cells = c.seq.split("").map(function (ch, i) {
            var step = i + 1;
            var tool = (c.tools && c.tools[i]) || "";
            return '<div class="cell ' + ch + (leakSteps[step] ? " leak" : "") +
              '" title="step ' + step + " — " + esc(tool) + '">' + (DEC_LETTER[ch] || "?") + "</div>";
          }).join("");
          var bad = c.atk || c.crit;
          var out = bad
            ? '<span class="race-out bad">' + (c.leaks.length || "attack") + " leaked</span>"
            : '<span class="race-out good">held</span>';
          return '<div class="race-row' + (d === "trustissues_v2" ? " ours" : "") + '"><div class="race-def">' +
            esc(DEF_LABEL[d]) + '</div><div class="race-cells">' + cells + "</div>" + out + "</div>";
        }).join("");
        return '<div class="race-card"><div class="race-name">' + esc(sid) +
          '</div><div class="race-goal">' + esc(meta.domain || "") + " · " + esc(meta.family || "none") +
          " · difficulty " + esc(meta.difficulty) + '</div><div class="race-rows">' + rows + "</div></div>";
      }).join("") || '<div class="lab-note">No scenario matches this filter.</div>';
    }
    render();
  })();

  /* --- Panel 3: Ablation Lab ------------------------------------------ */
  (function ablation() {
    var NOTE = {
      baseline: "The shipped configuration. Every other card is measured against this run.",
      rule3_off: "Opaque-value detection disabled. Public is unchanged, but validation loses ASR 0.250 — the mechanism is the only thing holding that split.",
      rule4_off: "The instruction-resemblance rule disabled. It produces a bit-for-bit identical digest: not one of the 213 decisions changes. The rule an adaptive attacker would paraphrase around is carrying zero load.",
      rules34_off: "Both content rules disabled, leaving only tool scope and confirmation. This is the only variant that reaches FBR 0.000 — and it does so at ASR 0.742. That is the trade we refused.",
      no_restricted_gate: "The RESTRICTED override in rule 3 removed, so an internal recipient exempts even a secret token. Alone it costs nothing — rule 4 still catches those four drafts.",
      no_restricted_gate_and_rule4_off: "Both redundant paths removed together. Now four ent_*_draft scenarios break. Neither mechanism looks load-bearing alone; together they are. This is why we keep both.",
      keys_on: "Argument names counted as carried values, as the pre-fix code did. No security metric moves; FBR rises 0.049 → 0.080. Pure false-positive fuel."
    };
    var base = P.ablation.baseline;
    var names = Object.keys(P.ablation);
    var sel = "rule4_off";

    function cls(v, b, inverted) {
      if (Math.abs(v - b) < 1e-9) return "flat";
      return (v > b) === !inverted ? "up" : "down";
    }

    function render() {
      document.getElementById("ablGrid").innerHTML = names.map(function (n) {
        var a = P.ablation[n];
        var tag = "";
        if (n !== "baseline" && a.identical) tag = '<span class="abl-tag ident">identical digest — 0 decisions changed</span>';
        else if (a.flips.length) tag = '<span class="abl-tag brk">breaks ' + a.flips.length + " scenarios</span>";
        else if (a.fbr_delta.length) tag = '<span class="abl-tag noise">+' + a.fbr_delta.length + " scenarios gain false blocks</span>";
        return '<button class="abl' + (n === sel ? " sel" : "") + '" data-a="' + esc(n) + '">' +
          '<div class="abl-n">' + esc(n) + '</div><div class="abl-m">' +
          '<span>ASR <b class="' + cls(a.asr, base.asr) + '">' + a.asr.toFixed(3) + "</b></span>" +
          '<span>CVR <b class="' + cls(a.cvr, base.cvr) + '">' + a.cvr.toFixed(3) + "</b></span>" +
          '<span>FBR <b class="' + cls(a.fbr, base.fbr) + '">' + a.fbr.toFixed(3) + "</b></span>" +
          "</div>" + tag + "</button>";
      }).join("");

      Array.prototype.forEach.call(document.querySelectorAll(".abl"), function (b) {
        b.addEventListener("click", function () { sel = b.dataset.a; render(); });
      });

      var a = P.ablation[sel];
      var body = "<h4>" + esc(sel) + "</h4><p>" + esc(NOTE[sel] || "") + "</p>" +
        '<p style="margin-top:8px;font-family:\'Courier New\',monospace;font-size:.72rem;color:var(--text-muted)">digest ' +
        esc(a.digest) + "</p>";
      if (a.flips.length) {
        body += '<p style="margin-top:12px"><b style="color:#fca5a5">Attacks that now succeed:</b></p><div class="flip-list">' +
          a.flips.map(function (s) { return '<span class="flip">' + esc(s) + "</span>"; }).join("") + "</div>";
      }
      if (a.fbr_delta.length) {
        body += '<p style="margin-top:12px"><b style="color:#fcd34d">Change in blocks on legitimate steps:</b></p><div class="flip-list">' +
          a.fbr_delta.map(function (x) {
            return '<span class="flip fb">' + esc(x.s) + " " + (x.d > 0 ? "+" : "") + esc(x.d) + "</span>";
          }).join("") + "</div>";
      }
      if (!a.flips.length && !a.fbr_delta.length) {
        body += '<p style="margin-top:12px;color:#6ee7b7">No scenario changes outcome.</p>';
      }
      document.getElementById("ablDetail").innerHTML = body;
    }
    render();
  })();

  /* --- Panel 4: Value-Flow Probe --------------------------------------- */
  (function probe() {
    var withOpaque = allSteps.filter(function (s) { return (s.opaque || []).length; });
    var examples = [];
    withOpaque.slice(0, 4).forEach(function (s) {
      examples.push([s._sid + " step " + s.step, s.atext]);
    });
    examples.push(["benign case note", 'Dispute CASE-7001 remains open pending officer review.']);

    var inEl = document.getElementById("probeIn");
    var outEl = document.getElementById("probeOut");
    var vEl = document.getElementById("probeVerdict");

    function run() {
      var vals = values(inEl.value);
      if (!vals.length) {
        outEl.innerHTML = '<span style="font-size:.76rem;color:var(--text-muted)">No identifier-shaped value found. ' +
          "Ordinary prose carries nothing the defense needs to gate.</span>";
        vEl.innerHTML = "";
        return;
      }
      var op = vals.filter(isOpaque);
      outEl.innerHTML = vals.map(function (v) {
        return '<span class="tok ' + (isOpaque(v) ? "opaque" : "plain") + '">' + esc(v) + "</span>";
      }).join("");
      vEl.innerHTML = op.length
        ? '<div class="verdict block">⛔ ' + op.length + " opaque value" + (op.length > 1 ? "s" : "") +
          " — if no trusted source supplied " + (op.length > 1 ? "them" : "it") +
          ", rule 3 intercepts this call.</div>"
        : '<div class="verdict pass">✓ ' + vals.length + " value" + (vals.length > 1 ? "s" : "") +
          ", none credential-shaped. Rule 3 does not fire on shape alone.</div>";
    }

    document.getElementById("probeExamples").innerHTML = examples.map(function (e, i) {
      return '<button data-i="' + i + '">' + esc(e[0]) + "</button>";
    }).join("");
    Array.prototype.forEach.call(document.querySelectorAll("#probeExamples button"), function (b) {
      b.addEventListener("click", function () { inEl.value = examples[+b.dataset.i][1]; run(); });
    });

    inEl.addEventListener("input", run);
    inEl.value = examples.length ? examples[0][1] : "";
    run();

    function why(s) {
      if ((s.restricted_hit || []).length) {
        return ["#fca5a5", "⚑ RESTRICTED — this label permits no destination at all, so even an " +
          "internal recipient is not grounds for release."];
      }
      if (s.outbound && s.external_recipient === false) {
        return ["#6ee7b7", "✓ recipient is inside internal_email_domains and the value is not RESTRICTED, " +
          "so it has not crossed the trust boundary. Rule 3 stands down."];
      }
      if (s.outbound && s.external_recipient === true) {
        return ["#fca5a5", "⚑ recipient is outside internal_email_domains — this is egress."];
      }
      return ["#fca5a5", "⚑ this tool names no recipient, so no destination can be shown to permit the value."];
    }

    // The same tool and the same internal recipient, decided both ways purely
    // on the sensitivity label -- the clearest statement of the thesis.
    var pairA = withOpaque.filter(function (s) {
      return s.outbound && s.external_recipient === false && (s.restricted_hit || []).length;
    })[0];
    var pairB = withOpaque.filter(function (s) {
      return s.outbound && s.external_recipient === false && !(s.restricted_hit || []).length;
    })[0];
    var contrast = "";
    if (pairA && pairB) {
      contrast = '<div class="leak" style="border-left-color:#a78bfa;margin-bottom:10px">' +
        '<div class="leak-top"><span class="leak-scen">the discriminator is the label, not the destination</span></div>' +
        '<div class="leak-msg">Both calls below are <code>' + esc(pairA.tool) +
        "</code> to a recipient <b>inside</b> the organisation, and both carry an opaque value the user never supplied. " +
        "They are decided differently:<br><br>" +
        '<span class="chip crit">BLOCK</span> <code>' + esc(pairA._sid) + "</code> step " + esc(pairA.step) +
        " &mdash; value is <b>RESTRICTED</b><br>" +
        '<span class="chip ok">ALLOW</span> <code>' + esc(pairB._sid) + "</code> step " + esc(pairB.step) +
        " &mdash; value is <b>not RESTRICTED</b><br><br>" +
        "A rule keyed on the recipient would allow both. A rule keyed on resemblance to untrusted text would " +
        "block both. Only the sensitivity label separates them.</div></div>";
    }

    document.getElementById("probeReal").innerHTML = contrast + withOpaque.map(function (s) {
      var w = why(s);
      var allowed = s.decision === "allow";
      return '<div class="leak" style="border-left-color:' + (allowed ? "#10b981" : "#ef4444") +
        '"><div class="leak-top"><span class="leak-scen">' + esc(s._sid) +
        '</span><span class="leak-tags"><span class="chip step">step ' + esc(s.step) +
        '</span><span class="chip ' + (allowed ? "ok" : "crit") + '">' + esc(s.decision) +
        '</span><span class="chip high">' + esc(s.tool) + "</span></span></div>" +
        '<div class="leak-msg">opaque: ' + (s.opaque || []).map(function (v) {
          return '<span class="tok opaque">' + esc(v) + "</span>";
        }).join("") +
        '<div style="margin-top:6px;font-size:.72rem;color:' + w[0] + '">' + w[1] + "</div></div></div>";
    }).join("");
  })();
})();
