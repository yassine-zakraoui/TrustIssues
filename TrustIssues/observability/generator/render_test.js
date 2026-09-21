/* Minimal DOM shim: executes the dashboard's real script against the real
   embedded data, so rendering failures surface instead of being assumed away. */
const fs = require("fs");
const vm = require("vm");

const DASH = process.argv[2];
const html = fs.readFileSync(DASH, "utf8");

const TAG = /<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g;
const ATTR = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"/g;

let ALL = [];

function mkEl(tag, attrs) {
  const el = {
    tagName: (tag || "div").toUpperCase(),
    _attrs: attrs || {},
    dataset: {},
    style: {},
    children: [],
    _html: "",
    _text: "",
    value: "",
    _listeners: {},
  };
  for (const k of Object.keys(el._attrs)) {
    if (k.startsWith("data-")) el.dataset[k.slice(5).replace(/-([a-z])/g, (m, c) => c.toUpperCase())] = el._attrs[k];
  }
  el.id = el._attrs.id || "";
  let cls = (el._attrs.class || "").split(/\s+/).filter(Boolean);
  el.classList = {
    add: (...c) => c.forEach((x) => { if (!cls.includes(x)) cls.push(x); }),
    remove: (...c) => { cls = cls.filter((x) => !c.includes(x)); },
    contains: (c) => cls.includes(c),
    toggle: (c, f) => (f === undefined ? (cls.includes(c) ? el.classList.remove(c) : el.classList.add(c))
      : f ? el.classList.add(c) : el.classList.remove(c)),
  };
  Object.defineProperty(el, "className", { get: () => cls.join(" "), set: (v) => { cls = String(v).split(/\s+/).filter(Boolean); } });
  Object.defineProperty(el, "innerHTML", {
    get: () => el._html,
    set: (v) => {
      // A real DOM discards the replaced subtree; the registry must too, or
      // repeated re-renders grow it without bound.
      if (el._owned && el._owned.length) {
        const dead = new Set(el._owned);
        ALL = ALL.filter((x) => !dead.has(x));
      }
      el._html = String(v);
      el.children = parse(String(v));
      el.children.forEach((c) => { c._parent = el; });
      el._owned = el.children;
    },
  });
  Object.defineProperty(el, "textContent", { get: () => el._text, set: (v) => { el._text = String(v); } });
  el.addEventListener = (ev, fn) => { (el._listeners[ev] = el._listeners[ev] || []).push(fn); };
  el.removeEventListener = () => {};
  el.click = () => (el._listeners.click || []).forEach((f) => f.call(el, { target: el, preventDefault() {} }));
  el.dispatchEvent = () => true;
  el.setAttribute = (k, v) => { el._attrs[k] = v; if (k === "class") el.className = v; };
  el.getAttribute = (k) => el._attrs[k];
  el.appendChild = (c) => { el.children.push(c); return c; };
  el.querySelector = (s) => el.children.find((c) => match(c, s)) || null;
  el.querySelectorAll = (s) => el.children.filter((c) => match(c, s));
  el.closest = () => null;
  el.scrollIntoView = () => {};
  el.focus = () => {};
  el.getBoundingClientRect = () => ({ top: 0, left: 0, width: 100, height: 100, bottom: 0, right: 0 });
  // Only register what the page can actually query. Decorative nodes (grid
  // cells, chips) are thousands per re-render and are never selected.
  const queryable =
    ["BUTTON", "INPUT", "TEXTAREA", "SELECT", "A"].includes(el.tagName) ||
    !!el.id ||
    Object.keys(el.dataset).length > 0 ||
    cls.some((c) => QUERYABLE_CLASSES.has(c));
  if (queryable) ALL.push(el);
  return el;
}
const QUERYABLE_CLASSES = new Set([
  "lab-tab", "lab-panel", "abl", "scenario-item", "filter-tab", "tab", "nav-item",
]);

function parse(src) {
  const out = [];
  let m;
  TAG.lastIndex = 0;
  while ((m = TAG.exec(src))) {
    const attrs = {};
    let a;
    ATTR.lastIndex = 0;
    while ((a = ATTR.exec(m[2]))) attrs[a[1]] = a[2];
    out.push(mkEl(m[1], attrs));
  }
  return out;
}

function matchSimple(el, compound) {
  const toks = compound.match(/(^[a-zA-Z]+|[.#][-\w]+|\[[^\]]+\])/g) || [compound];
  return toks.every((t) => {
    if (t.startsWith(".")) return el.classList.contains(t.slice(1));
    if (t.startsWith("#")) return el.id === t.slice(1);
    if (t.startsWith("[")) return el._attrs[t.slice(1, -1).split("=")[0]] !== undefined;
    return el.tagName === t.toUpperCase();
  });
}

// Descendant combinators must be honoured, or "#probeExamples button" silently
// matches every button on the page and the test stops resembling a browser.
function match(el, sel) {
  sel = sel.trim();
  if (sel.includes(",")) return sel.split(",").some((s) => match(el, s));
  const parts = sel.split(/\s+/).filter(Boolean);
  if (!matchSimple(el, parts[parts.length - 1])) return false;
  let p = el._parent;
  for (let i = parts.length - 2; i >= 0; i--) {
    while (p && !matchSimple(p, parts[i])) p = p._parent;
    if (!p) return false;
    p = p._parent;
  }
  return true;
}

const body = html.slice(html.indexOf("<body"), html.lastIndexOf("</body>") + 7);
ALL = parse(body.replace(/<script[\s\S]*?<\/script>/g, ""));

const document = {
  getElementById(id) {
    let el = ALL.find((e) => e.id === id);
    if (!el) { el = mkEl("div", { id }); }
    return el;
  },
  querySelector: (s) => ALL.find((e) => match(e, s)) || null,
  querySelectorAll: (s) => ALL.filter((e) => match(e, s)),
  createElement: (t) => mkEl(t, {}),
  addEventListener: () => {},
  body: mkEl("body", {}),
  documentElement: mkEl("html", {}),
};

const errors = [];
const sandbox = {
  document,
  window: { addEventListener: () => {}, matchMedia: () => ({ matches: false, addEventListener() {} }) },
  console,
  setTimeout: (f) => { try { f(); } catch (e) { errors.push("setTimeout: " + e.message); } },
  clearTimeout: () => {},
  requestAnimationFrame: (f) => { try { f(0); } catch (e) { errors.push("raf: " + e.message); } },
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  navigator: { userAgent: "node" },
  location: { href: "file://dash" },
  Math, JSON, Date, Object, Array, String, Number, Boolean, RegExp, Error, Set, Map, isNaN, parseInt, parseFloat,
};
sandbox.window.document = document;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
console.log("script blocks:", scripts.length);
scripts.forEach((code, i) => {
  try {
    vm.runInContext(code, sandbox, { filename: `dash-script-${i}.js` });
  } catch (e) {
    errors.push(`script[${i}]: ${e.message}`);
  }
});

const g = (id) => document.getElementById(id);
const report = {
  portBadge: g("portBadge")._text || g("portBadge")._html,
  ledgerStats: (g("ledgerStats").innerHTML.match(/class="stat /g) || []).length,
  ledgerRows: (g("ledgerList").innerHTML.match(/class="leak"/g) || []).length,
  raceCards: (g("raceList").innerHTML.match(/class="race-card"/g) || []).length,
  raceCells: (g("raceList").innerHTML.match(/class="cell /g) || []).length,
  ablCards: (g("ablGrid").innerHTML.match(/class="abl/g) || []).length,
  ablDetail: g("ablDetail").innerHTML.length,
  probeTokens: (g("probeOut").innerHTML.match(/class="tok /g) || []).length,
  probeVerdict: g("probeVerdict").innerHTML.slice(0, 80),
  probeReal: (g("probeReal").innerHTML.match(/class="leak"/g) || []).length,
  originalScenarioList: (g("scenarioListContainer").innerHTML.match(/scenario/gi) || []).length,
  originalTimeline: g("timelineContainer").innerHTML.length,
};
console.log("\n=== render report ===");
for (const k of Object.keys(report)) console.log(`  ${k.padEnd(22)} ${report[k]}`);
// Interactions: every control must run without throwing and must change state.
console.log("\n=== interaction report ===");
function clickAll(sel, label, probeId) {
  const els = document.querySelectorAll(sel);
  let fired = 0, changed = 0;
  els.forEach((el) => {
    const before = probeId ? g(probeId).innerHTML : "";
    try {
      el.click();
      fired++;
    } catch (e) {
      errors.push(`${label} click: ${e.message}`);
      console.log(`    ! ${label}: ${e.message}\n${(e.stack || "").split("\n").slice(1, 4).join("\n")}`);
    }
    if (probeId && g(probeId).innerHTML !== before) changed++;
  });
  console.log(`  ${label.padEnd(18)} ${els.length} control(s), ${fired} fired, ${changed} changed output`);
}
clickAll(".lab-tab", "lab tabs");
clickAll(".abl", "ablation cards", "ablDetail");
clickAll("#raceFilter button", "race filters", "raceList");
clickAll("#probeExamples button", "probe examples", "probeOut");

const probeAfter = g("probeOut").innerHTML;
console.log(`  probe still renders  ${(probeAfter.match(/class="tok /g) || []).length} token(s)`);
console.log(`  contrast callout     ${g("probeReal").innerHTML.includes("discriminator is the label") ? "present" : "MISSING"}`);

console.log("\nerrors:", errors.length);
errors.forEach((e) => console.log("  !", e));
process.exit(errors.length ? 1 : 0);
