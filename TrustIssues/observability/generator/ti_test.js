/* DOM shim with SVG support: runs the dashboard's real script so render and
   interaction failures surface instead of being assumed away. */
const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync(process.argv[2], "utf8");
const TAG = /<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*?)(\/?)>/g;
const ATTR = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"/g;
const VOID = new Set(["meta", "link", "br", "hr", "img", "input", "path", "circle", "rect", "line", "stop", "use"]);

let ALL = [];
const QCLASS = new Set(["lab-tab", "navitem", "sitem", "chip", "tl", "tl-b", "mini-row", "dlegend", "lg", "dl", "fi", "stat", "bar-row", "fill", "nm",
  "legend", "sw", "tv-toggle", "crumb", "seg", "nav", "caret", "sub", "track", "card", "tip"]);

function mkEl(tag, attrs, ns) {
  const el = {
    tagName: (tag || "div").toUpperCase(), namespaceURI: ns || null,
    _attrs: { ...(attrs || {}) }, dataset: {}, style: {}, children: [],
    _html: "", _text: "", value: "", _listeners: {}, _parent: null, _owned: [],
  };
  for (const k of Object.keys(el._attrs)) {
    if (k.startsWith("data-")) el.dataset[k.slice(5).replace(/-([a-z])/g, (m, c) => c.toUpperCase())] = el._attrs[k];
  }
  el.id = el._attrs.id || "";
  let cls = (el._attrs.class || "").split(/\s+/).filter(Boolean);
  el.classList = {
    add: (...c) => c.forEach(x => { if (x && !cls.includes(x)) cls.push(x); }),
    remove: (...c) => { cls = cls.filter(x => !c.includes(x)); },
    contains: c => cls.includes(c),
    toggle: (c, f) => { const has = cls.includes(c); const want = f === undefined ? !has : !!f;
      if (want && !has) cls.push(c); if (!want && has) cls = cls.filter(x => x !== c); return want; },
  };
  Object.defineProperty(el, "className", { get: () => cls.join(" "), set: v => { cls = String(v).split(/\s+/).filter(Boolean); } });
  Object.defineProperty(el, "innerHTML", {
    get: () => el._html,
    set: v => {
      if (el._owned.length) { const dead = new Set(el._owned); ALL = ALL.filter(x => !dead.has(x)); }
      el._html = String(v);
      el.children = parse(String(v));
      el.children.forEach(c => { c._parent = el; });
      el._owned = el.children.slice();   // distinct array: appendChild writes to both
    },
  });
  Object.defineProperty(el, "textContent", { get: () => el._text, set: v => { el._text = String(v); } });
  Object.defineProperty(el, "firstChild", { get: () => el.children[0] || null });
  Object.defineProperty(el, "parentElement", { get: () => el._parent });
  el.addEventListener = (ev, fn) => { (el._listeners[ev] = el._listeners[ev] || []).push(fn); };
  el.removeEventListener = () => {};
  el.click = () => (el._listeners.click || []).slice().forEach(f => f.call(el, { target: el, preventDefault() {} }));
  el.fire = (ev, detail) => (el._listeners[ev] || []).slice().forEach(f => f.call(el, Object.assign({ target: el, preventDefault() {} }, detail)));
  el.setAttribute = (k, v) => { el._attrs[k] = String(v); if (k === "class") el.className = v;
    if (k === "id") el.id = String(v); if (k.startsWith("data-")) el.dataset[k.slice(5)] = String(v); };
  el.getAttribute = k => (k in el._attrs ? el._attrs[k] : null);
  el.hasAttribute = k => k in el._attrs;
  el.removeAttribute = k => { delete el._attrs[k]; };
  el.toggleAttribute = (k, f) => { const has = k in el._attrs; const want = f === undefined ? !has : !!f;
    if (want) el._attrs[k] = ""; else delete el._attrs[k]; return want; };
  el.appendChild = c => { c._parent = el; el.children.push(c); el._owned.push(c);
    if (!ALL.includes(c) && registrable(c)) ALL.push(c); return c; };
  el.insertBefore = (c, ref) => { c._parent = el; const i = el.children.indexOf(ref);
    el.children.splice(i < 0 ? 0 : i, 0, c); el._owned.push(c);
    if (!ALL.includes(c) && registrable(c)) ALL.push(c); return c; };
  el.remove = () => { if (el._parent) el._parent.children = el._parent.children.filter(x => x !== el);
    ALL = ALL.filter(x => x !== el); };
  el.querySelector = s => descendants(el).find(c => match(c, s)) || null;
  el.querySelectorAll = s => descendants(el).filter(c => match(c, s));
  el.getBoundingClientRect = () => ({ top: 0, left: 0, width: 800, height: 300, bottom: 300, right: 800 });
  el.focus = () => {};
  return el;
}
function registrable(el) {
  const cls = (el._attrs.class || "").split(/\s+/);
  return ["BUTTON", "INPUT", "A", "TEXTAREA", "SELECT"].includes(el.tagName) || !!el.id ||
    Object.keys(el.dataset).length > 0 || cls.some(c => QCLASS.has(c));
}
function descendants(el, out = []) { for (const c of el.children) { out.push(c); descendants(c, out); } return out; }

function parse(src) {
  const out = []; let m; TAG.lastIndex = 0;
  while ((m = TAG.exec(src))) {
    if (m[1].toLowerCase() === "svg" && m[3]) continue;
    const attrs = {}; let a; ATTR.lastIndex = 0;
    while ((a = ATTR.exec(m[2]))) attrs[a[1]] = a[2];
    const e = mkEl(m[1], attrs, null);
    if (registrable(e)) ALL.push(e);
    out.push(e);
  }
  return out;
}
function matchSimple(el, compound) {
  const toks = compound.match(/(^[a-zA-Z]+|[.#][-\w]+|\[[^\]]+\])/g) || [compound];
  return toks.every(t => {
    if (t.startsWith(".")) return el.classList.contains(t.slice(1));
    if (t.startsWith("#")) return el.id === t.slice(1);
    if (t.startsWith("[")) {
      const body = t.slice(1, -1);
      const eq = body.indexOf("=");
      if (eq < 0) return el._attrs[body] !== undefined || el.dataset[body.replace(/^data-/, "")] !== undefined;
      const k = body.slice(0, eq), v = body.slice(eq + 1).replace(/^["']|["']$/g, "");
      return String(el._attrs[k]) === v;
    }
    return el.tagName === t.toUpperCase();
  });
}
function match(el, sel) {
  sel = sel.trim();
  if (sel.includes(",")) return sel.split(",").some(s => match(el, s));
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

const docEl = mkEl("html", { "data-theme": "dark" });

// Build a real tree for the static markup, so descendant selectors
// ("#probeExamples button", ".seg button") resolve the way a browser resolves
// them. A flat parse silently makes those selectors match everything.
const ANY = /<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*?)(\/?)>/g;
function parseTree(src) {
  const roots = []; const stack = []; let m; ANY.lastIndex = 0;
  while ((m = ANY.exec(src))) {
    const raw = m[0], tag = m[1].toLowerCase(), closing = raw[1] === "/";
    if (closing) { if (stack.length && stack[stack.length - 1].tagName === tag.toUpperCase()) stack.pop(); continue; }
    const attrs = {}; let a; ATTR.lastIndex = 0;
    while ((a = ATTR.exec(m[2]))) attrs[a[1]] = a[2];
    const e = mkEl(tag, attrs, null);
    if (registrable(e)) ALL.push(e);
    const parent = stack[stack.length - 1];
    if (parent) { e._parent = parent; parent.children.push(e); } else roots.push(e);
    if (!m[3] && !VOID.has(tag)) stack.push(e);
  }
  return roots;
}
const body = html.slice(html.indexOf("<body"), html.lastIndexOf("</body>") + 7);
parseTree(body.replace(/<script[\s\S]*?<\/script>/g, ""));
const byId = id => ALL.find(e => e.id === id);

const document = {
  documentElement: docEl, body: mkEl("body", {}),
  getElementById: id => byId(id) || null,
  querySelector: s => ALL.find(e => match(e, s)) || null,
  querySelectorAll: s => ALL.filter(e => match(e, s)),
  createElement: t => mkEl(t, {}, null),
  createElementNS: (ns, t) => mkEl(t, {}, ns),
  addEventListener: () => {},
};

const CSSVARS = {};
(html.match(/--[\w-]+:\s*[^;}]+/g) || []).forEach(d => {
  const i = d.indexOf(":"); const k = d.slice(2, i).trim(); const v = d.slice(i + 1).trim();
  if (!(k in CSSVARS)) CSSVARS[k] = v;
});

const errors = [];
const rafQ = [];
const sandbox = {
  document, console,
  getComputedStyle: () => ({ getPropertyValue: p => CSSVARS[p.replace(/^--/, "")] || "#000000" }),
  requestAnimationFrame: f => { rafQ.push(f); return rafQ.length; },
  setTimeout: (f) => { try { f(); } catch (e) { errors.push("setTimeout: " + e.message); } return 0; },
  clearTimeout: () => {},
  setInterval: () => 0,
  clearInterval: () => {},
  localStorage: { _d: {}, getItem(k) { return this._d[k] ?? null; }, setItem(k, v) { this._d[k] = String(v); }, removeItem(k) { delete this._d[k]; } },
  CSS: { escape: s => String(s).replace(/[^\w-]/g, c => "\\" + c) },
  addEventListener: () => {},
  location: { href: "file://x" }, navigator: { userAgent: "node" },
  Math, JSON, Date, Object, Array, String, Number, Boolean, RegExp, Error, Set, Map, isNaN, parseInt, parseFloat,
};
sandbox.window = sandbox; sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const code = html.slice(html.lastIndexOf("<script>") + 8, html.lastIndexOf("</script>"));
try { vm.runInContext(code, sandbox, { filename: "dash.js" }); }
catch (e) { errors.push("script: " + e.message); console.log("FATAL:", e.stack.split("\n").slice(0, 5).join("\n")); }
rafQ.forEach(f => { try { f(0); } catch (e) { errors.push("raf: " + e.message); } });

const g = id => document.getElementById(id) || mkEl("div", {});
const count = (id, sel) => (g(id).querySelectorAll(sel) || []).length;
const svgOf = id => g(id).children.find(c => c.tagName === "SVG");
const nIn = (id, tag) => { const s = svgOf(id); return s ? descendants(s).filter(e => e.tagName === tag).length : 0; };


console.log("=== render ===");
const R = {
  "wordmark letters": count("wordmark", "span"),
  "wordmark ticker":  g("wmTicker").innerHTML.length,
  "KPI tiles":        count("statGrid", ".stat"),
  "depth paths":      nIn("depthPlot", "PATH"),
  "depth axis text":  nIn("depthPlot", "TEXT"),
  "depth legend":     count("depthLegend", ".lg"),
  "reason-code bars": count("codeBars", ".bar-row"),
  "family bars":      nIn("famPlot", "RECT"),
  "donut segments":   nIn("donutPlot", "PATH"),
  "donut legend":     count("donutLegend", ".dl"),
  "compare bars":     nIn("cmpPlot", "RECT"),
  "family chips":     count("famChips", ".chip"),
  "scenario rows":    count("scenList", ".sitem"),
  "timeline steps":   count("inspector", ".tl-b"),
  "domain rollup":    count("miniDom", ".mini-row"),
  "family feed":      count("feedFam", ".fi"),
};
for (const k of Object.keys(R)) console.log(`  ${k.padEnd(18)} ${R[k]}`);

console.log("\n=== interactions ===");
function tryClick(sel, label, probe) {
  const els = document.querySelectorAll(sel);
  let fired = 0, changed = 0;
  els.forEach(e => {
    const before = probe ? g(probe).innerHTML : "";
    try { e.click(); fired++; } catch (err) {
      errors.push(`${label}: ${err.message}`);
      console.log(`    ! ${label}: ${err.message}\n${(err.stack||"").split("\n").slice(1,3).join("\n")}`);
    }
    if (probe && g(probe).innerHTML !== before) changed++;
  });
  console.log(`  ${label.padEnd(18)} ${els.length} control(s), ${fired} fired${probe?`, ${changed} changed`:""}`);
  return els;
}
tryClick("[data-dom]", "domain tabs", "depthPlot");
tryClick("#depthLegend .lg", "depth legend", "depthPlot");
tryClick("[data-table]", "table toggles");
tryClick("#famChips .chip", "family chips", "scenList");
tryClick("#scenList .sitem", "scenario rows", "inspector");
tryClick("#themeBtn", "theme");
tryClick("#railBtn", "rail drawer");


console.log("\n=== post-interaction ===");
console.log(`  depth paths         ${nIn("depthPlot", "PATH")}`);
console.log(`  timeline steps      ${count("inspector", ".tl-b")}`);
console.log(`  fbr notes           ${count("inspector", ".fbr-note")}`);
console.log(`  tables built        ${["depthTable","famTable","donutTable","cmpTable"].filter(t=>count(t,"table")).length}/4`);
console.log(`  theme now           ${docEl.getAttribute("data-theme")}`);


console.log("\n=== inspector probe ===");
function insp(tag){
  const h=g("inspector").innerHTML;
  console.log(`  ${tag.padEnd(24)} html=${String(h.length).padStart(5)} #tl=${document.getElementById("tl")?"yes":"NO "} tl-b=${count("inspector",".tl-b")} rows=${count("scenList",".sitem")}`);
}
insp("after full test");
document.querySelectorAll("#famChips .chip")[0].click();
insp("after All chip");
const rws = document.querySelectorAll("#scenList .sitem");
if(rws.length>3){ rws[3].click(); insp("after clicking row 4"); }
let fbrTotal=0, stepTotal=0;
document.querySelectorAll("#scenList .sitem").forEach(r=>{
  r.click(); fbrTotal+=count("inspector",".fbr-note"); stepTotal+=count("inspector",".tl-b");
});
console.log(`  swept all rows: ${stepTotal} timeline steps, ${fbrTotal} fbr notes (expect 213 / 8)`);

const zero = Object.entries(R).filter(([, v]) => !v).map(([k]) => k);
if (zero.length) { console.log("\nEMPTY:", zero.join(", ")); errors.push("empty: " + zero.join(",")); }
console.log("\nerrors:", errors.length);
errors.forEach(e => console.log("  !", e));
process.exit(errors.length ? 1 : 0);
