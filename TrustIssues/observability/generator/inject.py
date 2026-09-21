"""Splice the Counterfactual Lab into the dashboard. Idempotent via markers."""
import io
import json
import os
import re
import sys

SP = sys.argv[1]
DASH = sys.argv[2]

CSS_A, CSS_B = "/* LAB:CSS:START */", "/* LAB:CSS:END */"
HTML_A, HTML_B = "<!-- LAB:HTML:START -->", "<!-- LAB:HTML:END -->"
JS_A, JS_B = "/* LAB:JS:START */", "/* LAB:JS:END */"

read = lambda p: io.open(os.path.join(SP, p), encoding="utf-8").read()
html = io.open(DASH, encoding="utf-8").read()

payload = json.load(io.open(os.path.join(SP, "intel_full.json"), encoding="utf-8"))
# A literal </script> inside the JSON would close the tag early.
blob = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")

css = CSS_A + read("panels.css") + CSS_B
markup = HTML_A + read("panels.html") + HTML_B
js = JS_A + "\nwindow.INTEL = " + blob + ";\n" + read("panels.js") + JS_B


def splice(doc, a, b, block, anchor):
    """Replace an existing marked block, or insert before `anchor`."""
    pat = re.compile(re.escape(a) + ".*?" + re.escape(b), re.S)
    if pat.search(doc):
        return pat.sub(lambda _: block, doc, count=1)
    i = doc.rindex(anchor)
    return doc[:i] + block + "\n" + doc[i:]


html = splice(html, CSS_A, CSS_B, css, "</style>")
html = splice(html, HTML_A, HTML_B, markup, "<script>")
html = splice(html, JS_A, JS_B, js, "</script>")

io.open(DASH, "w", encoding="utf-8").write(html)
print("dashboard bytes:", os.path.getsize(DASH))
for tag in (CSS_A, HTML_A, JS_A):
    print(" ", tag, "->", html.count(tag), "occurrence(s)")
