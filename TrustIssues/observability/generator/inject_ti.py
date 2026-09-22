import io, json, os, sys
SP = os.path.dirname(os.path.abspath(__file__))
tpl = io.open(os.path.join(SP, "template.html"), encoding="utf-8").read()
payload = json.load(io.open(os.path.join(SP, "dash_payload.json"), encoding="utf-8"))
blob = json.dumps(payload, separators=(",", ":")).replace("</", "<" + chr(92) + "/")
assert "/*__PAYLOAD__*/" in tpl
out = tpl.replace("/*__PAYLOAD__*/", blob)
dst = sys.argv[1]
io.open(dst, "w", encoding="utf-8").write(out)
print("written:", os.path.getsize(dst), "bytes; script tags:", out.count("</script>"))
