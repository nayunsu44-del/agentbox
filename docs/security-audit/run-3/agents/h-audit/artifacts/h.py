import sys, os, time, json, math, types, tempfile
sys.path.insert(0, "/target")
os.environ.setdefault("HOME", "/scratch")
from agentbox.audit import AuditLog, mask_text, AuditWriteError

out = []
def p(*a):
    print(*a, flush=True)

tmp = tempfile.mkdtemp(dir="/scratch")

# ---------- 1. UI / CLI timeline window after >5000 rows ----------
p("== 1. timeline window ==")
log = AuditLog(os.path.join(tmp, "a.db"))
SID = "sb_dummy"
N = 5100
log.conn.execute("BEGIN")
# fast path: use append for correctness of chain
log.conn.execute("COMMIT")
for i in range(N):
    log.append(actor="agent", event="tool_request", sandbox_id=SID, tool="exec",
               payload={"args": {"command": f"ls #{i}"}})
log.append(actor="system", event="gui_changes", sandbox_id=SID,
           payload={"snapshot_id": "snap_X", "reason": "idle", "counts": {"added": 0, "modified": 0, "deleted": 1},
                    "added": [], "modified": [], "deleted": ["/workspace/important.txt"], "truncated": False})
last_id = N + 1
p("total rows in DB:", last_id, "verify:", log.verify().as_dict())

# Drive the real web.py /ui/audit route with a stub box (no Docker needed).
# jinja2 is not available inside sbx, so fastapi.templating is replaced by a stub that
# records the template context the real route passes (rows, total) instead of rendering HTML.
import types as _t
from starlette.responses import Response as _R
class _Env:
    def __init__(self): self.globals = {}; self.filters = {}
class _Tpl:
    def __init__(self, directory): self.env = _Env()
    def TemplateResponse(self, request, name, ctx, headers=None):
        rows = ctx.get("rows") or []
        body = json.dumps({"template": name, "ids": [r["id"] for r in rows], "total": ctx.get("total"),
                           "events": [r["event"] for r in rows]})
        return _R(body, media_type="application/json", headers=headers)
_stub = _t.ModuleType("fastapi.templating"); _stub.Jinja2Templates = _Tpl
sys.modules["fastapi.templating"] = _stub
from fastapi import FastAPI
from fastapi.testclient import TestClient
from agentbox import web

class P:  # principal stub
    kind = "human"; session = "hs_test"; scope = "*"

box = types.SimpleNamespace()
box.audit = log
box.close_idle_gui_bursts = lambda: None
box.sandboxes = types.SimpleNamespace(runtime="runc")
app = FastAPI()
web.register(app, box, types.SimpleNamespace(secure_cookie=False), "hum_dummydummydummy",
             guard=lambda f: f(), browser_human=lambda: P(), human_only=lambda: P(),
             same_origin=lambda h: True)
c = TestClient(app)
r = c.get(f"/ui/audit?sandbox_id={SID}")
j = r.json()
ids = j["ids"]
p("status", r.status_code, "template", j["template"], "rows passed to template:", len(ids),
  "max id:", max(ids), "min id:", min(ids), "total:", j["total"])
p("latest id in DB:", last_id, "in UI rows?", last_id in ids, "| gui_changes in UI rows?", "gui_changes" in j["events"])
p("template footer would read: 최근 %d개만 표시 (전체 %d개)" % (len(ids), j["total"]))
p("describe(gui_changes row):", web.describe(log.list(after_id=last_id - 1)[0]))

# CLI cmd_audit: same request shape (limit=5000, no after_id) -> what /audit returns
rows = log.list(sandbox_id=None, after_id=0, limit=min(5000, 5000))
p("CLI/API default /audit?limit=5000 -> first id", rows[0]["id"], "last id", rows[-1]["id"], "contains latest?", any(r["id"] == last_id for r in rows))

# ---------- 2. verify robustness / canonicalization ----------
p("== 2. verify round-trip ==")
log2 = AuditLog(os.path.join(tmp, "b.db"))
for v in [float("nan"), float("inf"), -0.0, 1e308, 2**200, "\u202e\u200f", {"a": [1, {"b": None}]}, True]:
    log2.append(actor="agent", event="tool_request", sandbox_id=SID, tool="exec", payload={"args": {"x": v}})
p("verify after odd JSON values:", log2.verify().as_dict())
for bad in ["\ud800", 10 ** 5000]:
    try:
        log2.append(actor="agent", event="tool_request", sandbox_id=SID, tool="exec", payload={"args": {"x": bad}})
        p("appended", type(bad))
    except AuditWriteError as e:
        p("AuditWriteError", e)
    except Exception as e:
        p("non-AuditWriteError escapes append:", type(e).__name__, str(e)[:80])
p("verify after failed appends:", log2.verify().as_dict())

# ---------- 3. masking ----------
p("== 3. mask_text ==")
cases = [
    "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuv",
    "export TOKEN=\"$(rm -rf /workspace/proj)\"",
    "password: hunter2hunter2",
    "{\"client_secret\": \"abcdefgh12345\"}",
    "secret%3Dabcdefgh12345",
    "ghp_" + "A" * 36,
    "x_agt_" + "B" * 32,
    "Authorization: Bearer abcdefghijklmnop",
    "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "aws_secret_access_key\n= wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "SECRET\u00a0=\u00a0abcdefgh12345",
    "ＴＯＫＥＮ=abcdefgh12345",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
    "postgres://user:pa55word@host/db",
    "hf_" + "C" * 34,
    "npm_" + "D" * 36,
]
for t in cases:
    p(repr(t[:60]), "->", repr(mask_text(t)[:80]))

p("== 4. mask_text timing (adversarial, bounded 200 KB) ==")
adv = {
    "assign_chain": "a" * 99 + "=" + ("b=" * 50000),
    "dash_chain": "-" * 100000,
    "quote_open": "secret=\"" + "\\x" * 50000,
    "flag_chain": " ".join(["--x"] * 30000),
    "url": "a://" + "b" * 100 + ":" * 100000,
    "begin_pk": "-----BEGIN PRIVATE KEY-----" * 5000,
    "bearer": "bearer " * 25000,
    "upass": "-u " + "a" * 100 + ":" * 100000,
}
for k, t in adv.items():
    t0 = time.perf_counter(); mask_text(t[:200000]); dt = time.perf_counter() - t0
    p(f"{k}: len={len(t[:200000])} {dt:.3f}s")
