"""Bounded harness: audit timeline readers after >5000 rows (no Docker; fake SandboxManager, fake templates).

Uses the real FastAPI app from agentbox.api.build() with the real AuditLog, policy, service and web routes.
Only SandboxManager (Docker) and Jinja2Templates (jinja2 not installed in the sandbox) are replaced.
The fake template renders the context the route passes (row ids, total) as JSON.
"""
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, "/target")
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_dummy_local_token_0000"
HOME = Path("/scratch/audit-h")
HOME.mkdir(parents=True, exist_ok=True)
for f in HOME.glob("agentbox.db*"):
    f.unlink()
os.environ["AGENTBOX_HOME"] = str(HOME)

import types  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
ft = types.ModuleType("fastapi.templating")
sys.modules["fastapi.templating"] = ft


class _Env:
    def __init__(self):
        self.globals, self.filters = {}, {}


class FakeTemplates:
    def __init__(self, directory):
        self.env = _Env()

    def TemplateResponse(self, request, name, ctx, headers=None):
        rows = ctx.get("rows") or []
        body = {"template": name, "total": ctx.get("total"), "shown": len(rows),
                "newest_shown_id": max((r["id"] for r in rows), default=None),
                "events_shown": sorted({r["event"] for r in rows}),
                "marker_shown": any("AFTER_FLOOD" in json.dumps(r["payload"]) for r in rows)}
        return HTMLResponse(json.dumps(body), headers=headers)


ft.Jinja2Templates = FakeTemplates

import agentbox.api as api  # noqa: E402


class _Client:
    def close(self):
        pass


class _Tpl:
    desktop = False


class FakeSM:
    def __init__(self, settings, db):
        self.settings = settings
        self.runtime = "runc"
        self.conn = sqlite3.connect(":memory:")
        self.client = _Client()

    def sandbox_for_token(self, token):
        return "sb_test" if token == "agt_dummy" else None

    def get(self, sid):
        if sid != "sb_test":
            from agentbox.sandbox import SandboxError
            raise SandboxError("no")
        return {"id": sid, "status": "running"}

    def list(self):
        return [self.get("sb_test")]

    def template_of(self, sid):
        return _Tpl()

    def snapshot_count(self, sid):
        return 0

    def list_dir(self, sid, path):
        return {"path": path, "listing": "total 0"}


api.SandboxManager = FakeSM

from fastapi.testclient import TestClient  # noqa: E402

app, box, human = api.build()
c = TestClient(app)
AG = {"Authorization": "Bearer agt_dummy"}
HU = {"Authorization": f"Bearer {human}"}

# agent: ordinary allowed tool calls (3 audit rows each)
for i in range(1700):
    r = c.post("/sandboxes/sb_test/tools/list_dir", json={"args": {"path": "/workspace"}}, headers=AG)
    assert r.status_code == 200, r.text
# then an action the human should see
r = c.post("/sandboxes/sb_test/tools/list_dir", json={"args": {"path": "/workspace/AFTER_FLOOD"}}, headers=AG)
assert r.status_code == 200

total_rows = box.audit.conn.execute("SELECT COUNT(*), MAX(id) FROM audit").fetchone()
ui = c.get("/ui/audit", params={"sandbox_id": "sb_test"}, headers=HU)
cli_q = c.get("/audit", params={"limit": 5000}, headers=HU).json()           # what `agentbox audit` sends
out = {
    "db_rows_and_max_id": total_rows,
    "ui_audit_fragment_context": json.loads(ui.text),
    "cli_audit_query": {"returned": len(cli_q), "max_id": max(e["id"] for e in cli_q),
                        "marker_present": any("AFTER_FLOOD" in json.dumps(e["payload"]) for e in cli_q)},
}
print(json.dumps(out, indent=1))
