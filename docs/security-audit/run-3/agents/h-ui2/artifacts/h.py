# h-ui2 harness: server-side half of the clickjacking check.
# Fakes only the Docker client (no daemon in sbx) and the post-approval snapshot/exec,
# then drives the real FastAPI app with TestClient.
import os, sys, types, json
sys.path.insert(0, "/target"); sys.path.insert(1, "/scratch/libs")
os.environ.clear()
os.environ["AGENTBOX_HOME"] = "/tmp/abhome"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_dummy_" + "0" * 32

import docker  # real package; replace only from_env
class _FakeDocker:
    def info(self):
        return {"Runtimes": {"runc": {}}}
docker.from_env = lambda *a, **k: _FakeDocker()

from agentbox import api, service
from fastapi.testclient import TestClient

ran = []
service.AgentBox._snapshot = lambda self, sid, tool, reason, ref: {"id": "snap_fake", "image": "x"}
service.AgentBox._run_tool = lambda self, sid, tool, args: (ran.append((sid, tool, args)) or {"exit_code": 0, "stdout": "", "stderr": ""})

app, box, human = api.build()
# minimal sandbox row so /ui/sandboxes/{sid} and desktop page render
sid = "sb_dummy01"
box.sandboxes.get = lambda s: {"id": s, "template": "desktop", "runtime": "runc", "status": "running",
                               "source_dir": "", "created_at": "2026-10-22T00:00:00"}
box.sandboxes.template_of = lambda s: types.SimpleNamespace(desktop=True)
box.sandboxes._desktop = lambda s: object()
box.sandboxes.list_snapshots = lambda s: []

ORIGIN = "http://testserver"
c = TestClient(app, base_url=ORIGIN)
r = c.post("/login", data={"token": human}, headers={"Origin": ORIGIN}, follow_redirects=False)
print("login", r.status_code, "set-cookie:", r.headers.get("set-cookie", "").split(";", 1)[1].strip())

apr = box.approvals.create(sandbox_id=sid, tool="exec", args={"command": "rm -rf /workspace/src"},
                           rule_id="dummy-gate", rule_reason="destructive", preview={"cwd": "/workspace", "affected": []})
print("pending approval", apr["id"], apr["status"])

FRAME_HDRS = {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate",
              "Referer": "http://testserver:9999/evil.html"}
def hdrs(r):
    h = {k.lower(): v for k, v in r.headers.items()}
    return {k: h.get(k) for k in ("x-frame-options", "content-security-policy", "cross-origin-opener-policy",
                                  "cross-origin-embedder-policy", "cross-origin-resource-policy")}
for path in ["/ui", f"/ui/sandboxes/{sid}", "/ui/approvals", f"/sandboxes/{sid}/desktop", "/login"]:
    r = c.get(path, headers=FRAME_HDRS, follow_redirects=False)
    print("GET", path, r.status_code, json.dumps(hdrs(r)))

r = c.get("/ui/approvals", headers=FRAME_HDRS)
i = r.text.find(f"/ui/approvals/{apr['id']}/approve")
btn = r.text[r.text.rfind("<button", 0, i): r.text.find("</button>", i) + 9]
print("approve button markup:", btn)
print("approve button has hx-confirm:", "hx-confirm" in btn)

# The click inside the framed agentbox document: htmx XHR from the agentbox origin itself.
CLICK = {"Origin": ORIGIN, "HX-Request": "true", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"}
r = c.post(f"/ui/approvals/{apr['id']}/approve?sandbox_id=", headers=CLICK)
print("POST approve", r.status_code, "HX-Trigger:", r.headers.get("hx-trigger"))
print("approval after click:", box.approvals.get(apr["id"])["status"], "decided_by:", box.approvals.get(apr["id"])["decided_by"])
print("agent args executed:", ran)

# takeover from framed desktop page (fetch POST, credentials same-origin)
box.takeover = lambda s, sess: {"taken": s, "session": sess}
r = c.post(f"/sandboxes/{sid}/desktop/takeover", headers={"Origin": ORIGIN})
print("POST takeover", r.status_code, r.json().get("taken"))

# control: a cross-site POST (Origin of the framer) is refused, showing same_origin is what a framed click passes
r = c.post(f"/ui/approvals/{apr['id']}/deny", headers={"Origin": "http://testserver:9999"})
print("control cross-port POST (direct CSRF)", r.status_code)
