"""parent-live after the run-7 follow-up fixes: delete_file content bypass, approvals list size, pid-exhaustion preview card."""
import os, tempfile, pathlib, threading, time
os.environ["AGENTBOX_PIDS"] = "64"; os.environ["AGENTBOX_EXEC_TIMEOUT"] = "8"
from fastapi.testclient import TestClient
tmp = pathlib.Path(tempfile.mkdtemp()); os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; (src / ".claude").mkdir(parents=True); (src / ".claude" / "settings.json").write_text("{}")
(src / "cfg").symlink_to(".claude", target_is_directory=True); (src / "a.txt").write_text("a")
from agentbox.api import build
app, box, human = build(); c = TestClient(app); H = {"Authorization": f"Bearer {human}"}
print("docker_root_problem:", box.docker_root_problem)
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json(); sid = sb["id"]; A = {"Authorization": f"Bearer {sb['agent_token']}"}
def tool(t, a): r = c.post(f"/sandboxes/{sid}/tools/{t}", json={"args": a}, headers=A); return r.status_code, r.json()
st, j = tool("delete_file", {"path": "/workspace/a.txt", "content": "x" * 1_300_000})
print("delete_file + 1.3M content ->", st, (j.get("detail") or j.get("status"))[:60])
for i in range(5):
    tool("write_file", {"path": f"/workspace/d{i}/CLAUDE.md", "content": "\x01" * 1_000_000})
t = time.monotonic(); r = c.get("/approvals", params={"status": "pending"}, headers=H)
print(f"GET /approvals (5 pending x 1MB): {len(r.content)} bytes, {time.monotonic()-t:.2f}s; content in list: {'content' in r.json()[0]['args']}")
for a in r.json(): c.post(f"/approvals/{a['id']}", json={"decision": "deny"}, headers=H)
cmd = " ".join(["tail -f /dev/null &"] * 58) + " tail -f /dev/null"
th = threading.Thread(target=lambda: tool("exec", {"command": cmd})); th.start(); time.sleep(2.0)
st, j = tool("write_file", {"path": "/workspace/cfg/settings.json", "content": "INJECTED"})
th.join()
apr = c.get(f"/approvals/{j.get('approval_id')}", headers=H).json() if j.get("approval_id") else {}
pv = apr.get("preview") or {}
print("write_file under pid exhaustion ->", st, j.get("status"), "| card instruction_file:", pv.get("instruction_file"),
      "| notes:", [n[:40] for n in pv.get("notes", [])])
print(".claude/settings.json:", box.sandboxes._container(sid).exec_run(["cat", "/workspace/.claude/settings.json"]).output.decode()[:40])
c.delete(f"/sandboxes/{sid}", headers=H)
