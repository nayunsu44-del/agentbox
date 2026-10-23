"""parent-live N2: what happens when agent-grown audit rows fill the volume that holds agentbox.db?

Real control plane from the audited tree, real Docker CLI sandboxes, AGENTBOX_HOME on a 16 MiB loop-mounted
ext4 (dummy tokens). Sandbox A's agent sends allowlisted `ls` calls with a long argument (each logs a
16 KiB args head) on 4 threads until an audit write fails; then sandbox B's agent, a human approval decision
in B, a human snapshot of B and the read paths are tried. The recovery options run in parent_live_diskfull_recovery.py after this process exits.

usage: python3 parent_live_diskfull.py <src-audited> <home-on-small-volume> <out.json>
then:  python3 parent_live_diskfull_recovery.py <src-audited> <db> <out.json>   (separate process)
"""
import json, os, shutil, sqlite3, sys, threading, time
SRC, HOME, OUT = sys.argv[1:4]
sys.path.insert(0, SRC)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_IMAGE="buildpack-deps:noble-curl")
from agentbox.api import build
from agentbox.config import Settings
from agentbox.audit import AuditLog

app, box, human = build(Settings())
res = {"volume_bytes": shutil.disk_usage(HOME).total}
a, _ = box.create_sandbox(None, "cli")
b, _ = box.create_sandbox(None, "cli")
A, B = a["id"], b["id"]
pend = box.call_tool(B, "exec", {"command": "rm /workspace/x"})  # pending approval in B, decided after the fill
res["b_pending_approval"] = pend.body.get("approval_id")
arg = "ls /workspace/" + "a" * 16000
stop = threading.Event()
stats = {"calls": 0, "first_failure": None}
lock = threading.Lock()


def worker():
    while not stop.is_set():
        try:
            o = box.call_tool(A, "exec", {"command": arg})
            with lock:
                stats["calls"] += 1
        except Exception as e:
            with lock:
                if stats["first_failure"] is None:
                    stats["first_failure"] = {"after_calls": stats["calls"], "error": f"{type(e).__name__}: {getattr(e, 'status', '')} {str(e)[:200]}"}
            stop.set()

t0 = time.monotonic()
ths = [threading.Thread(target=worker) for _ in range(4)]
[t.start() for t in ths]
[t.join(900) for t in ths]
res["fill"] = {**stats, "seconds": round(time.monotonic() - t0, 1), "free_bytes_after": shutil.disk_usage(HOME).free}


def attempt(name, fn):
    try:
        out = fn()
        res.setdefault("after_full", {})[name] = {"ok": True, "result": str(out)[:200]}
    except Exception as e:
        res.setdefault("after_full", {})[name] = {"ok": False, "error": f"{type(e).__name__}: {getattr(e, 'status', '')} {str(e)[:200]}"}

attempt("sandbox_B_agent_ls", lambda: box.call_tool(B, "exec", {"command": "ls /workspace"}).status)
attempt("human_decide_B_approval", lambda: box.decide(res["b_pending_approval"], True, "human", "*")["status"])
attempt("human_snapshot_B", lambda: box.snapshot_sandbox(B)["id"])
attempt("human_list_audit", lambda: len(box.audit.list(limit=50)))
attempt("human_verify_audit", lambda: box.audit.verify())
attempt("human_delete_A", lambda: box.delete_sandbox(A))
attempt("human_delete_B", lambda: box.delete_sandbox(B))
for sid in (A, B):  # parent cleanup outside the product path
    try:
        cid = box.sandboxes.get(sid)["container_id"]
        box.sandboxes.client.containers.get(cid).remove(force=True)
    except Exception:
        pass
db = box.sandboxes.settings.db_path
try:
    lv = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    res["live_db_read_while_control_plane_running"] = {"integrity": lv.execute("pragma integrity_check").fetchone()[0]}
    lv.close()
except Exception as e:
    res["live_db_read_while_control_plane_running"] = {"error": f"{type(e).__name__}: {e}"}
res["db_path"] = str(db)
box.close()
open(OUT, "w").write(json.dumps(res, ensure_ascii=False, indent=1, default=str) + "\n")
print(json.dumps(res, ensure_ascii=False, indent=1, default=str))
