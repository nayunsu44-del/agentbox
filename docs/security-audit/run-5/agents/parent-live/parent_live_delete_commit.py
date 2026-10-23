"""parent-live (run-5, h-lifecycle candidate): when the human deletes a sandbox while the agent's pre-overwrite docker
commit is running, does a snapshot row and image survive for the deleted sandbox?

Real Docker engine, cli template (ubuntu:24.04), audited tree in-process. The agent first writes ~600 MiB of new
files (allowed, no snapshot) so the commit takes seconds, then overwrites an existing file (allowed, snapshot first).
The human DELETE is sent after a delay while that commit runs.

usage: python3 parent_live_delete_commit.py <src-audited> <home> <out.json> [delay_s ...]
"""
import json
import os
import subprocess
import sys
import threading
import time

SRC, HOME, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
DELAYS = [float(x) for x in sys.argv[4:]] or [0.5]
sys.path.insert(0, SRC)
os.makedirs(HOME, exist_ok=True)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_IMAGE="ubuntu:24.04",
                  AGENTBOX_MIN_FREE="0", AGENTBOX_MEM="1g")
from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

app, box, _ = build(Settings())
res = {"runs": []}
for delay in DELAYS:
    rec, _ = box.create_sandbox(None, "cli")
    sid, cid = rec["id"], rec["container_id"]
    run = {"delay_s": delay, "sid": sid}
    try:
        box.call_tool(sid, "write_file", {"path": "/workspace/a.txt", "content": "v1"})
        # bulk data inside the writable layer via docker exec as root (stand-in for many agent write_file calls)
        subprocess.run(["docker", "exec", cid, "sh", "-c", "head -c 600M /dev/urandom > /workspace/big.bin"], check=True)
        out = {}

        def agent():
            t = time.monotonic()
            try:
                o = box.call_tool(sid, "write_file", {"path": "/workspace/a.txt", "content": "v2"})
                out["agent"] = {"status": o.status, "body": str(o.body)[:200]}
            except Exception as e:  # noqa: BLE001
                out["agent"] = {"error": repr(e)[:300]}
            out["agent_s"] = round(time.monotonic() - t, 2)

        th = threading.Thread(target=agent)
        th.start()
        time.sleep(delay)
        t = time.monotonic()
        try:
            box.delete_sandbox(sid)
            run["delete"] = "ok"
        except Exception as e:  # noqa: BLE001
            run["delete"] = repr(e)[:300]
        run["delete_s"] = round(time.monotonic() - t, 2)
        th.join()
        run.update(out)
        time.sleep(1)
        run["status_after"] = box.sandboxes.conn.execute("SELECT status FROM sandboxes WHERE id=?", (sid,)).fetchone()[0]
        run["snapshot_rows_after"] = [r[0] for r in box.sandboxes.conn.execute(
            "SELECT id FROM snapshots WHERE sandbox_id=?", (sid,))]
        run["images_after"] = subprocess.run(["docker", "images", "-q", "--filter", f"label=agentbox.sandbox={sid}"],
                                             capture_output=True, text=True).stdout.split()
        run["images_by_name"] = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}",
                                                f"agentbox-snap:{sid}-*"], capture_output=True, text=True).stdout.split()
        run["audit"] = [(r["actor"], r["event"]) for r in box.audit.list(sandbox_id=sid, limit=100)]
    finally:
        try:
            box.delete_sandbox(sid)   # second delete removes any orphan the first one left
        except Exception as e:  # noqa: BLE001
            run["cleanup"] = repr(e)[:200]
        run["images_after_second_delete"] = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", f"agentbox-snap:{sid}-*"],
            capture_output=True, text=True).stdout.split()
    res["runs"].append(run)
    print(json.dumps({k: run.get(k) for k in ("delay_s", "delete", "delete_s", "agent", "agent_s", "status_after",
                                               "snapshot_rows_after", "images_by_name", "images_after_second_delete")}),
          flush=True)
box.close()
open(OUT, "w", encoding="utf-8").write(json.dumps(res, indent=1) + "\n")
