"""parent-live: does a concurrent allowlisted `touch` let an over-quota write_file commit without approval?

Runs the audited control plane in-process against the REAL Docker engine (Linux cloud container,
review session) with a disposable AGENTBOX_HOME, one CLI sandbox at snapshot_quota=2 that already
holds two snapshots, and races exec `touch /workspace/pN` against write_file /workspace/pN at
several start offsets. A trial "bypasses" when write_file returns 200 and the snapshot count grew
with no approval created for that request. Evidence only: the v11 record keeps its verifier verdict.

usage: python3 -I parent_live_snapquota.py <src-audited> <home> <out.json>
"""
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

SRC, HOME, OUT = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
OFFSETS = [-0.02, -0.01, -0.005, 0.0, 0.005, 0.01, 0.02]
REPEAT = 3

sys.path.insert(0, SRC)
os.environ["AGENTBOX_HOME"] = str(HOME)
os.environ["AGENTBOX_IMAGE"] = "buildpack-deps:noble-curl"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_" + "p" * 40
os.environ["AGENTBOX_SNAPSHOT_QUOTA"] = "2"

from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

result = {"settings": {"snapshot_quota": 2, "image": "buildpack-deps:noble-curl"}, "control": {}, "trials": [], "error": None}
box = None
sid = None


def pending(sid):
    return [a for a in box.approvals.list() if a["sandbox_id"] == sid and a["status"] == "pending"]


def deny_all(sid):
    for a in pending(sid):
        try:
            box.decide(a["id"], False, "human", "*")
        except Exception:
            pass


def trial(n, offset):
    path = f"/workspace/p{n}"
    out = {}
    before = box.sandboxes.snapshot_count(sid)
    apr_before = {a["id"] for a in pending(sid)}

    def do_exec():
        try:
            out["exec"] = box.call_tool(sid, "exec", {"command": f"touch {path}"}).status
        except Exception as e:
            out["exec"] = f"{type(e).__name__}: {str(e)[:120]}"

    def do_write():
        try:
            o = box.call_tool(sid, "write_file", {"path": path, "content": "x"})
            out["write"] = o.status
            out["write_body_status"] = o.body.get("status")
        except Exception as e:
            out["write"] = f"{type(e).__name__}: {str(e)[:120]}"

    first, second, delay = (do_exec, do_write, offset) if offset >= 0 else (do_write, do_exec, -offset)
    t1 = threading.Thread(target=first)
    t1.start()
    time.sleep(delay)
    t2 = threading.Thread(target=second)
    t2.start()
    t1.join(60)
    t2.join(60)
    after = box.sandboxes.snapshot_count(sid)
    new_apr = [a["id"] for a in pending(sid) if a["id"] not in apr_before]
    row = {"n": n, "exec_offset_s": offset, **out, "snapshots_before": before, "snapshots_after": after,
           "new_approvals": len(new_apr),
           "bypass": out.get("write") == 200 and after > before and not new_apr}
    deny_all(sid)
    return row


try:
    HOME.mkdir(parents=True, exist_ok=True)
    settings = Settings(home=HOME, image="buildpack-deps:noble-curl")
    app, box, human = build(settings)
    rec, tok = box.create_sandbox(None, "cli")
    sid = rec["id"]
    box.snapshot_sandbox(sid)
    box.snapshot_sandbox(sid)
    # control: overwrite of a stably existing file at quota must go to approval with no commit
    box.call_tool(sid, "exec", {"command": "touch /workspace/existing"})
    c0 = box.sandboxes.snapshot_count(sid)
    o = box.call_tool(sid, "write_file", {"path": "/workspace/existing", "content": "x"})
    result["control"] = {"status": o.status, "body_status": o.body.get("status"),
                         "rule": (box.approvals.get(o.body["approval_id"]) or {}).get("rule_id") if o.body.get("approval_id") else None,
                         "snapshots_before": c0, "snapshots_after": box.sandboxes.snapshot_count(sid)}
    deny_all(sid)
    n = 0
    for off in OFFSETS:
        for _ in range(REPEAT):
            n += 1
            try:
                result["trials"].append(trial(n, off))
            except Exception:
                result["trials"].append({"n": n, "exec_offset_s": off, "error": traceback.format_exc()[-800:]})
    result["final_snapshot_count"] = box.sandboxes.snapshot_count(sid)
except Exception:
    result["error"] = traceback.format_exc()[-2000:]
finally:
    if box is not None and sid is not None:
        try:
            box.delete_sandbox(sid)  # removes the container and every agentbox-snap image
        except Exception as e:
            result["cleanup_error"] = str(e)[:200]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    by = {}
    for t in result["trials"]:
        k = t.get("exec_offset_s")
        by.setdefault(k, [0, 0])
        by[k][1] += 1
        by[k][0] += bool(t.get("bypass"))
    print("control:", result["control"], "error:", bool(result["error"]))
    print("bypass by exec offset (wins/trials):", by)
    if box is not None:
        try:
            box.close()
        except Exception:
            pass
