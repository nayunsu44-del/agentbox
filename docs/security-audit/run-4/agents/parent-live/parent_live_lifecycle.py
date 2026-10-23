"""parent-live: can a restore racing a delete resurrect the deleted row and revive the agent token?

Runs the audited control plane in-process against the REAL Docker engine with a disposable
AGENTBOX_HOME, one CLI sandbox and one snapshot per trial, and repeats the race at several
delete offsets so the answer is a distribution rather than one lucky schedule.

usage: python parent_live_lifecycle.py <out.json>
"""
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

SRC = r"<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited"
HOME = Path(r"<WINDOWS_HOST_ROOT>/temp/agentbox-run4/parent-live/lifecycle")
OUT = Path(sys.argv[1])
OFFSETS = [0.02, 0.08, 0.15, 0.25, 0.4, 0.7]

sys.path.insert(0, SRC)
os.environ["AGENTBOX_HOME"] = str(HOME)
os.environ["AGENTBOX_IMAGE"] = "buildpack-deps:noble-curl"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_" + "p" * 40

from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

result = {"trials": [], "control": {}, "error": None}
box = None
settings = Settings(home=HOME, image="buildpack-deps:noble-curl")


def state(sid):
    rec = box.sandboxes.get(sid)
    cid = rec.get("container_id")
    alive = False
    if cid:
        try:
            alive = box.sandboxes.client.containers.get(cid).status == "running"
        except Exception:
            alive = False
    return {"status": rec.get("status"), "container_id": cid, "container_alive": alive}


def force_clean(sid):
    try:
        rec = box.sandboxes.get(sid)
    except Exception:
        return
    cid = rec.get("container_id")
    if cid:
        try:
            box.sandboxes.client.containers.get(cid).remove(force=True)
        except Exception:
            pass
    for s in box.sandboxes.list_snapshots(sid):
        try:
            box.sandboxes.client.images.remove(s["image"], force=True)
        except Exception:
            pass


def trial(offset):
    rec, old_token = box.create_sandbox(None, "cli")
    sid = rec["id"]
    snap = box.snapshot_sandbox(sid)
    calls = {}

    def do_restore():
        try:
            box.restore_sandbox(sid, snap["id"])
            calls["restore"] = "ok"
        except Exception as e:
            calls["restore"] = f"{type(e).__name__}: {str(e)[:160]}"

    t = threading.Thread(target=do_restore)
    t.start()
    time.sleep(offset)
    try:
        box.delete_sandbox(sid)
        calls["delete"] = "ok"
    except Exception as e:
        calls["delete"] = f"{type(e).__name__}: {str(e)[:160]}"
    t.join(timeout=180)
    time.sleep(0.3)
    after = state(sid)
    row = {"offset_s": offset, "calls": calls, "after": after,
           "old_token_matches": box.sandboxes.token_matches(sid, old_token),
           "old_token_maps_to_sid": box.sandboxes.sandbox_for_token(old_token) == sid,
           "resurrected": after["status"] == "running" and box.sandboxes.token_matches(sid, old_token)}
    force_clean(sid)
    return row


try:
    HOME.mkdir(parents=True, exist_ok=True)
    app, box, human = build(settings)
    for off in OFFSETS:
        try:
            result["trials"].append(trial(off))
        except Exception:
            result["trials"].append({"offset_s": off, "error": traceback.format_exc()[-800:]})

    # sequential control
    rec2, tok2 = box.create_sandbox(None, "cli")
    sid2 = rec2["id"]
    snap2 = box.snapshot_sandbox(sid2)
    box.delete_sandbox(sid2)
    ctl = {}
    try:
        box.restore_sandbox(sid2, snap2["id"])
        ctl["restore_after_delete"] = "returned normally (UNEXPECTED)"
    except Exception as e:
        ctl["restore_after_delete"] = f"{type(e).__name__}: {str(e)[:160]}"
    ctl["after"] = state(sid2)
    ctl["old_token_matches"] = box.sandboxes.token_matches(sid2, tok2)
    result["control"] = ctl
    force_clean(sid2)
except Exception:
    result["error"] = traceback.format_exc()[-2000:]
finally:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("resurrected_trials=", sum(1 for t in result["trials"] if t.get("resurrected")), "of", len(result["trials"]))
    if box is not None:
        try:
            box.close()
        except Exception:
            pass
