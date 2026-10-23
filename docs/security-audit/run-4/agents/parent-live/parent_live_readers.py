"""parent-live N3: control-plane peak memory of the four uncapped container-output readers.

One mode per process (VmHWM is a per-process high-water mark). Real Docker engine, live
agentbox-desktop:0.1 sandbox prepared with 200,000 files in /workspace/many and /workspace/outbox.
The process runs under RLIMIT_AS so a runaway read fails inside this process instead of the host.

usage: python3 parent_live_readers.py <src-audited> <home> <sid> <mode> <out.json>
modes: baseline | list_dir | exec_ls | outbox | preview | screenshot_devzero
"""
import json, os, resource, sys, time, traceback
SRC, HOME, SID, MODE, OUT = sys.argv[1:6]
LIMIT = 3 * 1024 ** 3
resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))
sys.path.insert(0, SRC)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_IMAGE="buildpack-deps:noble-curl")
from agentbox.api import build
from agentbox.config import Settings


def hwm():
    for line in open("/proc/self/status"):
        if line.startswith("VmHWM:"):
            return int(line.split()[1])


app, box, human = build(Settings())
sb = box.sandboxes
res = {"mode": MODE, "rlimit_as_bytes": LIMIT}
before = hwm()
t0 = time.monotonic()
try:
    if MODE == "list_dir":
        o = box.call_tool(SID, "list_dir", {"path": "/workspace/many"})
        res["status"], res["returned_bytes"] = o.status, len(o.body["result"]["listing"])
    elif MODE == "exec_ls":
        o = box.call_tool(SID, "exec", {"command": "ls -la /workspace/many"})
        res["status"], res["returned_bytes"] = o.status, len(json.dumps(o.body["result"]))
    elif MODE == "outbox":
        items = sb.outbox_list(SID)
        res["entries"] = len(items)
    elif MODE == "preview":
        o = box.call_tool(SID, "exec", {"command": "rm /workspace/many/*"})
        res["status"], res["body_status"] = o.status, o.body.get("status")
        apr = box.approvals.get(o.body["approval_id"]) if o.body.get("approval_id") else None
        if apr:
            res["affected_rows"] = len((apr.get("preview") or {}).get("affected", []))
            box.decide(apr["id"], False, "human", "*")
    elif MODE == "screenshot_devzero":
        c = sb._desktop(SID)
        c.exec_run(["sh", "-c", "mkdir -p /home/desktop/.cache && ln -sf /dev/zero /home/desktop/.cache/agentbox-shot.png"], user="desktop")
        o = box.call_tool(SID, "screenshot", {})
        res["status"] = o.status
except BaseException as e:
    res["error"] = f"{type(e).__name__}: {str(e)[:300]}"
res["seconds"] = round(time.monotonic() - t0, 2)
res["vmhwm_before_kib"], res["vmhwm_after_kib"] = before, hwm()
res["vmhwm_delta_mib"] = round((res["vmhwm_after_kib"] - before) / 1024, 1)
open(OUT, "w").write(json.dumps(res, indent=1) + "\n")
print(json.dumps(res))
