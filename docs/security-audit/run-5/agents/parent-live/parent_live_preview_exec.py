"""parent-live (run-5, h-policy-cpu preview candidate): how long does the approval preview of 'rm -r d d d ...' take
against the real Docker engine, how many execs does it start, and does it delay another sandbox's allowed exec?

Bounded sizes only (N operands, default 500 and 2000); never the 8 MiB case.

usage: python3 parent_live_preview_exec.py <src-audited> <home> <out.json> [N ...]
"""
import json
import os
import subprocess
import sys
import threading
import time

SRC, HOME, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
SIZES = [int(x) for x in sys.argv[4:]] or [500, 2000]
sys.path.insert(0, SRC)
os.makedirs(HOME, exist_ok=True)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_IMAGE="ubuntu:24.04",
                  AGENTBOX_MIN_FREE="0")
from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

app, box, _ = build(Settings())
res = {"runs": []}
a, _ = box.create_sandbox(None, "cli")
b, _ = box.create_sandbox(None, "cli")
try:
    box.call_tool(a["id"], "exec", {"command": "mkdir d"})


    def probe(stop, out):
        while not stop.is_set():
            t = time.monotonic()
            box.call_tool(b["id"], "exec", {"command": "ls"})
            out.append(time.monotonic() - t)
            time.sleep(0.2)

    base = []
    for _ in range(5):
        t = time.monotonic()
        box.call_tool(b["id"], "exec", {"command": "ls"})
        base.append(time.monotonic() - t)
    res["other_sandbox_ls_baseline_s"] = [round(x, 3) for x in base]
    for n in SIZES:
        ev = subprocess.Popen(["docker", "events", "--filter", "type=container", "--filter", f"container={a['container_id']}",
                               "--filter", "event=exec_start", "--format", "{{.Action}}"], stdout=subprocess.PIPE, text=True)
        stop, lat = threading.Event(), []
        th = threading.Thread(target=probe, args=(stop, lat))
        th.start()
        t = time.monotonic()
        out = box.call_tool(a["id"], "exec", {"command": "rm -r " + " ".join(["d"] * n)})
        dur = time.monotonic() - t
        stop.set()
        th.join()
        time.sleep(1)
        ev.terminate()
        execs = sum(1 for line in ev.stdout.read().splitlines() if line.strip())
        aid = out.body.get("approval_id")
        if aid:
            box.decide(aid, False)
        lat.sort()
        res["runs"].append({"operands": n, "status": out.status, "seconds_to_response": round(dur, 2),
                            "exec_start_events": execs, "per_exec_ms": round(1000 * dur / max(execs, 1), 2),
                            "other_sandbox_ls_s": {"n": len(lat), "median": round(lat[len(lat) // 2], 3) if lat else None,
                                                   "max": round(lat[-1], 3) if lat else None}})
        print(res["runs"][-1], flush=True)
finally:
    for s in (a, b):
        try:
            box.delete_sandbox(s["id"])
        except Exception as e:  # noqa: BLE001
            print("cleanup", e)
    box.close()
open(OUT, "w", encoding="utf-8").write(json.dumps(res, indent=1) + "\n")
print(json.dumps(res, indent=1))
