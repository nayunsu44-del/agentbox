"""parent-live (run-5, h-gui-lease path a): does an approved GUI input decided during a human takeover open an
agent GUI burst whose later idle close kills a process the human started during the lease?

Runs the audited control plane in-process against the real Docker engine and a fresh agentbox-desktop:0.1
sandbox. Policy = default policy plus a rule that gates click behind approval (the candidate's path (a)
precondition). AGENTBOX_GUI_SNAPSHOT_IDLE is lowered to 5 s so the idle close happens without a 60 s wait.

usage: python3 parent_live_gui_lease.py <src-audited> <home> <out.json>
"""
import json
import os
import subprocess
import sys
import time

SRC, HOME, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, SRC)
os.makedirs(HOME, exist_ok=True)
pol = open(f"{SRC}/agentbox/default_policy.yaml", encoding="utf-8").read()
pol = pol.replace("rules:\n", "rules:\n  - id: gui-approval\n    tool: click\n    action: require_approval\n"
                  "    reason: parent-live precondition\n", 1)
open(f"{HOME}/policy.yaml", "w", encoding="utf-8").write(pol)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_POLICY=f"{HOME}/policy.yaml",
                  AGENTBOX_GUI_SNAPSHOT_IDLE="5", AGENTBOX_IMAGE="buildpack-deps:noble-curl")
from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

app, box, _ = build(Settings())
res = {"steps": []}


def step(name, **kw):
    res["steps"].append({"step": name, **kw})
    print(name, json.dumps(kw, ensure_ascii=False, default=str)[:300])


rec, _tok = box.create_sandbox(None, "desktop")
sid = rec["id"]
cid = box.sandboxes._desktop(sid).id
for _ in range(60):
    try:
        procs, wins = box.sandboxes.desktop_processes(sid)
        if wins:
            break
    except Exception:
        pass
    time.sleep(1)
step("desktop_ready", sid=sid, window_pids=sorted(wins))
try:
    box.takeover(sid, "sess_human")
    step("takeover", lease=bool(box.desktop.lease(sid)))
    out = box.call_tool(sid, "click", {"x": 5, "y": 5})
    aid = out.body.get("approval_id")
    step("agent_click", status=out.status, approval_id=aid)
    apr = box.decide(aid, True, session="sess_human")
    step("human_approves_during_lease", status=apr["status"], result=apr.get("result"),
         lease=bool(box.desktop.lease(sid)), burst_open=sid in box.bursts._gui_burst,
         burst_baseline_size=len(box.bursts._gui_burst.get(sid, {}).get("procs", []) or []))
    # A job the human starts during the lease (new session, reparented to PID 1, as a terminal job would be).
    subprocess.run(["docker", "exec", "-u", "desktop", cid, "setsid", "-f", "sleep", "600"], check=True)
    time.sleep(1)
    ps = subprocess.run(["docker", "exec", cid, "ps", "-eo", "pid,uid,sid,args"], capture_output=True, text=True).stdout
    human_pid = [int(line.split()[0]) for line in ps.splitlines()[1:] if line.split()[3:] == ["sleep", "600"]]
    step("human_job_started", pids=human_pid)
    time.sleep(7)   # past AGENTBOX_GUI_SNAPSHOT_IDLE
    box.expire_stale()   # what GET /approvals/{aid} or any agent tool call runs
    box.bursts.close_idle(wait=30)
    ps2 = subprocess.run(["docker", "exec", cid, "ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
    alive = [p for p in human_pid if any(line.split()[0] == str(p) for line in ps2.splitlines()[1:])]
    rows = [r for r in box.audit.list(sandbox_id=sid, limit=500)
            if r["event"] in ("human_takeover", "snapshot", "approval_decision", "tool_error",
                              "gui_processes_stopped", "gui_processes_kept", "gui_changes", "gui_burst_open_failed")]
    step("after_idle_close", lease_still_held=bool(box.desktop.lease(sid)), human_job_alive=alive,
         burst_open=sid in box.bursts._gui_burst)
    res["audit"] = [{k: r[k] for k in ("id", "actor", "event", "tool", "payload")} for r in rows]
    res["verdict"] = {"burst_opened_during_lease": any(r["event"] == "snapshot" and r["tool"] == "click" for r in rows),
                      "human_job_killed_during_lease": bool(human_pid) and not alive and bool(box.desktop.lease(sid))}
finally:
    try:
        box.handback(sid, "sess_human")
    except Exception as e:
        step("handback_error", error=str(e))
    box.delete_sandbox(sid)
    box.close()
open(OUT, "w", encoding="utf-8").write(json.dumps(res, ensure_ascii=False, indent=1, default=str) + "\n")
print("VERDICT", res.get("verdict"))
