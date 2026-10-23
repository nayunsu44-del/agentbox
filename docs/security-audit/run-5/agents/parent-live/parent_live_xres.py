"""parent-live (run-5, h-xres unresolved facts): in a real agentbox-desktop:0.1 sandbox, (1) do the XRes window owners
returned by desktop_processes match the container-namespace pids of the processes that really own Xfce windows, and
(2) is a non-windowed desktop-user process started during an agent GUI burst stopped when the burst closes?

usage: python3 parent_live_xres.py <src-audited> <home> <out.json>
"""
import json
import os
import subprocess
import sys
import time

SRC, HOME, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, SRC)
os.makedirs(HOME, exist_ok=True)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_GUI_SNAPSHOT_IDLE="5",
                  AGENTBOX_IMAGE="buildpack-deps:noble-curl")
from agentbox.api import build  # noqa: E402
from agentbox.config import Settings  # noqa: E402

app, box, _ = build(Settings())
res = {}
rec, _tok = box.create_sandbox(None, "desktop")
sid = rec["id"]
cid = box.sandboxes._desktop(sid).id
try:
    for _ in range(60):
        try:
            procs, wins = box.sandboxes.desktop_processes(sid)
            if len(wins) >= 2:
                break
        except Exception:
            pass
        time.sleep(1)
    time.sleep(3)
    procs, wins = box.sandboxes.desktop_processes(sid)
    by = {p["pid"]: p for p in procs}
    res["window_owner_pids"] = {str(p): by.get(p, {}).get("args") for p in sorted(wins)}
    # Independent view: which client pids does the X server report? (xdotool's _NET_WM_PID is client-declared, shown
    # only for comparison; the XRes answer is what the control plane uses.)
    xd = subprocess.run(["docker", "exec", "-u", "desktop", "-e", "DISPLAY=:0", cid, "sh", "-c",
                         "for w in $(xdotool search --onlyvisible --name . 2>/dev/null); do "
                         "echo $w $(xdotool getwindowpid $w 2>/dev/null) $(xdotool getwindowname $w 2>/dev/null); done"],
                        capture_output=True, text=True).stdout
    res["xdotool_net_wm_pid_view"] = xd.splitlines()[:40]
    res["all_owner_pids_are_desktop_user_processes"] = all(by.get(p, {}).get("uid") == 1001 for p in wins)
    # (2) agent click opens a burst; then a non-windowed desktop-user job appears in a new session; idle close.
    out = box.call_tool(sid, "click", {"x": 5, "y": 5})
    res["agent_click_status"] = out.status
    subprocess.run(["docker", "exec", "-u", "desktop", cid, "setsid", "-f", "sleep", "601"], check=True)
    time.sleep(1)
    ps = subprocess.run(["docker", "exec", cid, "ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
    job = [int(line.split()[0]) for line in ps.splitlines()[1:] if line.split()[1:] == ["sleep", "601"]]
    time.sleep(7)
    box.expire_stale()
    box.bursts.close_idle(wait=30)
    ps2 = subprocess.run(["docker", "exec", cid, "ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
    res["job_pids"] = job
    res["job_alive_after_close"] = [p for p in job if any(line.split()[0] == str(p) for line in ps2.splitlines()[1:])]
    res["audit"] = [{k: r[k] for k in ("id", "event", "payload")} for r in box.audit.list(sandbox_id=sid, limit=500)
                    if r["event"] in ("gui_processes_stopped", "gui_processes_kept", "gui_burst_open_failed",
                                      "gui_burst_close_failed")]
finally:
    box.delete_sandbox(sid)
    box.close()
open(OUT, "w", encoding="utf-8").write(json.dumps(res, ensure_ascii=False, indent=1, default=str) + "\n")
print(json.dumps({k: res.get(k) for k in ("window_owner_pids", "all_owner_pids_are_desktop_user_processes",
                                          "agent_click_status", "job_pids", "job_alive_after_close")}, indent=1))
