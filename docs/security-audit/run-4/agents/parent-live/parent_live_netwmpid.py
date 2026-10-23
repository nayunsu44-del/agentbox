"""parent-live N4: does a forged _NET_WM_PID spare a headless uid-1001 writer from the GUI-burst stray kill?

Runs the audited control plane in-process against the real Docker engine and a live agentbox-desktop:0.1
sandbox. The writer was placed in the burst-start session (sid 1) by an xfce custom keyboard shortcut
(xfconf-query + key press, spawned by the baseline xfsettingsd), and netwmpid_forge.py mapped a 1x1
window whose _NET_WM_PID names the writer. Baseline = every pid except the writer family and the forger,
i.e. the state when the burst opened before the shortcut was pressed.

usage: python3 parent_live_netwmpid.py <src-audited> <home> <sid> <writer-pid> <out.json>
"""
import json, os, sys, time
SRC, HOME, SID, WRITER, OUT = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
sys.path.insert(0, SRC)
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40, AGENTBOX_IMAGE="buildpack-deps:noble-curl")
from agentbox.api import build
from agentbox.config import Settings
from agentbox.gui_state import gui_strays
app, box, human = build(Settings())
sb = box.sandboxes
procs, wins = sb.desktop_processes(SID)
by = {p["pid"]: p for p in procs}
def family(pid):
    out = {pid}
    changed = True
    while changed:
        changed = False
        for p in procs:
            if p["ppid"] in out and p["pid"] not in out:
                out.add(p["pid"]); changed = True
    return out
forgers = {p["pid"] for p in procs if "forge.py" in p["args"]}
baseline = {p["pid"] for p in procs} - family(WRITER) - forgers
res = {"writer": by.get(WRITER), "writer_in_window_pids": WRITER in wins, "window_pids": sorted(wins),
       "forger_pids": sorted(forgers)}
res["control_kill_list_without_forged_window"] = gui_strays(procs, wins - {WRITER}, baseline)
kill = gui_strays(procs, wins, baseline)
res["kill_list_with_forged_window"] = kill
res["writer_spared"] = WRITER not in kill
sb.kill_processes(SID, kill)
time.sleep(5)
procs2, _ = sb.desktop_processes(SID)
res["writer_alive_after_kill"] = any(p["pid"] == WRITER for p in procs2)
c = sb._desktop(SID)
r1 = c.exec_run(["sh", "-c", "tail -1 /workspace/_v05_probe"]).output.decode().strip()
time.sleep(5)
r2 = c.exec_run(["sh", "-c", "tail -1 /workspace/_v05_probe"]).output.decode().strip()
res["probe_mtime_advances"] = {"before": r1, "after_5s": r2, "advanced": r2 > r1}
open(OUT, "w").write(json.dumps(res, indent=1) + "\n")
print(json.dumps({k: res[k] for k in ("writer_in_window_pids", "writer_spared", "writer_alive_after_kill", "probe_mtime_advances")}))
print("control kill list contains writer:", WRITER in res["control_kill_list_without_forged_window"])
