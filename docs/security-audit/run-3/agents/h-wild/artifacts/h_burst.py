"""Bounded harness: GUI burst state after a sandbox restore (no Docker; fake SandboxManager).

Compares (A) a normal GUI burst, where a stray uid-1001 process started mid-burst is killed at burst
close, with (B) the same agent activity right after the human restores the sandbox (api.py restore ->
box.end_desktop(sid, "sandbox_restored") -> sandboxes.restore).
"""
import json
import sys
import time as _time
from pathlib import Path

sys.path.insert(0, "/target")

import agentbox.service as S  # noqa: E402
from agentbox.approvals import ApprovalStore  # noqa: E402
from agentbox.audit import AuditLog  # noqa: E402
from agentbox.config import Settings  # noqa: E402
from agentbox.desktop import DesktopControl  # noqa: E402
from agentbox.policy import Policy  # noqa: E402

CLOCK = [1000.0]
S.time.monotonic = lambda: CLOCK[0]   # service and desktop share the time module


class Tpl:
    desktop = True


class FakeSB:
    def __init__(self, settings):
        self.settings = settings
        self.runtime = "runc"
        self.snaps = []
        self.killed = []
        self.paused = False
        self.fresh()

    def fresh(self):
        # new container: init + desktop session
        self.procs = [{"pid": 1, "ppid": 0, "sid": 1, "uid": 0, "args": "docker-init"},
                      {"pid": 10, "ppid": 1, "sid": 10, "uid": 1001, "args": "xfce4-session"}]
        self.files = {"report.md": (10, "1.0", "1.0")}

    def get(self, sid):
        return {"id": sid}

    def template_of(self, sid):
        return Tpl()

    def snapshot_count(self, sid):
        return len(self.snaps)

    def snapshot(self, sid, reason="manual"):
        sid_ = f"snap_{len(self.snaps) + 1}"
        self.snaps.append(sid_)
        return {"id": sid_, "image": "agentbox-snap:" + sid_}

    def workspace_manifest(self, sid):
        if self.paused:   # sandbox.py uses _container(): docker refuses exec in a paused container (409 APIError)
            raise RuntimeError("409 Conflict: container is paused, unpause the container before exec")
        return dict(self.files), False

    def desktop_processes(self, sid):
        if self.paused:   # sandbox.py: _desktop() -> _require_running() raises for status 'paused'
            from agentbox.sandbox import SandboxError
            raise SandboxError(f"paused sandbox: {sid}")
        return [dict(p) for p in self.procs], set()

    def kill_processes(self, sid, pids):
        self.killed.extend(pids)
        self.procs = [p for p in self.procs if p["pid"] not in pids]

    def click(self, sid, x, y, button="left", double=False):
        return {"x": x, "y": y}


def make(tag):
    home = Path(f"/scratch/burst-{tag}")
    home.mkdir(parents=True, exist_ok=True)
    db = home / "a.db"
    if db.exists():
        db.unlink()
    st = Settings(home=home)
    st.gui_snapshot_idle, st.gui_snapshot_interval, st.snapshot_quota, st.tool_concurrency = 60, 600, 50, 4
    sb = FakeSB(st)
    box = S.AgentBox(audit=AuditLog(db), policy=Policy.load(st.policy_path), sandboxes=sb,
                     approvals=ApprovalStore(db), desktop=DesktopControl())
    return box, sb


def click(box, t):
    CLOCK[0] = 1000.0 + t
    return box.call_tool("sb_1", "click", {"x": 1, "y": 1}).status


def gui_events(box):
    return [(e["event"], {k: e["payload"].get(k) for k in ("snapshot_id", "reason", "count", "modified", "added")})
            for e in box.audit.list(limit=5000) if e["event"] in ("snapshot", "gui_changes", "gui_processes_stopped")]


out = {}

# ---- A: control, no restore -------------------------------------------------
box, sb = make("A")
click(box, 0)                                  # burst opens (snap_1), baseline {1,10}
sb.procs.append({"pid": 50, "ppid": 1, "sid": 50, "uid": 1001, "args": "setsid sh -c 'while :; do date >> /workspace/report.md; sleep 1; done'"})
sb.files["report.md"] = (99, "2.0", "2.0")
click(box, 10)
CLOCK[0] = 1000.0 + 100
box.close_idle_gui_bursts()                    # idle close
out["A_control"] = {"snapshots": sb.snaps, "killed": sb.killed, "burst_open": "sb_1" in box._gui_burst,
                    "events": gui_events(box)}

# ---- B: same activity right after a human restore --------------------------
box, sb = make("B")
click(box, 0)                                  # burst opens (snap_1)
CLOCK[0] = 1000.0 + 10
box.end_desktop("sb_1", "sandbox_restored")    # what POST /sandboxes/{sid}/restore does first
sb.fresh()                                     # sandboxes.restore(): new container from snap_1
after_restore = {"burst_open": "sb_1" in box._gui_burst,
                 "_gui_input_at_kept": "sb_1" in box._gui_input_at, "_gui_snap_at_kept": "sb_1" in box._gui_snap_at}
snaps_before = list(sb.snaps)
click(box, 20)                                 # first agent GUI input after the restore
gap = {"new_snapshot_on_first_input": sb.snaps != snaps_before, "burst_open": "sb_1" in box._gui_burst}
sb.procs.append({"pid": 60, "ppid": 1, "sid": 60, "uid": 1001, "args": "setsid sh -c 'while :; do date >> /workspace/report.md; sleep 1; done'"})
sb.files["report.md"] = (99, "2.0", "2.0")     # change made during the gap
for t in range(60, 600, 50):                   # agent keeps a GUI input at least every 60 s
    click(box, t)
gap["snapshots_during_gap"] = [s for s in sb.snaps if s not in snaps_before]
click(box, 610)                                # gui_snapshot_interval (600 s) since snap_1 -> new burst
baseline = sorted(box._gui_burst.get("sb_1", {}).get("pids", []))
CLOCK[0] = 1000.0 + 700
box.close_idle_gui_bursts()
out["B_after_restore"] = {"after_end_desktop": after_restore, "gap": gap, "new_burst_baseline_pids": baseline,
                          "snapshots": sb.snaps, "killed": sb.killed,
                          "stray_60_still_running": any(p["pid"] == 60 for p in sb.procs),
                          "events": gui_events(box)}

# ---- C: human pauses the sandbox while a GUI burst is open ------------------
box, sb = make("C")
click(box, 0)                                  # burst opens (snap_1)
sb.procs.append({"pid": 70, "ppid": 1, "sid": 70, "uid": 1001, "args": "setsid sh -c 'while :; do date >> /workspace/report.md; sleep 1; done'"})
sb.files["report.md"] = (99, "2.0", "2.0")
click(box, 10)
sb.paused = True                               # POST /sandboxes/{sid}/pause: log + docker pause, no burst handling
CLOCK[0] = 1000.0 + 100                        # UI audit fragment polls every 3 s -> close_idle_gui_bursts()
box.close_idle_gui_bursts()
during_pause = {"burst_still_tracked": "sb_1" in box._gui_burst, "killed": list(sb.killed)}
sb.paused = False                              # POST /sandboxes/{sid}/resume
CLOCK[0] = 1000.0 + 200
box.close_idle_gui_bursts()
click(box, 210)                                # next agent GUI input after resume -> new burst
baseline = sorted(box._gui_burst.get("sb_1", {}).get("pids", []))
CLOCK[0] = 1000.0 + 400
box.close_idle_gui_bursts()
out["C_pause_during_burst"] = {"during_pause": during_pause, "new_burst_baseline_pids": baseline,
                               "snapshots": sb.snaps, "killed": sb.killed,
                               "stray_70_still_running": any(p["pid"] == 70 for p in sb.procs),
                               "events": gui_events(box)}

print(json.dumps(out, indent=1, ensure_ascii=False))
