"""v12 independent harness: GUI burst state vs. sandbox restore / pause.

Real AgentBox (service.py), AuditLog, ApprovalStore, Policy (default_policy.yaml), DesktopControl and the
real gui_strays; only SandboxManager is faked (no Docker). Time is driven by patching time.monotonic.
Fake rules mirror source: desktop_processes/click raise when paused (sandbox.py _require_running 466-469);
workspace_manifest raises when paused (Docker refuses exec in a paused container -> APIError).
"""
import json
import sys
import time
import types

sys.path.insert(0, "/target")
from agentbox import service as S  # noqa: E402
from agentbox.approvals import ApprovalStore  # noqa: E402
from agentbox.audit import AuditLog  # noqa: E402
from agentbox.desktop import DesktopControl  # noqa: E402
from agentbox.policy import Policy  # noqa: E402
from agentbox.sandbox import SandboxError  # noqa: E402

CLOCK = [10000.0]
time.monotonic = lambda: CLOCK[0]
SID = "sb_v12"


def desktop_session(pids):
    """pid 1 root start script, Xvfb, xfce4-session, panel (windowed) - all in session 1."""
    x, sess, panel = pids
    procs = [
        {"pid": 1, "ppid": 0, "sid": 1, "uid": 0, "args": "sleep infinity"},
        {"pid": x, "ppid": 1, "sid": 1, "uid": 1001, "args": "Xvfb :0"},
        {"pid": sess, "ppid": 1, "sid": 1, "uid": 1001, "args": "xfce4-session"},
        {"pid": panel, "ppid": sess, "sid": 1, "uid": 1001, "args": "xfce4-panel"},
    ]
    return procs, {panel}


class FakeSB:
    def __init__(self):
        self.settings = types.SimpleNamespace(gui_snapshot_idle=60, gui_snapshot_interval=600,
                                              snapshot_quota=50, tool_concurrency=4)
        self.status = "running"
        self.container = 1
        self.procs, self.wins = desktop_session((10, 11, 12))
        self.files = {"report.md": (5, "1.0", "1.0")}
        self.snaps = []
        self.killed = []
        self.clicks = 0

    # records
    def get(self, sid):
        return {"id": sid, "status": self.status, "container_id": f"c{self.container}"}

    def template_of(self, sid):
        return types.SimpleNamespace(desktop=True)

    def snapshot_count(self, sid):
        return len(self.snaps)

    def exists(self, sid, p):
        return False

    def snapshot(self, sid, reason="manual"):
        sid_ = f"snap_{len(self.snaps) + 1}"
        self.snaps.append({"id": sid_, "container": self.container, "files": dict(self.files)})
        return {"id": sid_, "image": f"agentbox-snap:{sid}-{sid_}"}

    def workspace_manifest(self, sid):
        if self.status == "paused":
            raise SandboxError("409 Container is paused, unpause the container before exec")
        return dict(self.files), False

    def desktop_processes(self, sid):
        if self.status == "paused":  # sandbox.py:688 -> _desktop -> _require_running:468-469
            raise SandboxError(f"일시정지된 샌드박스: {sid}")
        return [dict(p) for p in self.procs], set(self.wins)

    def kill_processes(self, sid, pids):
        if pids:
            self.killed.extend(pids)
            self.procs = [p for p in self.procs if p["pid"] not in pids]

    def click(self, sid, x, y, button, double):
        if self.status == "paused":
            raise SandboxError(f"일시정지된 샌드박스: {sid}")
        self.clicks += 1
        return {"clicked": [x, y]}

    # lifecycle (what sandboxes.restore/pause/resume change; no burst bookkeeping, as in source)
    def restore(self, snap_id, new_pids=(10, 11, 12)):
        snap = next(s for s in self.snaps if s["id"] == snap_id)
        self.container += 1
        self.files = dict(snap["files"])
        self.procs, self.wins = desktop_session(new_pids)
        self.status = "running"

    # attacker-side effects inside the container (uid 1001 via the GUI, e.g. terminal -> setsid loop)
    def spawn_stray(self, pid):
        self.procs.append({"pid": pid, "ppid": 1, "sid": pid, "uid": 1001,
                           "args": "bash -c while :; do echo x >> /workspace/report.md; sleep 5; done"})

    def touch(self, name, t):
        size = self.files.get(name, (0,))[0] + 1
        self.files[name] = (size, str(t), str(t))


def make(tmp):
    sb = FakeSB()
    box = S.AgentBox(AuditLog(f"{tmp}/audit.db"), Policy.load("/target/agentbox/default_policy.yaml"), sb,
                     ApprovalStore(f"{tmp}/appr.db"), DesktopControl())
    return box, sb


def at(t):
    CLOCK[0] = 10000.0 + t


def click(box, t):
    at(t)
    out = box.call_tool(SID, "click", {"x": 5, "y": 5}, actor="agent")
    return out.status


def gui_events(box):
    rows = box.audit.list(sandbox_id=SID, limit=5000)
    keep = []
    for r in rows:
        if r["event"] in ("snapshot", "gui_processes_stopped", "gui_changes"):
            p = r["payload"] if isinstance(r["payload"], dict) else json.loads(r["payload"])
            keep.append({"event": r["event"], "snapshot_id": p.get("snapshot_id"), "reason": p.get("reason"),
                         "pids": [x["pid"] for x in p.get("processes", [])] or None,
                         "modified": p.get("modified")})
    return keep


def alive(sb, pid):
    return any(p["pid"] == pid for p in sb.procs)


def run(name, fn):
    import tempfile
    with tempfile.TemporaryDirectory(dir="/scratch") as tmp:
        box, sb = make(tmp)
        res = fn(box, sb)
        res["snapshots"] = [s["id"] for s in sb.snaps]
        res["killed"] = sb.killed
        res["audit_gui_events"] = gui_events(box)
        box.audit.conn.close()
        box.approvals.conn.close()
        return name, res


def scen_control(box, sb):
    r = {}
    r["t0_click"] = click(box, 0)
    r["baseline"] = sorted(box._gui_burst[SID]["pids"])
    at(5); sb.spawn_stray(50); sb.touch("report.md", 5)
    r["t10_click"] = click(box, 10)
    at(100); box.close_idle_gui_bursts()
    r["stray_50_alive"] = alive(sb, 50)
    return r


def scen_restore(box, sb, clear_timers=False):
    r = {}
    click(box, 0)
    at(10)
    box.end_desktop(SID, "sandbox_restored")          # api.py:192 / web.py:243
    sb.restore("snap_1")                               # api.py:193 sandboxes.restore
    if clear_timers:                                   # proposed fix, for comparison only
        box._gui_input_at.pop(SID, None); box._gui_snap_at.pop(SID, None)
    r["after_restore"] = {"burst_open": SID in box._gui_burst,
                          "input_at_kept": SID in box._gui_input_at, "snap_at_kept": SID in box._gui_snap_at}
    n = len(sb.snaps)
    r["t20_click"] = click(box, 20)
    r["t20_snapshot_taken"] = len(sb.snaps) > n
    r["t20_burst_open"] = SID in box._gui_burst
    at(25); sb.spawn_stray(60); sb.touch("report.md", 25)
    n = len(sb.snaps)
    r["t70_click"] = click(box, 70)
    r["t70_snapshot_taken"] = len(sb.snaps) > n
    at(150); box.close_idle_gui_bursts()               # e.g. /ui/audit poll
    r["t200_click"] = click(box, 200)
    r["t200_baseline"] = sorted(box._gui_burst[SID]["pids"]) if SID in box._gui_burst else None
    at(300); box.close_idle_gui_bursts()
    r["stray_60_alive"] = alive(sb, 60)
    return r


def scen_pause(box, sb):
    r = {}
    click(box, 0)
    at(5); sb.spawn_stray(70); sb.touch("report.md", 5)
    click(box, 10)
    at(20); sb.status = "paused"                       # api.py:166-170: log + sandboxes.pause only
    at(100); box.close_idle_gui_bursts()               # /ui/audit poll every 3 s (web.py:261)
    r["burst_open_after_idle_close_while_paused"] = SID in box._gui_burst
    r["killed_during_pause"] = list(sb.killed)
    at(200); sb.status = "running"                     # resume
    r["stray_70_alive_after_resume"] = alive(sb, 70)
    r["t210_click"] = click(box, 210)
    r["t210_baseline"] = sorted(box._gui_burst[SID]["pids"]) if SID in box._gui_burst else None
    at(400); box.close_idle_gui_bursts()
    r["stray_70_alive"] = alive(sb, 70)
    return r


def scen_stale(box, sb, new_pids):
    """Parent lead: a burst opened on the old container after end_desktop survives the container swap."""
    r = {}
    click(box, 0)
    at(1000); box.close_idle_gui_bursts()
    at(1001); box.end_desktop(SID, "sandbox_restored")
    r["click_between_end_desktop_and_swap"] = click(box, 1002)   # race window: old container still present
    r["baseline_old_container"] = sorted(box._gui_burst[SID]["pids"])
    at(1003); sb.restore("snap_1", new_pids=new_pids)
    r["new_container_pids"] = [p["pid"] for p in sb.procs]
    at(1100); box.close_idle_gui_bursts()
    r["new_desktop_survivors"] = [p["pid"] for p in sb.procs if p["uid"] == 1001]
    return r


out = dict([
    run("A_control", scen_control),
    run("B_restore", scen_restore),
    run("B_restore_with_timers_cleared_fix_check", lambda b, s: scen_restore(b, s, clear_timers=True)),
    run("C_pause", scen_pause),
    run("D_stale_baseline_new_pids", lambda b, s: scen_stale(b, s, (14, 15, 16))),
    run("D_stale_baseline_same_pids", lambda b, s: scen_stale(b, s, (10, 11, 12))),
])
txt = json.dumps(out, indent=1, ensure_ascii=False)
print(txt)
with open("/scratch/v12_burst.out", "w") as f:
    f.write(txt + "\n")
