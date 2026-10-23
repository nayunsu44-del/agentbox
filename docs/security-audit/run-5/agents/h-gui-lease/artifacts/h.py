"""h-gui-lease harness: GUI burst opened while a human takeover lease is held (fakes only, no Docker)."""
import threading
import time
import sys

sys.path.insert(0, "/target")
from agentbox.approvals import ApprovalStore
from agentbox.config import Settings
from agentbox.desktop import DesktopControl
from agentbox.policy import Policy
from agentbox.service import AgentBox, ServiceError

BASE = [  # desktop session present before any takeover
    {"pid": 1, "ppid": 0, "sid": 1, "uid": 0, "args": "tini"},
    {"pid": 100, "ppid": 1, "sid": 100, "uid": 1001, "args": "xfce4-session"},
    {"pid": 101, "ppid": 100, "sid": 100, "uid": 1001, "args": "xfce4-panel"},
]
HUMAN = [  # what the human starts during the takeover: terminal window + shell + job inside it
    {"pid": 200, "ppid": 101, "sid": 100, "uid": 1001, "args": "xfce4-terminal"},
    {"pid": 201, "ppid": 200, "sid": 201, "uid": 1001, "args": "bash"},
    {"pid": 202, "ppid": 201, "sid": 201, "uid": 1001, "args": "python3 -m http.server 8000"},
]


class Audit:
    def __init__(self):
        self.rows = []

    def append(self, **row):
        self.rows.append(row)
        return len(self.rows)


class SB:
    def __init__(self, block_snapshot=False):
        self.settings = Settings()
        self.procs = list(BASE)
        self.windows = {100, 101}
        self.manifest = {"a.txt": (1, "1", "1")}
        self.killed = []
        self.snaps = []
        self.clicks = []
        self.block = block_snapshot
        self.entered = threading.Event()
        self.go = threading.Event()

    def get(self, sid):
        return {"id": sid, "container_id": "c1", "status": "running"}

    def _desktop(self, sid):
        return None

    def template_of(self, sid):
        class T:
            desktop = True
        return T()

    def desktop_processes(self, sid):
        return [dict(p) for p in self.procs], set(self.windows)

    def kill_processes(self, sid, pids):
        self.killed += list(pids)

    def workspace_manifest(self, sid):
        return dict(self.manifest), False

    def snapshot(self, sid, reason):
        self.snaps.append(reason)
        if self.block:
            self.entered.set()
            self.go.wait(10)   # stands in for the multi-second docker commit
        return {"id": f"snap_{len(self.snaps)}", "image": "img"}

    def snapshot_count(self, sid):
        return len(self.snaps)

    def click(self, sid, x, y, button, double):
        self.clicks.append((x, y))
        return {"clicked": [x, y]}

    def list_dir(self, sid, path):
        return {"path": path, "entries": []}

    def exists(self, sid, p):
        return False


def human_acts(sb):
    sb.procs += HUMAN
    sb.windows |= {200}
    sb.manifest["human_notes.txt"] = (5, "2", "2")


def events(box):
    return [(r["event"], r.get("payload", {}).get("reason"), r.get("payload", {}).get("processes"),
             {k: r.get("payload", {}).get(k) for k in ("added", "snapshot_id")} if r["event"] == "gui_changes" else None)
            for r in box.audit.rows if r["event"].startswith(("gui_", "human_", "tool_blocked", "snapshot"))]


def wait_closes(box):
    box.bursts.close_idle(wait=5)
    time.sleep(0.2)


def control():
    print("== control: burst finished before takeover (no race) ==")
    sb = SB()
    box = AgentBox(Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    print("click:", box.call_tool("sb", "click", {"x": 1, "y": 1}).status)
    box.takeover("sb", "hs_1")
    human_acts(sb)
    print("burst open during lease:", "sb" in box.bursts._gui_burst, "lease:", bool(box.desktop.lease("sb")))
    print("agent list_dir:", box.call_tool("sb", "list_dir", {"path": "/workspace"}).status)
    wait_closes(box)
    print("killed:", sb.killed)
    box.bursts._burst_pool.shutdown()


def race_call_tool(close_during_lease=True):
    print(f"== (b) call_tool click races takeover; close_during_lease={close_during_lease} ==")
    sb = SB(block_snapshot=True)
    box = AgentBox(Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", box.call_tool("sb", "click", {"x": 1, "y": 1})))
    t.start()
    assert sb.entered.wait(5)                     # agent passed needs_snapshot, now inside docker commit
    st = box.takeover("sb", "hs_1")               # human takes over; gui_lock is free, no burst to close
    print("takeover ok, lease:", bool(box.desktop.lease("sb")))
    sb.go.set()
    t.join(5)
    print("agent click status:", out["r"].status, out["r"].body.get("status"), "clicks:", sb.clicks)
    b = box.bursts._gui_burst.get("sb")
    print("burst open during lease:", b is not None, "baseline pids:", sorted(b["pids"]) if b else None,
          "snapshot:", b and b["snapshot_id"])
    human_acts(sb)
    if close_during_lease:
        r = box.call_tool("sb", "list_dir", {"path": "/workspace"})   # any agent tool call runs close_idle
        print("agent list_dir:", r.status, "lease still held:", bool(box.desktop.lease("sb")))
        wait_closes(box)
    else:
        box.handback("sb", "hs_1")
        print("handback done; human's shell/job still running; agent clicks again")
        r = box.call_tool("sb", "click", {"x": 2, "y": 2})
        print("agent click:", r.status)
        wait_closes(box)
    print("killed:", sb.killed)
    for e in events(box):
        print("  ", e)
    box.bursts._burst_pool.shutdown()


def race_decide():
    print("== (a) decide() approves a pending click while the lease is held ==")
    sb = SB()
    pol = Policy({"default": "allow", "rules": [{"id": "gui-approval", "tool": "click", "action": "require_approval"}]})
    box = AgentBox(Audit(), pol, sb, approvals=ApprovalStore("/scratch/a.db"), desktop=DesktopControl())
    box.takeover("sb", "hs_1")
    r = box.call_tool("sb", "click", {"x": 9, "y": 9})       # agent queues a click during the lease
    print("agent click during lease:", r.status, r.body.get("status"))
    aid = r.body["approval_id"]
    res = box.decide(aid, True, actor="human")
    print("decide ->", res["status"], "snapshots:", sb.snaps, "clicks:", sb.clicks)
    b = box.bursts._gui_burst.get("sb")
    print("burst open during lease:", b is not None, "baseline:", sorted(b["pids"]) if b else None)
    human_acts(sb)
    import urllib  # noqa
    # agent triggers close_idle with any tool call (GET /approvals/{aid} -> expire_stale does the same)
    box.expire_stale()
    wait_closes(box)
    print("lease still held:", bool(box.desktop.lease("sb")), "killed:", sb.killed)
    for e in events(box):
        print("  ", e)
    box.bursts._burst_pool.shutdown()


control()
race_call_tool(True)
race_call_tool(False)
race_decide()
