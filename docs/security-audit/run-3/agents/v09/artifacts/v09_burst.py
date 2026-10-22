"""v09 mock harness: GUI-burst bookkeeping failure modes (no Docker; fakes only)."""
import sys, time, types
sys.path.insert(0, "/target")
from agentbox import service as S
from agentbox import sandbox as SB

class FakeAudit:
    def __init__(self): self.ev = []
    def append(self, actor, event, sandbox_id=None, tool=None, payload=None):
        self.ev.append((event, tool, payload)); return len(self.ev)

class Settings:
    gui_snapshot_interval = 300; gui_snapshot_idle = 30; snapshot_quota = 50

def make_box(sb):
    box = object.__new__(S.AgentBox)
    box.audit = FakeAudit(); box.sandboxes = sb
    box.desktop = types.SimpleNamespace(lease=lambda sid: None, is_stale=lambda sid: False)
    box._gui_input_at = {}; box._gui_snap_at = {}; box._gui_burst = {}
    return box

# ---------------- Case 1: collection raises at burst open (except at service.py:210) -------------
class RaisingSB:
    settings = Settings()
    def __init__(self): self.calls = []; self.raise_open = True
    def snapshot(self, sid, reason): return {"id": "snap_1", "image": "img"}
    def workspace_manifest(self, sid):
        self.calls.append("manifest")
        if self.raise_open: raise SB.SandboxError("simulated collection failure")
        return {"a": (1, "1", "1"), "evil.txt": (5, "2", "2")}, False
    def desktop_processes(self, sid):
        self.calls.append("ps")
        return [{"pid": 50, "ppid": 1, "sid": 40, "uid": 1001, "args": "xfce4-session"},
                {"pid": 900, "ppid": 1, "sid": 900, "uid": 1001, "args": "sh -c 'while :; do touch /workspace/evil.txt; done'"}], set()
    def kill_processes(self, sid, pids): self.calls.append(("kill", list(pids)))

print("== Case 1: workspace_manifest raises at burst open ==")
sb = RaisingSB(); box = make_box(sb); sid = "sb_x"
box._gui_input_at[sid] = time.monotonic()
box._snapshot(sid, "key", "before key", {"request": 1})
print("burst recorded:", sid in box._gui_burst)
print("audit events:", [e[0] for e in box.audit.ev])
sb.raise_open = False
box._gui_input_at[sid] = time.monotonic()
print("next GUI input needs snapshot (new burst)?:", box._gui_needs_snapshot(sid))
box._gui_input_at[sid] = time.monotonic() - 31   # burst would now be idle
box.close_idle_gui_bursts()
print("after idle close: kill calls:", [c for c in sb.calls if isinstance(c, tuple)],
      "| events:", [e[0] for e in box.audit.ev])

# ---------------- Case 2: real SandboxManager collectors with a failing exec (nonzero exit) --------
class ExecResult:
    def __init__(self, code, out): self.exit_code = code; self.output = out
class FailingContainer:
    def exec_run(self, argv, user=None, environment=None, demux=False, **kw):
        # simulate fork failure inside the container: command exits nonzero, no stdout
        return ExecResult(126, (None, b"sh: Cannot fork") if demux else b"")
sm = object.__new__(SB.SandboxManager)
sm._container = lambda sid: FailingContainer(); sm._desktop = lambda sid: FailingContainer()
print("\n== Case 2: SandboxManager collectors when the in-container command fails (exit 126, no stdout) ==")
for name in ("workspace_manifest", "desktop_processes"):
    try: print(f"{name} ->", getattr(sm, name)("sb_x"), "(no exception)")
    except Exception as e: print(f"{name} RAISED", type(e).__name__, e)
try: print("kill_processes ->", sm.kill_processes("sb_x", [900]), "(no exception, exit status ignored)")
except Exception as e: print("kill_processes RAISED", e)

print("\n== Case 3: degraded baseline (empty manifest) then real change; human-visible gui_changes ==")
old = {}
new = {f"f{i}.txt": (2, "1", "1") for i in range(1, 301)}
new["zz_changed_by_gui.txt"] = (8, "9", "9")
burst = {"snapshot_id": "snap_2", "manifest": old, "truncated": False, "pids": {50}}
class SB3(RaisingSB):
    def workspace_manifest(self, sid): return new, False
sb3 = SB3(); box3 = make_box(sb3); box3._gui_burst[sid] = burst
box3._close_gui_burst(sid, "idle")
gc = [e for e in box3.audit.ev if e[0] == "gui_changes"][-1][2]
print("counts:", gc["counts"], "truncated:", gc["truncated"], "listed added:", len(gc["added"]),
      "| real change listed:", "zz_changed_by_gui.txt" in gc["added"])
print("control (correct baseline):")
box4 = make_box(SB3()); box4._gui_burst[sid] = {**burst, "manifest": {k: v for k, v in new.items() if k.startswith("f")}}
box4._close_gui_burst(sid, "idle")
gc = [e for e in box4.audit.ev if e[0] == "gui_changes"][-1][2]
print("counts:", gc["counts"], "added:", gc["added"])
