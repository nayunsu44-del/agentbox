"""v11: snapshot-quota TOCTOU probe. Real AgentBox/Policy(default_policy.yaml)/AuditLog/ApprovalStore,
fake SandboxManager whose exists() is a real `test -e`-like stat of a real file under /scratch/ws with a
fixed probe latency standing in for docker exec. No Docker, no network."""
import json, os, random, sys, threading, time
from pathlib import Path

from agentbox.approvals import ApprovalStore
from agentbox.audit import AuditLog
from agentbox.config import Settings
from agentbox.policy import Policy
from agentbox.service import AgentBox
import agentbox; assert "/scratch/fixed" in agentbox.__file__, agentbox.__file__

WS = Path("/scratch/ws")
PROBE_LAT = 0.02   # seconds per docker-exec-like probe


class FakeSB:
    def __init__(self, quota):
        self.settings = Settings()
        self.settings.snapshot_quota = quota
        self.settings.tool_concurrency = 4
        self.snaps = [{"id": f"pre{i}"} for i in range(quota)]   # already at quota
        self.lock = threading.Lock()
        self.commits_over_quota = 0
        self.exists_calls = 0

    def get(self, sid): return {"id": sid, "status": "running", "container_id": "c1", "template": "cli"}
    def template_of(self, sid):
        class T: desktop = False
        return T()
    def snapshot_count(self, sid):
        with self.lock: return len(self.snaps)
    def exists(self, sid, path):
        self.exists_calls += 1
        time.sleep(PROBE_LAT / 2)
        r = (WS / Path(path).name).exists()
        time.sleep(PROBE_LAT / 2)
        return r
    def snapshot(self, sid, reason="manual"):
        with self.lock:
            if len(self.snaps) >= self.settings.snapshot_quota:
                self.commits_over_quota += 1
            s = {"id": f"snap{len(self.snaps)}", "image": f"img{len(self.snaps)}", "reason": reason}
            self.snaps.append(s)
        return s
    def write_file(self, sid, path, content):
        (WS / Path(path).name).write_text(content); return {"path": path, "bytes": len(content)}
    def exec(self, sid, command):
        parts = command.split()
        assert parts[0] == "touch"
        time.sleep(PROBE_LAT)          # docker exec latency
        (WS / Path(parts[1]).name).touch()
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}
    def preview(self, sid, command): return {"command": command, "affected": [], "notes": []}


def make(tag, quota=2):
    d = Path("/scratch/db") / tag
    d.mkdir(parents=True, exist_ok=True)
    pol = Policy.load(Path(agentbox.__file__).parent / "default_policy.yaml")
    sb = FakeSB(quota)
    box = AgentBox(AuditLog(d / "audit.db"), pol, sb, ApprovalStore(d / "appr.db"))
    return box, sb


def tally(box, sb, outs):
    from collections import Counter
    rows = box.audit.conn.execute("SELECT event FROM audit").fetchall() if hasattr(box.audit, "conn") else []
    return {"statuses": dict(Counter(o for o in outs)), "commits_while_over_quota": sb.commits_over_quota,
            "pending_approvals": len(box.approvals.list(status="pending", sandbox_id="sb1")),
            "snapshot_rows_after": len(sb.snaps), "audit_events": dict(Counter(r[0] for r in rows))}


def reset_ws():
    WS.mkdir(parents=True, exist_ok=True)
    for f in WS.iterdir(): f.unlink()


out = {"probe_latency_s": PROBE_LAT}
pol = Policy.load(Path(agentbox.__file__).parent / "default_policy.yaml")
out["policy"] = {"write_file": pol.decide("write_file", {"path": "/workspace/x", "content": "a"}).as_dict(),
                 "exec_touch": pol.decide("exec", {"command": "touch /workspace/p1"}).as_dict()}

# Control: path stable-existing -> must be 202 snapshot-quota, 0 commits
reset_ws(); (WS / "stable").write_text("x")
box, sb = make("control")
o = box.call_tool("sb1", "write_file", {"path": "/workspace/stable", "content": "y"})
out["control_existing"] = {"status": o.status, "rule": o.body.get("status"), **tally(box, sb, [o.status])}

# A: real background toggler (models an in-container loop: create/delete a file continuously)
reset_ws()
box, sb = make("toggler")
stop = threading.Event()
def toggler():
    p = WS / "t"
    while not stop.is_set():
        p.touch(); time.sleep(random.uniform(0.002, 0.02))
        try: p.unlink()
        except FileNotFoundError: pass
        time.sleep(random.uniform(0.002, 0.02))
th = threading.Thread(target=toggler, daemon=True); th.start()
outs = []
for i in range(40):
    try:
        o = box.call_tool("sb1", "write_file", {"path": "/workspace/t", "content": str(i)})
        outs.append(o.status)
    except Exception as e:
        outs.append(type(e).__name__ + ":" + str(getattr(e, "status", "")))
stop.set(); th.join()
out["A_background_toggler_40_calls"] = tally(box, sb, outs)

# B: concurrent agent-token exec 'touch /workspace/pN' (allowlisted, not snap-locked) alongside write_file,
# sweeping the attacker-chosen start offset of the exec relative to the write_file call
for off_ms in (-15, -10, -5, 0, 5):
    reset_ws()
    box, sb = make(f"exec_touch_{off_ms}")
    outs = []
    for i in range(20):
        path = f"/workspace/p{i}"
        res = {}
        def w(): res["w"] = box.call_tool("sb1", "write_file", {"path": path, "content": "z"}).status
        def t(): res["t"] = box.call_tool("sb1", "exec", {"command": f"touch {path}"}).status
        first, second, delay = (t, w, -off_ms / 1000) if off_ms < 0 else (w, t, off_ms / 1000)
        a, b = threading.Thread(target=first), threading.Thread(target=second)
        a.start(); time.sleep(delay); b.start(); a.join(); b.join()
        outs.append(res.get("w"))
    out[f"B_exec_touch_offset_{off_ms}ms_20_pairs"] = tally(box, sb, outs)

json.dump(out, sys.stdout, indent=1, default=str)
print()
