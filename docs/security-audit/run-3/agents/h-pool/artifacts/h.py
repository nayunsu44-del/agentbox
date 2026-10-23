"""Mocked, bounded harness (no Docker, no network).

Check 1: AgentBox.call_tool for sandbox A runs close_idle_gui_bursts() for every
sandbox before A's concurrency check, so slow per-sandbox close work for sandbox B
(manifest/ps execs that have no deadline in sandbox.py) runs on A's thread, outside
B's tool_concurrency budget. The slowness is simulated with a 0.5 s sleep in a stub.

Check 2: snapshot quota under 8 concurrent write_file calls on one sandbox stays at
the quota (the check and the snapshot both run under _snap_locks).
"""
import sys, threading, time, types
sys.path.insert(0, "/target")

from agentbox import service as S
from agentbox.config import Settings
from agentbox.policy import ALLOW, Decision

SLOW = 0.5


class Audit:
    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()

    def append(self, **kw):
        with self.lock:
            self.n += 1
            return self.n


class Policy:
    def decide(self, tool, args):
        return Decision(ALLOW, "test-allow", "allowed in harness", None)


class Approvals:
    def list(self, status=None, sandbox_id=None):
        return []

    def create(self, **kw):
        return {"id": "apr_test"}


class Desktop:
    def lease(self, sid):
        return None

    def is_stale(self, sid):
        return False


class Sandboxes:
    def __init__(self, quota):
        self.settings = types.SimpleNamespace(snapshot_quota=quota, gui_snapshot_idle=60,
                                              gui_snapshot_interval=600, tool_concurrency=4)
        self.snaps = {}
        self.lock = threading.Lock()
        self.manifest_calls = []

    def get(self, sid):
        return {"id": sid}

    def workspace_manifest(self, sid):
        self.manifest_calls.append((sid, threading.current_thread().name))
        time.sleep(SLOW)  # stands in for an untimed docker exec in another sandbox
        return {}, False

    def desktop_processes(self, sid):
        return [], set()

    def kill_processes(self, sid, pids):
        pass

    def exists(self, sid, p):
        return True

    def snapshot_count(self, sid):
        with self.lock:
            return self.snaps.get(sid, 0)

    def snapshot(self, sid, reason=""):
        time.sleep(0.05)
        with self.lock:
            self.snaps[sid] = self.snaps.get(sid, 0) + 1
            return {"id": f"snap{self.snaps[sid]}", "image": "x"}

    def write_file(self, sid, path, content):
        return {"path": path, "bytes": len(content), "sha256": "0"}

    def list_dir(self, sid, path):
        return {"path": path, "listing": ""}


def box(quota=50):
    sb = Sandboxes(quota)
    b = S.AgentBox(audit=Audit(), policy=Policy(), sandboxes=sb, approvals=Approvals(), desktop=Desktop())
    return b, sb


print("== check 1: cross-sandbox burst close runs on another sandbox's call ==")
b, sb = box()
# Sandbox B has an open GUI burst whose last input is older than gui_snapshot_idle.
b._gui_burst["sbB"] = {"snapshot_id": "s", "manifest": {}, "truncated": False, "pids": set()}
b._gui_input_at["sbB"] = time.monotonic() - 1000
t0 = time.monotonic()
threading.current_thread().name = "sbA-request"
out = b.call_tool("sbA", "list_dir", {"path": "/workspace"})
dt = time.monotonic() - t0
print("sbA list_dir status", out.status, "elapsed %.2fs" % dt)
print("manifest calls (sid, thread):", sb.manifest_calls)
print("busy counters after:", b._busy)

print("== check 1b: same close runs in the human expire_stale path ==")
b, sb = box()
b._gui_burst["sbB"] = {"snapshot_id": "s", "manifest": {}, "truncated": False, "pids": set()}
b._gui_input_at["sbB"] = time.monotonic() - 1000
threading.current_thread().name = "human-request"
t0 = time.monotonic()
b.expire_stale()
print("expire_stale elapsed %.2fs" % (time.monotonic() - t0), "manifest calls:", sb.manifest_calls)

print("== check 2: snapshot quota under concurrency ==")
b, sb = box(quota=3)
res = []


def w(i):
    try:
        res.append(b.call_tool("sbC", "write_file", {"path": f"/workspace/f{i}", "content": "x"}).status)
    except S.ServiceError as e:
        res.append(e.status)


ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
[t.start() for t in ts]
[t.join() for t in ts]
print("statuses:", sorted(res))
print("snapshots taken:", sb.snaps.get("sbC"), "quota 3")
