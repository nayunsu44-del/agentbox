"""Parent-live check (v09 blocker 1): can the agent, through the approval-free exec allowlist alone, fill the desktop
container's pids cgroup so that a concurrent first GUI input opens a burst with an empty /workspace baseline?
Disposable desktop sandbox, dummy tokens, scratch AGENTBOX_HOME, loopback. Setup of the 300 pre-existing files and the
'GUI-made' change use docker exec (stand-ins for earlier agent work and for a GUI terminal, N-1); the pressure itself
and the GUI input go through box.call_tool as the agent.
"""
import os, sys, tempfile, threading, time
home = tempfile.mkdtemp(prefix="abx-l9-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "a" * 40)
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
_, box, _ = build()
s = box.sandboxes.settings
print("exec_timeout", s.exec_timeout, "| gui idle", s.gui_snapshot_idle)

sb, _ = box.create_sandbox(None, "desktop")
sid = sb["id"]
c = box.sandboxes._container(sid)
box.sandboxes._wait_display(c)
c.exec_run(["sh", "-c", "for i in $(seq 1 300); do echo x > /workspace/f$i.txt; done; chown -R 1000:1000 /workspace"], user="0:0")


def pids():
    c.reload()
    for line in open(f"/proc/{c.attrs['State']['Pid']}/cgroup"):
        _, ctrl, path = line.strip().split(":", 2)
        if "pids" in ctrl.split(","):
            b = f"/sys/fs/cgroup/pids{path}"
            return int(open(b + "/pids.current").read()), int(open(b + "/pids.max").read().strip())


cmd = "tail -f /dev/null & " * 1100 + "tail -f /dev/null"
print("policy:", box.policy.decide("exec", {"command": cmd}).action)
print("pids before:", pids())
res = {}
t = threading.Thread(target=lambda: res.__setitem__("exec", box.call_tool(sid, "exec", {"command": cmd})), daemon=True)
t0 = time.monotonic(); t.start()
peak = (0, 0)
while time.monotonic() - t0 < 25:
    cur = pids(); peak = max(peak, cur)
    if cur[0] >= cur[1] - 2:
        break
    time.sleep(0.5)
print(f"pids at GUI input: {pids()} (peak {peak}) after {time.monotonic() - t0:.1f}s")
out = box.call_tool(sid, "key", {"keys": "shift"})
b = box._gui_burst.get(sid)
print(f"agent GUI input -> {out.status} | burst recorded: {b is not None} | baseline manifest entries: "
      f"{len(b['manifest']) if b else None} | baseline pids: {len(b['pids']) if b else None}")
print("audit events after GUI input:", [e["event"] for e in box.audit.list(sandbox_id=sid, limit=5000)][-4:])
t.join(120)
ex = res.get("exec")
print(f"agent exec returned after {time.monotonic() - t0:.0f}s: status {getattr(ex, 'status', None)} "
      f"exit {(getattr(ex, 'body', {}) or {}).get('result', {}).get('exit_code') if ex else None} | pids now {pids()}")
time.sleep(5)
print("pids 5s after the exec returned (background tails outlive the exec):", pids())
c.exec_run(["pkill", "-x", "tail"], user="0:0")          # parent releases the pressure so the close can be observed
time.sleep(2)
print("pids after release:", pids())
c.exec_run(["sh", "-c", "echo changed > /workspace/zz_changed_by_gui.txt"], user="desktop")
box._close_gui_burst(sid, "test_idle")
ev = [e for e in box.audit.list(sandbox_id=sid, limit=5000) if e["event"] == "gui_changes"]
if ev:
    p = ev[-1]["payload"]
    print(f"gui_changes counts={p['counts']} truncated={p['truncated']} | real change listed: {'zz_changed_by_gui.txt' in p['added']}")
else:
    print("no gui_changes record")
box.sandboxes.delete(sid)
print("done")
