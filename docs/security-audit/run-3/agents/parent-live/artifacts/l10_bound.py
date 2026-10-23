"""Parent-live check (v10/v11 bound): with the sandbox X server stopped, how long does an agent GUI call hold
gui_lock (and so block a human takeover), and how long does an unrelated sandbox's tool call wait behind an idle
burst close? Measured up to 150 s. The X server is stopped by the desktop user (uid 1001), the account that the
agent reaches through GUI tools (N-1: e.g. a terminal opened with Ctrl+Alt+T running `kill -STOP $(pgrep -x Xvfb)`);
the parent stands in for that GUI step with docker exec as uid 1001. Disposable sandboxes, dummy tokens, loopback.
"""
import os, sys, tempfile, threading, time
home = tempfile.mkdtemp(prefix="abx-l10-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "f" * 40, AGENTBOX_GUI_SNAPSHOT_IDLE="5")
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
_, box, _ = build()
LIMIT = 150


def desktop():
    sb, _ = box.create_sandbox(None, "desktop")
    c = box.sandboxes._container(sb["id"])
    box.sandboxes._wait_display(c)
    return sb["id"], c


def timed(label, fn, res):
    t0 = time.monotonic()
    try:
        out = fn()
        res[label] = ("returned", getattr(out, "status", out if not isinstance(out, dict) else "ok"), time.monotonic() - t0)
    except BaseException as e:
        res[label] = ("raised " + type(e).__name__ + ": " + str(e)[:80], None, time.monotonic() - t0)


# --- A: takeover behind a stuck agent screenshot (v10)
sid, c = desktop()
xvfb = c.exec_run(["pgrep", "-u", "desktop", "-x", "Xvfb"]).output.decode().split()[0]
c.exec_run(["kill", "-STOP", xvfb], user="desktop")
res = {}
t1 = threading.Thread(target=timed, args=("screenshot", lambda: box.call_tool(sid, "screenshot", {}), res), daemon=True)
t1.start(); time.sleep(2)
pub = box.desktop.new_session("*")[1]
t2 = threading.Thread(target=timed, args=("takeover", lambda: box.takeover(sid, pub), res), daemon=True)
t0 = time.monotonic(); t2.start()
t2.join(LIMIT); t1.join(1)
print(f"A: after {time.monotonic() - t0:.0f}s with Xvfb stopped: screenshot {res.get('screenshot', 'still blocked')} | "
      f"takeover {res.get('takeover', 'still blocked')}")
c.exec_run(["kill", "-CONT", xvfb], user="desktop")
t1.join(30); t2.join(30)
print(f"A: after SIGCONT: screenshot {res.get('screenshot')} | takeover {res.get('takeover')}")
try:
    box.handback(sid, pub, "test")
except Exception:
    pass

# --- B: unrelated sandbox's tool call behind an idle burst close of the stuck sandbox (v11)
sid_a, ca = desktop()
box.call_tool(sid, "key", {"keys": "shift"})            # opens a burst on the stuck-to-be sandbox
print("B: burst open on victim-owner sandbox:", sid in box._gui_burst)
c.exec_run(["kill", "-STOP", xvfb], user="desktop")
time.sleep(7)                                          # burst idle (> AGENTBOX_GUI_SNAPSHOT_IDLE=5)
res = {}
t3 = threading.Thread(target=timed, args=("other_list_dir", lambda: box.call_tool(sid_a, "list_dir", {"path": "/workspace"}), res), daemon=True)
t0 = time.monotonic(); t3.start(); t3.join(LIMIT)
print(f"B: unrelated sandbox list_dir after {time.monotonic() - t0:.0f}s: {res.get('other_list_dir', 'still blocked')}")
c.exec_run(["kill", "-CONT", xvfb], user="desktop")
t3.join(30)
print(f"B: after SIGCONT: {res.get('other_list_dir')}")
box.sandboxes.delete(sid); box.sandboxes.delete(sid_a)
print("done")
