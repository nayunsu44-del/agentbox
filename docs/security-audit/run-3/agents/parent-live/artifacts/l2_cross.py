"""Parent-live check: does sandbox B's idle GUI burst close block sandbox A's tool call / a human audit read when B's X server is unresponsive?"""
import os, sys, tempfile, threading, time
os.environ.update(AGENTBOX_HOME=tempfile.mkdtemp(prefix="abx-l2-"), AGENTBOX_HUMAN_TOKEN="hum_" + "e" * 40,
                  AGENTBOX_GUI_SNAPSHOT_IDLE="1")
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
_, box, _ = build()
b, _ = box.create_sandbox(None, "desktop"); a, _ = box.create_sandbox(None, "cli")
B, A = b["id"], a["id"]
cb = box.sandboxes._container(B); box.sandboxes._wait_display(cb)
print("B click:", box.call_tool(B, "click", {"x": 5, "y": 5}).status, "burst open:", B in box._gui_burst)
xvfb = cb.exec_run(["pgrep", "-u", "desktop", "-x", "Xvfb"]).output.decode().split()[0]
cb.exec_run(["kill", "-STOP", xvfb], user="desktop")
time.sleep(2)  # B's burst is now idle
r = {}
t0 = time.monotonic()
t = threading.Thread(target=lambda: r.__setitem__("a", box.call_tool(A, "list_dir", {"path": "/workspace"})), daemon=True)
t.start(); t.join(20)
print("A list_dir returned within 20s:", not t.is_alive(), "elapsed %.1f" % (time.monotonic() - t0))
cb.exec_run(["kill", "-CONT", xvfb], user="desktop"); t.join(30)
print("after SIGCONT: A done:", not t.is_alive(), "elapsed %.1f" % (time.monotonic() - t0))
for s in (A, B): box.sandboxes.delete(s)
