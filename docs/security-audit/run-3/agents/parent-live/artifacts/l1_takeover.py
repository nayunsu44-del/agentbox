"""Parent-live check: does a human takeover wait behind an agent GUI call when the sandbox X server is unresponsive?"""
import os, sys, tempfile, threading, time
home = tempfile.mkdtemp(prefix="abx-l1-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "d" * 40, AGENTBOX_GUI_SNAPSHOT_INTERVAL="0")
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
_, box, _ = build()
sb, _ = box.create_sandbox(None, "desktop")
sid = sb["id"]
c = box.sandboxes._container(sid)
box.sandboxes._wait_display(c)
xvfb = c.exec_run(["pgrep", "-u", "desktop", "-x", "Xvfb"]).output.decode().split()[0]
print("xvfb pid", xvfb)
c.exec_run(["kill", "-STOP", xvfb], user="desktop")          # X server stops answering (same uid the GUI session runs as)
res = {}
t1 = threading.Thread(target=lambda: res.__setitem__("shot", box.call_tool(sid, "screenshot", {})), daemon=True)
t1.start(); time.sleep(2)
pub = box.desktop.new_session("*")[1]
t0 = time.monotonic()
t2 = threading.Thread(target=lambda: res.__setitem__("take", box.takeover(sid, pub)), daemon=True)
t2.start(); t2.join(20)
print("takeover returned within 20s:", not t2.is_alive(), "elapsed %.1f" % (time.monotonic() - t0))
c.exec_run(["kill", "-CONT", xvfb], user="desktop")
t2.join(30); t1.join(30)
print("after SIGCONT: takeover done:", not t2.is_alive(), "elapsed %.1f" % (time.monotonic() - t0), "screenshot done:", not t1.is_alive())
box.sandboxes.delete(sid)
