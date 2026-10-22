"""Parent-live check (h-autostart candidate): can the agent, with GUI tools only, write an XDG autostart entry under
/home/desktop that gui_changes does not record, that a later snapshot captures, and that runs again as uid 1001
after a human restore? Disposable desktop sandbox, dummy tokens, scratch AGENTBOX_HOME, loopback. Imports the audited
tree. The payload only writes a dummy marker file into /workspace.
"""
import os, sys, tempfile, time
AUDITED = sys.argv[1]
home = tempfile.mkdtemp(prefix="abx-l12-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "c" * 40)
sys.path.insert(0, AUDITED)
import agentbox
print("agentbox imported from", os.path.dirname(agentbox.__file__))
from agentbox.api import build
_, box, _ = build()
S = box.sandboxes


def tool(name, **a):
    o = box.call_tool(sid, name, a)
    return o.status


def ls():
    return (box.call_tool(sid, "list_dir", {"path": "/workspace"}).body or {}).get("result", {}).get("listing", "")


sb, _ = box.create_sandbox(None, "desktop")
sid = sb["id"]
S._wait_display(S._container(sid))
time.sleep(8)  # let the Xfce session come up
print("agent key ctrl+alt+t:", tool("key", keys="ctrl+alt+t"))
time.sleep(4)
cmd = ("mkdir -p ~/.config/autostart && printf '[Desktop Entry]\\nType=Application\\nName=t\\n"
       "Exec=sh -c \"id -u > /workspace/PROOF_autostart.txt\"\\n' > ~/.config/autostart/t.desktop; exit")
print("agent type:", tool("type", text=cmd))
print("agent key Return:", tool("key", keys="Return"))
time.sleep(3)
c = S._container(sid)
r = c.exec_run(["sh", "-c", "ls -l /home/desktop/.config/autostart; cat /home/desktop/.config/autostart/t.desktop"], user="0:0")
print("observer (root, read-only check): autostart dir ->", r.output.decode(errors="replace").strip().replace("\n", " | "))
print("PROOF before restore:", "PROOF_autostart.txt" in ls())
box._gui_input_at[sid] -= 61          # treat the burst as idle so it closes and logs gui_changes
box.close_idle_gui_bursts()
ev = [e for e in box.audit.list(sandbox_id=sid, limit=5000) if e["event"] in ("gui_changes", "gui_processes_stopped")]
for e in ev:
    print(f"audit {e['event']}: {str(e['payload'])[:300]}")
print("gui_changes mention /home/desktop:", any("home/desktop" in str(e["payload"]) or "autostart" in str(e["payload"]) for e in ev))
snap = S.snapshot(sid, "manual")          # a later human snapshot (or any docker-commit snapshot) after the burst
print("human snapshot:", snap["id"])
r = S.restore(sid, snap["id"])
print("human restore:", r["status"])
S._wait_display(S._container(sid))
deadline = time.monotonic() + 40
seen = False
while time.monotonic() < deadline and not seen:
    time.sleep(2)
    seen = "PROOF_autostart.txt" in ls()
print("PROOF after restore (autostart re-executed):", seen)
if seen:
    print("PROOF content (uid):", (box.call_tool(sid, "read_file", {"path": "/workspace/PROOF_autostart.txt"}).body or {}).get("result", {}).get("content", "").strip())
ev2 = [e["event"] for e in box.audit.list(sandbox_id=sid, limit=5000)]
print("audit events after restore:", ev2[ev2.index("sandbox_restored") if "sandbox_restored" in ev2 else -5:][:12])
S.delete(sid)
print("done")
