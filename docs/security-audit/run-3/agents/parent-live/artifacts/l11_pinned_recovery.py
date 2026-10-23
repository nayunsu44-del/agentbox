"""Parent-live check (v16): after one approval-free agent exec leaves the sandbox at its pids limit, what still works?
Disposable sandboxes (cli template and desktop template), dummy tokens, scratch AGENTBOX_HOME, loopback.
Imports the audited tree (worktree at 8e4db9e). Records which agent tools, human actions and other sandboxes still work.
"""
import os, sys, tempfile, time
AUDITED = sys.argv[1]
home = tempfile.mkdtemp(prefix="abx-l11-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "b" * 40)
sys.path.insert(0, AUDITED)
import agentbox
print("agentbox imported from", os.path.dirname(agentbox.__file__))
from agentbox.api import build
_, box, _ = build()
S = box.sandboxes


def pids(sid):
    c = S._container(sid); c.reload()
    for line in open(f"/proc/{c.attrs['State']['Pid']}/cgroup"):
        _, ctrl, path = line.strip().split(":", 2)
        if "pids" in ctrl.split(","):
            b = f"/sys/fs/cgroup/pids{path}"
            return int(open(b + "/pids.current").read()), int(open(b + "/pids.max").read().strip())


def step(name, fn):
    t0 = time.monotonic()
    try:
        r = fn()
        print(f"  {name}: ok ({time.monotonic() - t0:.1f}s) {str(r)[:160]}")
    except Exception as e:
        print(f"  {name}: FAILED ({time.monotonic() - t0:.1f}s) {type(e).__name__}: {str(e)[:160]}")


def tool(sid, name, args):
    o = box.call_tool(sid, name, args)
    return o.status, str(o.body)[:120]


for template in ("cli", "desktop"):
    print(f"== template {template}")
    sb, _ = box.create_sandbox(None, template)
    sid = sb["id"]
    other, _ = box.create_sandbox(None, "cli")
    if template == "desktop":
        S._wait_display(S._container(sid))
    box.call_tool(sid, "write_file", {"path": "/workspace/probe.txt", "content": "probe"})
    snap = S.snapshot(sid, "before-pressure")
    n = pids(sid)[1] + 50
    cmd = "tail -f /dev/null & " * n + "tail -f /dev/null"
    print("  policy:", box.policy.decide("exec", {"command": cmd}).action, "| pids before:", pids(sid))
    t0 = time.monotonic()
    o = box.call_tool(sid, "exec", {"command": cmd})
    r = (o.body or {}).get("result", {})
    print(f"  agent exec: status {o.status} exit {r.get('exit_code')} after {time.monotonic() - t0:.0f}s | pids {pids(sid)}")
    time.sleep(5)
    print("  pids 5s later:", pids(sid))
    step("agent exec 'echo hi'", lambda: tool(sid, "exec", {"command": "echo hi"}))
    step("agent read_file", lambda: tool(sid, "read_file", {"path": "/workspace/probe.txt"}))
    step("agent list_dir", lambda: tool(sid, "list_dir", {"path": "/workspace"}))
    step("other sandbox exec", lambda: tool(other["id"], "exec", {"command": "echo other"}))
    step("human snapshot", lambda: S.snapshot(sid, "while-pinned")["id"])
    step("human pause", lambda: S.pause(sid))
    step("human resume", lambda: S.resume(sid))
    step("pids after pause/resume", lambda: pids(sid))
    step("human restore", lambda: S.restore(sid, snap["id"])["status"])
    step("pids after restore", lambda: pids(sid))
    step("agent exec after restore", lambda: tool(sid, "exec", {"command": "echo back"}))
    step("human delete", lambda: S.delete(sid))
    S.delete(other["id"])
print("done")
