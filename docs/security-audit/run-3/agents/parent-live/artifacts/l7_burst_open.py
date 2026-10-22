"""Parent-live check (v09): what do the GUI-burst collection execs do when the container's pid cgroup is nearly full?

Disposable desktop sandboxes (one per case, so no state leaks between cases), dummy human token, scratch AGENTBOX_HOME,
loopback only. Pid pressure is created the way code running as the desktop user (uid 1001) can create it: plain `sleep`
background processes. Pressure is released with `pkill -x sleep` (no container restart, so no stale burst state).
Per case the script records:
  * whether workspace_manifest / desktop_processes raise or silently return empty/partial data,
  * whether the first GUI input of a burst still executes and whether the burst is recorded,
  * what the audit log shows,
  * what the human-visible gui_changes record looks like when the burst closes after a real change.
usage: MARGINS=2,1,0 python3 l7_burst_open.py
"""
import os, sys, tempfile, time

home = tempfile.mkdtemp(prefix="abx-l7-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "e" * 40)
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build

_, box, _ = build()


def new_sandbox():
    sb, _ = box.create_sandbox(None, "desktop")
    sid = sb["id"]
    c = box.sandboxes._container(sid)
    box.sandboxes._wait_display(c)
    # 300 pre-existing workspace files (what a sandbox looks like after some work)
    c.exec_run(["sh", "-c", "for i in $(seq 1 300); do echo x > /workspace/f$i.txt; done; chown -R 1000:1000 /workspace"],
               user="0:0")
    return sid, c


def events(sid, names=None):
    out = box.audit.list(sandbox_id=sid, limit=5000)
    return [e for e in out if names is None or e["event"] in names]


def cgroup_pids(c):
    c.reload()
    init = c.attrs["State"]["Pid"]
    for line in open(f"/proc/{init}/cgroup"):
        _, ctrl, path = line.strip().split(":", 2)
        if "pids" in ctrl.split(","):
            base = f"/sys/fs/cgroup/pids{path}"
            return int(open(base + "/pids.current").read()), int(open(base + "/pids.max").read().strip())
    raise RuntimeError("pids cgroup not found")


def fill_pids(c, margin):
    """sleepers as the desktop user until pids.current == max - margin. Each spawner shell ends in `exec sleep`, so it
    keeps exactly one pid slot (that is how margin 0 is reachable)."""
    while True:
        cur, mx = cgroup_pids(c)
        need = mx - margin - cur
        if need <= 0:
            return cur, mx
        b = min(need, 200) - 1
        c.exec_run(["sh", "-c", f"i=0; while [ $i -lt {b} ]; do sleep 3000 & i=$((i+1)); done; exec sleep 3000"],
                   user="desktop", detach=True)
        time.sleep(1.5)


def real_change_and_close(sid, c, label):
    """a real change by the desktop user, then close the burst the way idle/next_burst would"""
    c.exec_run(["sh", "-c", "echo changed > /workspace/zz_changed_by_gui.txt"], user="desktop")
    before = len(events(sid, {"gui_changes"}))
    box._close_gui_burst(sid, "test_idle")
    ev = events(sid, {"gui_changes"})
    if len(ev) == before:
        print(f"   {label}: NO gui_changes record")
        return
    pl = ev[-1]["payload"]
    print(f"   {label}: gui_changes counts={pl['counts']} truncated={pl['truncated']} "
          f"| real change visible in added[:100]: {'zz_changed_by_gui.txt' in pl['added']} | listed paths={len(pl['added'])}")


print("=== A. control (no pressure) ===")
sid, c = new_sandbox()
out = box.call_tool(sid, "key", {"keys": "shift"})
print(f"A1 first GUI input -> {out.status} | burst recorded: {sid in box._gui_burst} "
      f"| baseline manifest entries: {len(box._gui_burst[sid]['manifest']) if sid in box._gui_burst else None}")
real_change_and_close(sid, c, "A2 close")
box.sandboxes.delete(sid)

for margin in [int(x) for x in os.environ.get("MARGINS", "2,1,0").split(",")]:
    print(f"\n=== B. pid pressure, {margin} free pid(s) left when the burst opens ===")
    sid, c = new_sandbox()
    cur, mx = fill_pids(c, margin)
    print(f"pids {cur}/{mx}")
    for label, argv in (("pgrep Xvfb", ["pgrep", "-x", "Xvfb"]),):
        try:
            r = c.exec_run(argv, user="desktop")
            print(f"diag {label}: exit={r.exit_code} out={r.output.decode(errors='replace').strip()[:40]!r}")
        except BaseException as e:
            print(f"diag {label}: RAISED {type(e).__name__}: {str(e)[:100]}")
    for name in ("workspace_manifest", "desktop_processes"):
        try:
            r = getattr(box.sandboxes, name)(sid)
            if name == "workspace_manifest":
                print(f"{name}: returned manifest entries={len(r[0])} truncated={r[1]} (no exception)")
            else:
                print(f"{name}: returned procs={len(r[0])} window_pids={len(r[1])} (no exception)")
        except BaseException as e:
            print(f"{name}: RAISED {type(e).__module__}.{type(e).__name__}: {str(e)[:160]}")
    before = len(events(sid))
    try:
        out = box.call_tool(sid, "key", {"keys": "shift"})
        print(f"first GUI input -> status {out.status}")
    except BaseException as e:
        print(f"first GUI input RAISED {type(e).__module__}.{type(e).__name__}: {str(e).splitlines()[0][:120]}")
    print("burst recorded:", sid in box._gui_burst,
          "| baseline manifest entries:", len(box._gui_burst[sid]["manifest"]) if sid in box._gui_burst else None)
    print("audit events added:", [(e["event"], e["tool"]) for e in events(sid)[before:]])
    # pressure ends (the agent's own processes exit / the stray killer's single `kill` exec runs): no restart
    c.exec_run(["pkill", "-x", "sleep"], user="desktop")
    time.sleep(2)
    cur, mx = cgroup_pids(c)
    before = len(events(sid))
    try:
        out = box.call_tool(sid, "key", {"keys": "shift"})
        print(f"after pressure ended (pids {cur}/{mx}): next GUI input -> {out.status} | needs_snapshot: "
              f"{box._gui_needs_snapshot(sid)} | burst recorded: {sid in box._gui_burst}")
    except BaseException as e:
        print(f"after pressure ended: next GUI input RAISED {type(e).__name__}: {str(e).splitlines()[0][:120]}")
    print("audit events added:", [(e["event"], e["tool"]) for e in events(sid)[before:]])
    real_change_and_close(sid, c, "close after degraded open")
    box.sandboxes.delete(sid)

print("\ndone")
