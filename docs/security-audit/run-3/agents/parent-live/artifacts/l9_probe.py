import os, sys, tempfile, threading, time, collections
home = tempfile.mkdtemp(prefix="abx-l9p-")
os.environ.update(AGENTBOX_HOME=home, AGENTBOX_HUMAN_TOKEN="hum_" + "b" * 40)
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
_, box, _ = build()
sb, _ = box.create_sandbox(None, "desktop")
sid = sb["id"]; c = box.sandboxes._container(sid); box.sandboxes._wait_display(c)
cmd = "tail -f /dev/null & " * 1100 + "tail -f /dev/null"
out = box.call_tool(sid, "exec", {"command": cmd})
print("exec:", out.status, str(out.body)[:300])
time.sleep(3)
init = c.attrs["State"]["Pid"]
c.reload(); init = c.attrs["State"]["Pid"]
# host-side view of the container's processes (no pid needed inside the container)
cg = [l for l in open(f"/proc/{init}/cgroup") if ":pids:" in l][0].strip().split(":", 2)[2]
procs = [int(x) for x in open(f"/sys/fs/cgroup/pids{cg}/cgroup.procs").read().split()]
states = collections.Counter()
for p in procs:
    try:
        st = open(f"/proc/{p}/stat").read()
        comm = st[st.index("(") + 1:st.rindex(")")]; state = st[st.rindex(")") + 2]
        uid = [l for l in open(f"/proc/{p}/status") if l.startswith("Uid:")][0].split()[1]
        states[(comm, state, uid)] += 1
    except FileNotFoundError:
        pass
print("container processes by (comm, state, uid):", states.most_common(8))
print("pid 1 in container:", open(f"/proc/{init}/cmdline").read().replace("\0", " ")[:80])
box.sandboxes.delete(sid)
