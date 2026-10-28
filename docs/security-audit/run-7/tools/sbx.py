#!/usr/bin/env python3
"""sbx.py <agent-id> <cmd...>

Run target-controlled code for audit agent <agent-id> inside an OS-enforced container.

Boundary (same as run-7 sbx.py): no network, no Docker socket inside, read-only container root,
read-only audited worktree at /target, writes only to agents/<id>/scratch at /scratch, /dev/shm capped
at 16 MiB, --pull never, uid 65534, all caps dropped, no-new-privileges, 512 MiB (RLIMIT_DATA), 1 CPU (cpuset),
64 pids, 32 MiB max file size, 120 s wall clock, empty env from an explicit allowlist.

Host differences forced by the run-7 host (Kiro Web Linux sandbox): every tool call is a fresh
sandbox, /run and /var are read-only, and no daemon survives between calls. So each sbx call starts
a private dockerd in its own mount namespace (tmpfs on /run, cgroup2 remounted rw inside that
namespace only), with an ephemeral data root on the per-call tmpfs /tmp, loads the agentbox-audit-sbx:1
image from a saved tar, runs the one container, and tears everything down. Concurrent sbx calls do
not share a daemon or a data root. The dockerd is never reachable from inside the container.
"""
import os
import re
import shlex
import subprocess
import sys
import time
import uuid

RUN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SP = os.environ.get("AUDIT_SCRATCHPAD", "/projects/sandbox/.scratch")
TARGET = f"{SP}/src-audited"
LOG = f"{SP}/sbx.log"
IMAGE = "agentbox-audit-sbx:1"
IMAGE_TAR = f"{SP}/sbx-image/agentbox-audit-sbx-1.tar"
WALL = 120


def usage(msg):
    print(f"sbx: {msg}", file=sys.stderr)
    print("usage: sbx.py <agent-id> <cmd...>", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) < 3:
        usage("missing arguments")
    aid, cmd = sys.argv[1], sys.argv[2:]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", aid):
        usage("bad agent id")
    scratch = f"{RUN}/agents/{aid}/scratch"
    if os.path.islink(scratch) or not os.path.isdir(scratch):
        usage(f"{scratch} is missing or a symlink (run common.make_scratch)")
    if os.stat(scratch).st_uid != 65534:
        usage(f"{scratch} is not owned by uid 65534")
    name = f"sbx-{aid}-{uuid.uuid4().hex[:8]}"
    run = [
        "docker", "run", "--rm", "-i", "--pull", "never",
        "--name", name,
        "--network", "none",
        "--read-only",
        "--user", "65534:65534",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        # This host's cgroup2 is threaded with only cpuset/cpu/pids controllers: --memory is silently
        # discarded and --cpus fails. 512 MiB is enforced with RLIMIT_DATA and one CPU with cpuset.
        "--ulimit", "data=536870912:536870912",
        "--cpuset-cpus", "0",
        "--pids-limit", "64",
        "--ulimit", "fsize=33554432:33554432",
        "--ulimit", "nofile=256:256",
        "--ulimit", "core=0",
        "--tmpfs", "/dev/shm:rw,nosuid,nodev,noexec,size=16m",
        "-v", f"{TARGET}:/target:ro",
        "-v", f"{scratch}:/scratch:rw",
        "-w", "/scratch",
        "-e", "HOME=/scratch",
        "-e", "TMPDIR=/scratch",
        "-e", "PATH=/usr/local/bin:/usr/bin:/bin",
        "-e", "PYTHONPATH=/target",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "PYTHONNOUSERSITE=1",
        "--entrypoint", "/usr/bin/timeout",
        IMAGE, "-k", "5", str(WALL), *cmd,
    ]
    inner = f"""
set -u
mount -t tmpfs tmpfs /run || exit 90
mount -o remount,rw /sys/fs/cgroup || exit 91
mkdir -p /run/containerd /run/docker
D=$(mktemp -d /tmp/sbxd.XXXXXX)
/usr/bin/dockerd --data-root "$D" --bridge=none --iptables=false --ip-forward=false >"$D.log" 2>&1 &
for i in $(seq 90); do /usr/bin/docker info >/dev/null 2>&1 && break; sleep 0.5; done
/usr/bin/docker load -q -i {shlex.quote(IMAGE_TAR)} >/dev/null || {{ tail -5 "$D.log" >&2; exit 92; }}
{' '.join(shlex.quote(a) for a in run)}
rc=$?
kill %1 2>/dev/null; wait 2>/dev/null
exit $rc
"""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp}\t{aid}\t{' '.join(cmd)}\n")
    env = {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "DOCKER_HOST": "unix:///run/docker.sock"}
    try:
        rc = subprocess.run(["unshare", "-m", "--propagation", "private", "bash", "-c", inner],
                            env=env, timeout=WALL + 60).returncode
    except subprocess.TimeoutExpired:
        rc = 124
    sys.exit(rc)


if __name__ == "__main__":
    main()
