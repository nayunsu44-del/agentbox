#!/usr/bin/env python3
"""sbx.py <agent-id> <cmd...>

Windows-host replacement for tools/sbx (bash). Same enforcement boundary, because the
previous runs ran on a Linux host where the bash wrapper could mount /usr and a loop file:

  no network, no Docker socket, read-only container root, read-only audited target at
  /target, writes only to agents/<id>/scratch at /scratch, /dev/shm capped at 16 MiB,
  --pull never, uid 65534, all caps dropped, no-new-privileges, 512 MiB (no swap), 1 CPU,
  64 pids, 32 MiB max file size, 120 s wall clock, empty env from an explicit allowlist.

Differences from the bash version, all forced by the Windows host:
  * the audited worktree is the bind source instead of a host /usr mount; python3,
    PyYAML, jinja2 and markupsafe come from the image (agentbox-audit-sbx:1) instead
    of the host interpreter;
  * scratch is a plain directory (common.make_scratch), so there is no 256 MiB loop
    cap; the parent calls common.cap_scratch() after each agent instead.

Parent-side tool: agents never get the docker CLI through this script, only the
command's output.
"""
import os
import subprocess
import sys
import time
import uuid

RUN = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
SP = os.environ.get("AUDIT_SCRATCHPAD")  # Windows scratchpad holding src-audited/ and sbx.log
if not SP:
    sys.exit("sbx: set AUDIT_SCRATCHPAD")
TARGET = f"{SP}/src-audited"
LOG = f"{SP}/sbx.log"
IMAGE = "agentbox-audit-sbx:1"
WALL = 120


def usage(msg):
    print(f"sbx: {msg}", file=sys.stderr)
    print("usage: sbx.py <agent-id> <cmd...>", file=sys.stderr)
    sys.exit(2)


def main():
    if len(sys.argv) < 3:
        usage("missing arguments")
    aid, cmd = sys.argv[1], sys.argv[2:]
    if not aid or aid.startswith("-") or any(c in aid for c in "/\\:"):
        usage("bad agent id")
    scratch = f"{RUN}/agents/{aid}/scratch"
    if os.path.islink(scratch) or not os.path.isdir(scratch):
        usage(f"{scratch} is missing or a symlink (run common.make_scratch)")
    name = f"sbx-{aid}-{uuid.uuid4().hex[:8]}"
    args = [
        "docker", "run", "--rm", "-i", "--pull", "never",
        "--name", name,
        "--network", "none",
        "--read-only",
        "--user", "65534:65534",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1",
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
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp}\t{aid}\t{' '.join(cmd)}\n")
    try:
        rc = subprocess.run(args, timeout=WALL + 20).returncode
    except subprocess.TimeoutExpired:
        rc = 124
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{stamp}\t{aid}\trc={rc}\n")
    sys.exit(rc)


if __name__ == "__main__":
    main()
