"""Parent-live check (v06 root cause): the source_dir overlap guard compares path strings, so a second name
for the data folder's project directory that is not a symlink (here a bind mount, standing in for a case-variant
spelling on a case-insensitive filesystem) passes the guard and the agent reads the human token.
Disposable project dir under /tmp, dummy human token written 0600 by Settings, loopback-only in-process app,
buildpack-deps:noble-curl sandbox deleted afterwards, bind mount removed afterwards.
"""
import os, subprocess, sys, tempfile

root = tempfile.mkdtemp(prefix="abx-l8-")
proj = os.path.join(root, "Users", "Me", "proj")
alias = os.path.join(root, "alias", "proj")
os.makedirs(proj); os.makedirs(alias)
os.environ["AGENTBOX_HOME"] = os.path.join(proj, "data")
os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
sys.path.insert(0, "/home/user/agentbox")
from agentbox.api import build
from agentbox.sandbox import SandboxError

_, box, human = build()
tok_path = os.path.join(proj, "data", "human_token")
print("human_token mode:", oct(os.stat(tok_path).st_mode & 0o777))
subprocess.run(["mount", "--bind", proj, alias], check=True)
try:
    print("alias is a symlink:", os.path.islink(alias), "| same inode as project dir:", os.path.samefile(alias, proj))
    for label, path in (("exact project dir", proj), ("bind-mount alias", alias)):
        try:
            rec, agent = box.create_sandbox(path, "cli")
        except SandboxError as e:
            print(f"{label}: REFUSED ({str(e)[:70]})")
            continue
        sid = rec["id"]
        out = box.call_tool(sid, "read_file", {"path": "/workspace/data/human_token"}, actor="agent")
        body = out.body if hasattr(out, "body") else out
        got = (body.get("result") or {}).get("content", "") if isinstance(body, dict) else str(body)
        print(f"{label}: ACCEPTED as {sid}; agent read_file /workspace/data/human_token -> status {out.status}, "
              f"equals real human token: {got.strip() == human}")
        box.sandboxes.delete(sid)
finally:
    subprocess.run(["umount", alias])
print("done")
