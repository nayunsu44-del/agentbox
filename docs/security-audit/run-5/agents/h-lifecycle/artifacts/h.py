"""h-lifecycle: deterministic schedule for delete_sandbox racing an agent pre-destructive snapshot.

Real AgentBox, AuditLog, ApprovalStore, SandboxManager logic (sqlite in /scratch); only the Docker client is
faked. The fake models the one Docker behaviour that is NOT established here: a commit that is already running
completes and leaves its image even though the container is force-removed meanwhile.
"""
import json
import os
import sqlite3
import threading
import time

from docker.errors import NotFound

from agentbox.approvals import ApprovalStore
from agentbox.audit import AuditLog
from agentbox.config import Settings
from agentbox.desktop import DesktopControl
from agentbox.policy import Policy
from agentbox.sandbox import SandboxManager, SCHEMA
from agentbox.service import AgentBox, ServiceError

OUT = "/scratch/h.out"
for f in ("sb.db", "audit.db", "apr.db"):
    try:
        os.unlink(f"/scratch/{f}")
    except FileNotFoundError:
        pass

commit_entered = threading.Event()
commit_go = threading.Event()


class FakeImages:
    def __init__(self):
        self.live = set()

    def remove(self, image, force=False):
        if image not in self.live:
            raise NotFound("no such image")
        self.live.discard(image)


class FakeContainer:
    def __init__(self, client, cid):
        self.client, self.id = client, cid

    def commit(self, repository, tag, pause, conf):
        commit_entered.set()
        commit_go.wait(10)                         # docker commit takes seconds; delete runs meanwhile
        self.client.images.live.add(f"{repository}:{tag}")

    def remove(self, force=False):
        self.client.alive.discard(self.id)


class FakeContainers:
    def __init__(self, client):
        self.client = client

    def get(self, cid):
        if cid not in self.client.alive:
            raise NotFound("no such container")
        return FakeContainer(self.client, cid)


class FakeClient:
    def __init__(self):
        self.alive = {"c1"}
        self.images = FakeImages()
        self.containers = FakeContainers(self)


settings = Settings()
settings.min_free_bytes = 0          # 256 MiB scratch would trip the disk guard; unrelated to this check
sb = object.__new__(SandboxManager)
sb.settings = settings
sb.client = FakeClient()
sb._lock = threading.Lock()
sb.conn = sqlite3.connect("/scratch/sb.db", check_same_thread=False, isolation_level=None)
sb.conn.executescript(SCHEMA)
sb.runtime = "runc"
sb.conn.execute("INSERT INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at,"
                " template) VALUES ('sb_1','c1','/src','ubuntu:24.04','runc','h','running','t','cli')")

box = AgentBox(AuditLog("/scratch/audit.db"), Policy({"default": "allow"}), sb, ApprovalStore("/scratch/apr.db"),
               desktop=DesktopControl())

out = {}


def agent():
    try:
        r = box.call_tool("sb_1", "delete_file", {"path": "/workspace/a.txt"}, actor="agent")
        out["agent"] = [r.status, r.body]
    except ServiceError as e:
        out["agent"] = [e.status, e.message]


t = threading.Thread(target=agent)
t.start()
assert commit_entered.wait(5), "agent snapshot never reached commit"
box.delete_sandbox("sb_1")                         # human DELETE /sandboxes/sb_1 returns while commit runs
after_delete = {
    "status": sb.get("sb_1")["status"],
    "snapshot_rows": [s["id"] for s in sb.list_snapshots("sb_1")],
    "images": sorted(sb.client.images.live),
}
commit_go.set()
t.join(10)
final = {
    "status": sb.get("sb_1")["status"],
    "snapshot_rows": [(s["id"], s["image"]) for s in sb.list_snapshots("sb_1")],
    "images_left_in_docker": sorted(sb.client.images.live),
    "containers_alive": sorted(sb.client.alive),
}
events = [(r["event"], r["sandbox_id"]) for r in box.audit.conn.execute(
    "SELECT event, sandbox_id FROM audit ORDER BY id").fetchall()] if False else None
rows = box.audit.conn.execute("SELECT id, actor, event, sandbox_id, payload FROM audit ORDER BY id").fetchall()
ev = [(r[0], r[1], r[2], r[3], json.loads(r[4]) if r[4] else None) for r in rows]
# control: a second human DELETE on the already-deleted id would clean the orphan (sandboxes.delete has no guard)
box.delete_sandbox("sb_1")
after_second_delete = sorted(sb.client.images.live)
with open(OUT, "w") as f:
    json.dump({"after_delete_returned": after_delete, "agent_result": out.get("agent"), "final": final,
               "audit": ev, "images_after_second_delete": after_second_delete}, f, ensure_ascii=False, indent=1,
              default=str)
