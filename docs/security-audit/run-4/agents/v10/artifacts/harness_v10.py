
import json, sys, threading, types, traceback
from pathlib import Path

from docker.errors import APIError, ImageNotFound, NotFound

import agentbox.sandbox as S
from agentbox.config import Settings
from agentbox.audit import AuditLog
from agentbox.approvals import ApprovalStore
from agentbox.policy import Policy
from agentbox.desktop import DesktopControl
from agentbox.service import AgentBox

SCRATCH = Path("/scratch")
DATA = SCRATCH / "data"
(DATA / "sources").mkdir(parents=True, exist_ok=True)

OUT = {}

class Res:
    def __init__(self, code=0, out=b"", err=b""):
        self.exit_code = code
        self.output = (out, err)

class FakeContainer:
    def __init__(self, cid, name, image, client):
        self.id, self.name, self.image, self.client = cid, name, image, client
        self.removed = False
        self.running = True
    def remove(self, force=False):
        if self.removed:
            raise NotFound("no such container: %s" % self.id)
        self.removed = True
        self.running = False
        self.client._by_id.pop(self.id, None)
        self.client._by_name.pop(self.name, None)
    def pause(self):
        self.running = False
    def unpause(self):
        self.running = True
    def commit(self, repository=None, tag=None, pause=True, conf=None):
        img = "%s:%s" % (repository, tag)
        self.client._images.add(img)
        return {"Id": "sha256:" + img}
    def exec_run(self, cmd, **kw):
        return Res(0, b"total 0\ndrwxr-xr-x 2 agent agent 40 Nov  1 00:00 .\n", b"")
    def attrs(self):
        return {"State": {"Running": self.running}}

class FakeImages:
    def __init__(self, c):
        self.c = c
    def get(self, name):
        if name not in self.c._images:
            raise ImageNotFound("no such image: %s" % name)
        return {"Id": name}
    def remove(self, name, force=False):
        if name not in self.c._images:
            raise NotFound("no such image: %s" % name)
        users = [ct for ct in self.c._by_id.values() if ct.image == name and not ct.removed and ct.running]
        if users:
            raise APIError("409 Client Error: conflict: unable to delete %s (must be forced) - image is being used by running container %s"
                           % (name, users[0].id))
        self.c._images.discard(name)

class FakeContainers:
    def __init__(self, c):
        self.c = c
    def run(self, **kw):
        name = kw.get("name")
        image = kw.get("image")
        if image not in self.c._images:
            raise ImageNotFound("no such image: %s" % image)
        if name in self.c._by_name:
            raise APIError("409 Client Error: Conflict. The container name %s is already in use" % name)
        cid = self.c.next_id()
        ct = FakeContainer(cid, name, image, self.c)
        self.c._by_id[cid] = ct
        self.c._by_name[name] = ct
        hook = self.c.run_hook
        if hook is not None:
            hook(ct)
        return ct
    def get(self, ref):
        ct = self.c._by_id.get(ref) or self.c._by_name.get(ref)
        if ct is None or ct.removed:
            raise NotFound("no such container: %s" % ref)
        return ct

class FakeClient:
    def __init__(self):
        self._images = set()
        self._by_id = {}
        self._by_name = {}
        self._n = 0
        self.run_hook = None
        self.containers = FakeContainers(self)
        self.images = FakeImages(self)
    def next_id(self):
        self._n += 1
        return "c%d" % self._n
    def info(self):
        return {"Runtimes": {"runc": {}}}

def make_box(fake):
    S.docker = types.SimpleNamespace(from_env=lambda: fake)
    settings = Settings(home=DATA)
    fake._images.add(settings.image)
    audit = AuditLog(DATA / "audit.db")
    approvals = ApprovalStore(DATA / "approvals.db")
    sandboxes = S.SandboxManager(settings, DATA / "sandbox.db")
    policy = Policy.load(Path("/target/agentbox/default_policy.yaml"))
    box = AgentBox(audit, policy, sandboxes, approvals, desktop=DesktopControl(), captures=None)
    return box, sandboxes, audit

def events(audit, sid):
    return [e["event"] for e in audit.list(sandbox_id=sid)]

def main():
    fake = FakeClient()
    box, sboxes, audit = make_box(fake)

    # ---------- race run ----------
    rec, token = box.create_sandbox(None, "cli")
    sid = rec["id"]
    print("create:", sid, "container", rec["container_id"], "status", rec["status"])
    snap = box.snapshot_sandbox(sid)
    print("snapshot:", snap["id"], snap["image"], "images", sorted(fake._images))

    parked = threading.Event()
    release = threading.Event()

    def hook(ct):
        if ct.image.startswith("agentbox-snap:"):
            parked.set()
            release.wait(20)

    fake.run_hook = hook
    err = {}
    def do_restore():
        try:
            err["restore_result"] = box.restore_sandbox(sid, snap["id"])
        except BaseException as e:
            err["restore_exc"] = "%s: %s" % (type(e).__name__, e)
    t = threading.Thread(target=do_restore)
    t.start()
    if not parked.wait(20):
        raise SystemExit("restore never reached the run hook")
    print("parked: replace container exists =", "c2" in fake._by_id, "rows:", sboxes.get(sid)["container_id"])
    fake.run_hook = None

    print("pre-delete token_matches:", sboxes.token_matches(sid, token))
    box.delete_sandbox(sid)
    print("delete returned; status now:", sboxes.get(sid)["status"],
          "token_matches:", sboxes.token_matches(sid, token),
          "sandbox_for_token:", sboxes.sandbox_for_token(token),
          "images:", sorted(fake._images))
    release.set()
    t.join(20)
    print("restore thread done, exc:", err.get("restore_exc"), "result status:",
          (err.get("restore_result") or {}).get("status"))

    after = sboxes.get(sid)
    out = box.call_tool(sid, "list_dir", {"path": "/workspace"})
    print("after: status", after["status"], "container", after["container_id"],
          "alive", (after["container_id"] in fake._by_id))
    print("after: token_matches", sboxes.token_matches(sid, token),
          "sandbox_for_token", sboxes.sandbox_for_token(token))
    print("after: snapshots", len(sboxes.list_snapshots(sid)), "images", sorted(fake._images))
    print("tool call:", out.status, json.dumps(out.body, ensure_ascii=False))
    print("audit:", events(audit, sid))

    # inspection of delete's image removal path
    print("snapshot rows after delete:", [s["id"] for s in sboxes.list_snapshots(sid)])

    # ---------- sequential control ----------
    rec2, token2 = box.create_sandbox(None, "cli")
    sid2 = rec2["id"]
    snap2 = box.snapshot_sandbox(sid2)
    box.delete_sandbox(sid2)
    print("ctl: after delete status", sboxes.get(sid2)["status"], "token", sboxes.token_matches(sid2, token2),
          "images", sorted(fake._images))
    try:
        box.restore_sandbox(sid2, snap2["id"])
        print("ctl: restore unexpectedly succeeded")
    except BaseException as e:
        print("ctl: restore raised", type(e).__name__, "|", str(e)[:120])
    print("ctl: final status", sboxes.get(sid2)["status"], "token", sboxes.token_matches(sid2, token2),
          "sandbox_for_token", sboxes.sandbox_for_token(token2))
    print("ctl audit:", events(audit, sid2))

main()
