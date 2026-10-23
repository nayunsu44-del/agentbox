"""h-ws harness: does the desktop WS handler block the shared event loop?

Real agentbox.api.build() app, Docker SDK replaced by an in-process fake (no daemon).
Measures GET /healthz latency (sync route, threadpool) issued 0.3 s after a WS upgrade.
"""
import os, sys, time, threading, sqlite3, shutil

HOME = "/scratch/home"
shutil.rmtree(HOME, ignore_errors=True)
os.makedirs(HOME)
os.environ.update({"AGENTBOX_HOME": HOME, "AGENTBOX_HUMAN_TOKEN": "hum_" + "d" * 40,
                   "AGENTBOX_DOCKER_CLI": "/bin/false", "AGENTBOX_MIN_FREE": "0"})

import docker


class FakeContainer:
    id = "c" * 64
    status = "running"
    attrs = {"State": {"Status": "running"}}


class FakeContainers:
    def get(self, cid):
        return FakeContainer()


class FakeClient:
    containers = FakeContainers()

    def info(self):
        return {"Runtimes": {"runsc": {}}}

    def close(self):
        pass


docker.from_env = lambda *a, **k: FakeClient()

from fastapi.testclient import TestClient
from agentbox import api, desktop as D

app, box, human = api.build()
db = str(box.sandboxes.settings.db_path)
with box.sandboxes._lock:
    box.sandboxes.conn.execute(
        "INSERT INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at, template)"
        " VALUES ('sb_x', ?, '/tmp', 'img', 'runsc', 'h', 'running', '2026-01-01', 'desktop')", (FakeContainer.id,))
link_cookie, _ = box.desktop.new_session("sb_x")      # desktop-link session (lowest human scope)
print("journal_mode", sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0])

client = TestClient(app)
client.__enter__()


def health_latency(delay=0.3):
    time.sleep(delay)
    t = time.monotonic()
    r = client.get("/healthz")
    return r.status_code, round(time.monotonic() - t, 2)


def ws_attempt(cookie, out):
    t = time.monotonic()
    try:
        hdrs = {"cookie": f"{D.COOKIE}={cookie}"} if cookie else {}
        with client.websocket_connect("/sandboxes/sb_x/desktop/ws?mode=view", headers=hdrs) as ws:
            try:
                ws.receive()
            except Exception as e:
                out["ws"] = f"closed:{type(e).__name__}:{getattr(e, 'code', '')}"
    except Exception as e:
        out["ws"] = f"rejected:{type(e).__name__}:{getattr(e, 'code', '')}"
    out["ws_s"] = round(time.monotonic() - t, 2)


def scenario(name, cookie, holder=None, hold=7.0):
    """holder: function started in a thread before the WS attempt, holding something for `hold` s."""
    out = {}
    ready = threading.Event()
    th = None
    if holder:
        th = threading.Thread(target=holder, args=(ready, hold), daemon=True)
        th.start()
        ready.wait(5)
        time.sleep(0.2)
    w = threading.Thread(target=ws_attempt, args=(cookie, out), daemon=True)
    w.start()
    code, lat = health_latency()
    w.join(30)
    if th:
        th.join(30)
    print(f"{name}: healthz={code} latency_s={lat} ws={out.get('ws')} ws_s={out.get('ws_s')}", flush=True)


def prune_like(ready, hold):
    """Another connection holds the SQLite write lock (as retention.prune does inside BEGIN IMMEDIATE)."""
    c = sqlite3.connect(db, isolation_level=None, timeout=30)
    c.execute("BEGIN IMMEDIATE")
    ready.set()
    time.sleep(hold)
    c.execute("ROLLBACK")
    c.close()


def audit_lock_holder(ready, hold):
    """A worker thread holds AuditLog._lock (as verify()/recent() do while reading the whole table)."""
    with box.audit._lock:
        ready.set()
        time.sleep(hold)


def desktop_writer_during_prune(ready, hold):
    """Write lock held elsewhere; a human threadpool call (new_session = login) waits on it holding DesktopControl._lock."""
    c = sqlite3.connect(db, isolation_level=None, timeout=30)
    c.execute("BEGIN IMMEDIATE")
    t = threading.Thread(target=lambda: _try(box.desktop.new_session), daemon=True)
    t.start()
    time.sleep(0.1)
    ready.set()
    time.sleep(hold)
    c.execute("ROLLBACK")
    c.close()
    t.join(10)


def _try(f):
    try:
        f()
    except Exception as e:
        print("  writer error:", type(e).__name__, e, flush=True)


scenario("S0 baseline, no WS", None) if False else None
code, lat = health_latency(0)
print(f"S0 baseline: healthz={code} latency_s={lat}")
scenario("S1 link-session WS, no contention", link_cookie)
scenario("S2 link-session WS while another conn holds BEGIN IMMEDIATE 7s", link_cookie, prune_like)
scenario("S3 junk-cookie (unauthenticated) WS while BEGIN IMMEDIATE 7s", "junk", prune_like)
scenario("S4 no-cookie (unauthenticated) WS while BEGIN IMMEDIATE 7s", None, prune_like)
scenario("S5 junk-cookie WS while login waits on write lock holding DesktopControl._lock", "junk",
         desktop_writer_during_prune)
scenario("S6 link-session WS while worker holds AuditLog._lock 4s", link_cookie, audit_lock_holder, 4.0)
scenario("S7 junk-cookie WS while worker holds AuditLog._lock 4s", "junk", audit_lock_holder, 4.0)

# S8: real lock holder. Rows an agent can add (each tool call writes several audit rows); here 250k
# small rows inserted directly, then time the parts of recent()/verify() that run under AuditLog._lock.
N = 100_000
c = sqlite3.connect(db, isolation_level=None)
c.execute("BEGIN")
c.executemany("INSERT INTO audit (ts, sandbox_id, actor, event, tool, payload, prev_hash, hash)"
              " VALUES ('2026-01-01T00:00:00', 'sb_x', 'agent', 'tool_request', 'exec', ?, ?, ?)",
              (('{"args":{"cmd":"%s"}}' % ("x" * 40), "0" * 64, "0" * 64) for _ in range(N)))
c.execute("COMMIT"); c.close()
print("db_bytes", os.path.getsize(db) + (os.path.getsize(db + "-wal") if os.path.exists(db + "-wal") else 0))
t = time.monotonic(); box.audit.recent(sandbox_id="sb_x", limit=400); print("recent_s", round(time.monotonic() - t, 3))
t = time.monotonic(); v = box.audit.verify(); print("verify_s", round(time.monotonic() - t, 3), "ok", v.ok)


def verify_loop(ready, hold):
    ready.set()
    end = time.monotonic() + hold
    while time.monotonic() < end:
        box.audit.verify()     # /ui/verify, /audit/verify (human) on a worker thread


scenario("S8 link-session WS while a worker runs audit.verify() over 100k rows", link_cookie, verify_loop, 3.0)
client.__exit__(None, None, None)
os._exit(0)
