"""h-approvals bounded check: one agent exec call vs disk guard and approval row size.
Runs only inside tools/sbx. No Docker: fake sandbox manager whose preview() calls the real
preview_command with empty glob/walk callbacks (the same callbacks a real container gives for 'x')."""
import json, os, shutil, sys, time, tracemalloc
from pathlib import Path

sys.path.insert(0, "/target")
from agentbox.approvals import ApprovalStore
from agentbox.audit import AuditLog, bound_payload
from agentbox.config import Settings
from agentbox.desktop import DesktopControl
from agentbox.policy import Policy
from agentbox.preview import preview_command
from agentbox.service import AgentBox, ServiceError

OUT = []
def say(*a):
    OUT.append(" ".join(str(x) for x in a))
    print(*a, flush=True)

class Tpl:
    desktop = False

class FakeSandboxes:
    def __init__(self, home):
        self.settings = Settings(home=home)
    def get(self, sid):
        return {"id": sid, "container_id": "c1", "status": "running"}
    def template_of(self, sid):
        return Tpl()
    def snapshot_count(self, sid):
        return 0
    def preview(self, sid, command, limit=200):
        return preview_command(command, limit, lambda p: [], lambda p, n: [])

def run(n_segments, tag):
    home = Path(f"/scratch/home_{tag}")
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    db = home / "agentbox.db"
    sb = FakeSandboxes(home)
    policy = Policy.load("/target/agentbox/default_policy.yaml")
    box = AgentBox(AuditLog(db), policy, sb, approvals=ApprovalStore(db), desktop=DesktopControl(),
                   approval_timeout=1)
    cmd = "x;" * n_segments
    body = json.dumps({"args": {"command": cmd}}).encode()
    t0 = time.monotonic(); rule = policy.decide('exec', {'command': cmd}).rule_id; td = time.monotonic() - t0
    say(f"[{tag}] request body bytes={len(body)} decision={rule} policy_decide_seconds={td:.2f}")
    free0 = shutil.disk_usage(home).free
    # guard margin: 1 MiB of headroom above AGENTBOX_MIN_FREE
    sb.settings.min_free_bytes = free0 - (1 << 20)
    db_before = os.path.getsize(db)
    say(f"[{tag}] min_free_bytes=free-1MiB disk_low_before={box.disk_low()} db_bytes_before={db_before}")
    t = time.monotonic()
    try:
        out = box.call_tool("sb_x", "exec", {"command": cmd}, actor="agent")
        say(f"[{tag}] call_tool status={out.status} body_status={out.body.get('status')}")
    except ServiceError as e:
        say(f"[{tag}] call_tool ServiceError {e.status}")
    dt = time.monotonic() - t
    peak = -1
    db_after = os.path.getsize(db)
    wal = Path(str(db) + "-wal")
    say(f"[{tag}] wal_bytes_after_call={wal.stat().st_size if wal.exists() else 0}")
    say(f"[{tag}] seconds={dt:.2f} db_bytes_after={db_after} "
        f"db_growth={db_after - db_before} growth/body={(db_after - db_before) / len(body):.1f}x")
    say(f"[{tag}] disk_low_after={box.disk_low()}")
    r = box.approvals.conn.execute("SELECT id, length(CAST(args AS BLOB)), length(CAST(preview AS BLOB)) "
                                   "FROM approvals").fetchone()
    say(f"[{tag}] approvals row id={r[0]} args_bytes={r[1]} preview_bytes={r[2]}")
    apr = box.approvals.get(r[0])
    say(f"[{tag}] pending preview notes={len(apr['preview']['notes'])} first_note={apr['preview']['notes'][0]!r}")
    a = box.audit.conn.execute("SELECT event, length(CAST(payload AS BLOB)) FROM audit ORDER BY id").fetchall()
    say(f"[{tag}] audit rows (event, payload_bytes)={a}")
    # human approval UI fragment for pending rows (web.py approvals_view -> _approvals.html)
    import jinja2
    from agentbox.web import _short, _shown
    env = jinja2.Environment(loader=jinja2.FileSystemLoader("/target/agentbox/templates"), autoescape=True)
    env.filters["short"] = _short
    env.finalize = _shown
    html = env.get_template("_approvals.html").render(pending=box.approvals.list(status="pending"), done=[],
                                                      sandbox_id="", timeout=300, error=None)
    say(f"[{tag}] _approvals.html bytes for one pending row={len(html.encode())}")
    # finished-row compaction (expire path) and file size afterwards
    time.sleep(1.1)
    box.expire_stale()
    r2 = box.approvals.conn.execute("SELECT status, length(CAST(args AS BLOB)), length(CAST(preview AS BLOB)) "
                                    "FROM approvals").fetchone()
    fl = box.approvals.conn.execute("PRAGMA freelist_count").fetchone()[0]
    ps = box.approvals.conn.execute("PRAGMA page_size").fetchone()[0]
    say(f"[{tag}] after expiry row={r2} db_bytes={os.path.getsize(db)} freelist_pages={fl} page_size={ps}")
    say(f"[{tag}] audit verify ok={box.audit.verify().ok}")
    box.bursts._burst_pool.shutdown()
    box.audit.conn.close(); box.approvals.conn.close()
    shutil.rmtree(home, ignore_errors=True)

run(65536, "128KiB")
Path("/scratch/h.out").write_text("\n".join(OUT) + "\n")
