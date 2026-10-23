"""h-retention bounded checks. Runs inside tools/sbx only; writes only under /scratch."""
import gzip
import os
import shutil
import signal
import sqlite3
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path

import agentbox.retention as R
from agentbox.audit import AuditLog
from agentbox.approvals import ApprovalStore

ROOT = Path("/scratch/work")
shutil.rmtree(ROOT, ignore_errors=True)
ROOT.mkdir()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def fixture(name, n_old=5, n_new=2):
    db = ROOT / f"{name}.db"
    log = AuditLog(db)
    for i in range(n_old):
        log.append(actor="system", event="e", payload={"i": i})
    time.sleep(0.01)
    cut = now()
    time.sleep(0.01)
    for i in range(n_new):
        log.append(actor="system", event="e", payload={"i": n_old + i})
    return db, log, cut


def counts(db):
    c = sqlite3.connect(str(db))
    a = c.execute("SELECT COUNT(*), MIN(id), MAX(id) FROM audit").fetchone()
    an = c.execute("SELECT seq, last_id, archive, archive_sha256 FROM audit_anchor").fetchall()
    c.close()
    return a, an


# ---- Check 1: SIGINT delivered while COMMIT runs (raised by CPython right after the C call returns) ----
print("== check1: KeyboardInterrupt surfacing right after a successful COMMIT ==")
db, log, cut = fixture("c1")
arch = ROOT / "c1.jsonl.gz"
real_connect = sqlite3.connect


class SigAfterCommit(sqlite3.Connection):
    def execute(self, sql, *a):
        r = super().execute(sql, *a)
        if sql == "COMMIT":
            # Same effect as Ctrl-C arriving during the (fsync-bound) COMMIT: the C call completes,
            # then the pending SIGINT is raised as KeyboardInterrupt at the next eval-breaker check.
            signal.raise_signal(signal.SIGINT)
        return r


R.sqlite3 = types.SimpleNamespace(connect=lambda *a, **k: real_connect(*a, factory=SigAfterCommit, **k),
                                  Connection=sqlite3.Connection, Error=sqlite3.Error)
print("before:", counts(db))
try:
    R.prune(db, cut, arch)
    print("prune returned normally")
except BaseException as e:
    print("prune raised:", type(e).__name__, "| context:", type(e.__context__).__name__ if e.__context__ else None,
          repr(e.__context__)[:120] if e.__context__ else "")
R.sqlite3 = sqlite3
print("archive exists after failure:", arch.exists())
print("after:", counts(db))
log2 = AuditLog(db)
print("verify():", log2.verify().as_dict())
try:
    print("verify_archives([archive]):", log2.verify_archives([arch]).as_dict())
except Exception as e:
    print("verify_archives([archive]) raised:", type(e).__name__, str(e)[:100])
print("verify_archives([]):", log2.verify_archives([]).as_dict())

# ---- Check 2: archive write failure (ENOSPC) before the DB transaction ----
print("\n== check2: archive write fails mid-way (simulated ENOSPC) ==")
db, log, cut = fixture("c2")
arch = ROOT / "c2.jsonl.gz"
orig_write = gzip.GzipFile.write
calls = {"n": 0}


def failing_write(self, data):
    calls["n"] += 1
    if calls["n"] > 2:
        raise OSError(28, "No space left on device")
    return orig_write(self, data)


gzip.GzipFile.write = failing_write
try:
    R.prune(db, cut, arch)
except BaseException as e:
    print("prune raised:", type(e).__name__, e)
gzip.GzipFile.write = orig_write
print("partial archive left:", arch.exists(), arch.stat().st_size if arch.exists() else None)
print("db after:", counts(db))
try:
    R.prune(db, cut, arch)
except BaseException as e:
    print("re-run raised:", type(e).__name__, str(e)[:80])

# ---- Check 3: normal prune + ad-hoc deletes still detected, approvals selection ----
print("\n== check3: normal prune, tamper detection, approval selection ==")
db, log, cut = fixture("c3")
st = ApprovalStore(db)
ids = {}
for status in ("pending", "approved", "denied", "executed", "failed", "expired"):
    a = st.create(sandbox_id="sbx_dummy", tool="exec", args={"command": "true"}, rule_id=None, rule_reason=None,
                  preview={})
    if status != "pending":
        st.conn.execute("UPDATE approvals SET status=?, created_at=? WHERE id=?", (status, "2000-01-01T00:00:00.000+00:00", a["id"]))
    else:
        st.conn.execute("UPDATE approvals SET created_at=? WHERE id=?", ("2000-01-01T00:00:00.000+00:00", a["id"]))
    ids[status] = a["id"]
s = R.prune(db, cut, ROOT / "c3.jsonl.gz")
print("summary:", {k: s[k] for k in ("audit_rows", "approval_rows", "first_id", "last_id", "pruned")})
left = {r[0] for r in sqlite3.connect(str(db)).execute("SELECT status FROM approvals")}
print("approval statuses left:", sorted(left))
log3 = AuditLog(db)
print("verify after prune:", log3.verify().as_dict())
print("verify_archives:", log3.verify_archives([ROOT / "c3.jsonl.gz"]).as_dict())
c = sqlite3.connect(str(db), isolation_level=None)
c.execute("DROP TRIGGER audit_no_delete")
first = c.execute("SELECT MIN(id) FROM audit").fetchone()[0]
c.execute("DELETE FROM audit WHERE id = ?", (first,))
print("verify after deleting first post-anchor row:", log3.verify().as_dict())
c.close()
print("done")
