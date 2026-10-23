"""Where does a real asynchronous SIGINT that arrives during a slow sqlite3 COMMIT surface?
Mirrors retention.prune's nested try layout (COMMIT is the last statement of the inner try)."""
import os
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path

print(sys.version.split()[0], "sqlite", sqlite3.sqlite_version)
DB = Path("/scratch/work/h2.db")


def setup():
    for p in (DB, Path(str(DB) + "-wal"), Path(str(DB) + "-shm")):
        p.unlink(missing_ok=True)
    c = sqlite3.connect(str(DB), isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=FULL")
    c.execute("PRAGMA cache_size=-200000")
    c.execute("CREATE TABLE t (x BLOB)")
    return c


def big_txn(c):
    c.execute("BEGIN IMMEDIATE")
    c.execute("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 20000) "
              "INSERT INTO t SELECT randomblob(1000) FROM n")


c = setup()
big_txn(c)
t0 = time.monotonic()
c.execute("COMMIT")
dur = time.monotonic() - t0
c.close()
print(f"calibration: COMMIT took {dur:.3f}s")

results = []
for attempt in range(5):
    c = setup()
    big_txn(c)
    timer = threading.Timer(dur / 3, lambda: os.kill(os.getpid(), signal.SIGINT))
    where = "none"
    committed_flag = False
    try:
        try:
            timer.start()
            c.execute("COMMIT")
        except BaseException as e:
            where = f"inner-except:{type(e).__name__}"
            try:
                c.execute("ROLLBACK")
            except BaseException as e2:
                where += f" then ROLLBACK raised {type(e2).__name__}: {e2}"
            raise
    except BaseException as e:
        where += f" | outer-except:{type(e).__name__} (prune would unlink the archive here)"
    finally:
        timer.cancel()
    try:
        time.sleep(0.05)
    except KeyboardInterrupt:
        where += " | SIGINT surfaced only after the try (late)"
    n = sqlite3.connect(str(DB)).execute("SELECT COUNT(*) FROM t").fetchone()[0]
    results.append((where, n))
    print(f"attempt {attempt}: {where}; rows committed={n}")
    c.close()
