"""parent-live N2 recovery half: run after parent_live_diskfull.py exits (separate process, control plane closed).

Copies the database off the full volume with the SQLite backup API, checks integrity and the audit counts,
then applies the two recovery options to the copy: delete the oldest 100 rows and verify, then delete
every row and verify.

usage: python3 parent_live_diskfull_recovery.py <src-audited> <db> <out.json>
"""
import json
import os
import sqlite3
import sys

SRC, DB, OUT = sys.argv[1:4]
sys.path.insert(0, SRC)
from agentbox.audit import AuditLog  # noqa: E402

res = {}
src = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
res["integrity_after_restart"] = src.execute("pragma integrity_check").fetchone()[0]
res["events"] = dict(src.execute("select event, count(*) from audit group by event").fetchall())
copy = OUT + ".db"
dst = sqlite3.connect(copy)
src.backup(dst)
dst.close()
src.close()
res["verify_as_is"] = str(AuditLog(copy).verify())
con = sqlite3.connect(copy)
con.execute("drop trigger if exists audit_no_delete")
con.execute("delete from audit where id in (select id from audit order by id limit 100)")
con.commit()
con.close()
res["verify_after_deleting_oldest_100"] = str(AuditLog(copy).verify())
con = sqlite3.connect(copy)
con.execute("drop trigger if exists audit_no_delete")  # AuditLog() above re-created it
con.execute("delete from audit")
con.commit()
con.close()
res["verify_after_deleting_all"] = str(AuditLog(copy).verify())
os.remove(copy)
open(OUT, "w").write(json.dumps(res, ensure_ascii=False, indent=1) + "\n")
print(json.dumps(res, ensure_ascii=False, indent=1))
