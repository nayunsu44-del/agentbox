"""v05: does the proposed generation binding (desktop_fixed.py = target desktop.py + patch, written to scratch by the
parent-side helper; the target itself is never touched) stop the rotation problem, keep restart-persistence and survive
the repo's own session unit tests?  Runs only inside sbx.  Dummy values only."""
import os
import shutil
import sys

sys.path.insert(0, "/target")
sys.path.insert(1, "/scratch")
import desktop_fixed as F
import agentbox.desktop as D

LINES = []


def out(k, v):
    s = f"{k}: {v}"
    print(s, flush=True)
    LINES.append(s)


base = "/scratch/pf"
shutil.rmtree(base, ignore_errors=True)
os.makedirs(base)
db = base + "/a.db"

a = F.DesktopControl(db_path=db, token_gen="A")
cookie, pub = a.new_session()
a.close()
b = F.DesktopControl(db_path=db, token_gen="A")
out("F1.restart with the same token keeps the session", b.session_scope(cookie) == (pub, "*"))
t2 = b.issue_ticket("*")
b.close()
c = F.DesktopControl(db_path=db, token_gen="B")
out("F2.token rotated: old session", c.session_scope(cookie))
out("F2.token rotated: old unredeemed ticket", c.redeem(t2, "*"))
ck2, pub2 = c.new_session()
t3 = c.issue_ticket("*")
c.close()
d = F.DesktopControl(db_path=db, token_gen="B")
out("F3.session minted under B survives a restart under B", d.session_scope(ck2) == (pub2, "*"))
out("F3.ticket minted under B survives a restart under B", d.redeem(t3, "*") is not None)
out("F4.revoke_all returns count (>=1)", d.revoke_all())
out("F4.session after revoke_all", d.session_scope(ck2))
d.close()

# a database written by the ORIGINAL class (no gen column) opens, migrates, and drops the legacy sessions once
leg = base + "/legacy.db"
o = D.DesktopControl(db_path=leg)
lc, lp = o.new_session()
o.close()
n = F.DesktopControl(db_path=leg, token_gen="A")
out("F5.legacy db + token_gen: legacy session dropped", n.session_scope(lc))
out("F5.gen column added", "gen" in [r[1] for r in n._db.execute("PRAGMA table_info(ui_sessions)")])
n.close()
leg2 = base + "/legacy2.db"
o = D.DesktopControl(db_path=leg2)
lc2, lp2 = o.new_session()
o.close()
n2 = F.DesktopControl(db_path=leg2)
out("F6.legacy db + default token_gen: session kept (old callers unchanged)", n2.session_scope(lc2) == (lp2, "*"))
n2.close()

import pytest

D.DesktopControl = F.DesktopControl  # run the repo's own session/ticket unit tests against the patched class
rc = pytest.main(["/target/tests/test_m4_unit.py", "-q", "-p", "no:cacheprovider", "--basetemp=/scratch/pt",
                  "-k", "session or ticket or expiry or secrets or lease"])
out("F7.pytest (repo test_m4_unit.py session/ticket/lease tests vs patched class) exit code", int(rc))

with open("/scratch/v05_fix_check.out", "w") as f:
    f.write("\n".join(LINES) + "\n")
