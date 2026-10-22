"""v05 verifier harness (independent of the hunter's). Runs only inside sbx: no network, no Docker, uid 65534.

Question: does a '*' browser session minted under human token OLD stay valid after the owner rotates to token NEW
and restarts on the same agentbox.db?  Dummy tokens and dummy resources only; everything lives in /scratch.

Docker is replaced by a dummy client (no daemon) and Jinja2 (absent in sbx) by a stub renderer. The renderer is only
called AFTER a route's authorization dependencies have run, so it cannot influence an authorization decision.
"""
import hashlib
import inspect
import os
import secrets
import shutil
import sys
import time

sys.path.insert(0, "/target")
import docker


class _NoDocker:
    def info(self):
        return {"Runtimes": {"runc": {}}}

    def close(self):
        pass


docker.from_env = lambda *a, **k: _NoDocker()

import types
from fastapi.responses import HTMLResponse


class _Env:
    def __init__(self):
        self.globals, self.filters = {}, {}


class _Tpl:
    def __init__(self, directory=None):
        self.env = _Env()

    def TemplateResponse(self, request, name, ctx, headers=None):
        return HTMLResponse(f"<rendered {name}>", headers=headers)


_stub = types.ModuleType("fastapi.templating")  # starlette 1.x raises ImportError at import time without jinja2
_stub.Jinja2Templates = _Tpl
sys.modules["fastapi.templating"] = _stub

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from agentbox import api, desktop as D

LINES = []


def out(k, v):
    s = f"{k}: {v}"
    print(s, flush=True)
    LINES.append(s)


def new_home(name):
    h = f"/scratch/{name}"
    shutil.rmtree(h, ignore_errors=True)
    os.makedirs(h)
    return h


def build(home, token):
    """Same as starting the control plane: api.build() reads Settings().human_token() once."""
    os.environ["AGENTBOX_HOME"] = home
    os.environ.pop("AGENTBOX_DB", None)
    if token is None:
        os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
    else:
        os.environ["AGENTBOX_HUMAN_TOKEN"] = token
    app, box, ht = api.build()
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    return c, box, app


def ck(cookie):
    return {"cookie": f"{D.COOKIE}={cookie}"}


def bearer(tok):
    return {"authorization": f"Bearer {tok}"}


def get(c, path, headers=None):
    r = c.get(path, headers=headers or {})
    c.cookies.clear()
    return r


def post(c, path, headers=None, data=None):
    r = c.post(path, headers=headers or {}, data=data)
    c.cookies.clear()
    return r


OLD = "hum_V05_old_dummy_token_aaaaaaaaaaaaaaaa"
NEW = "hum_V05_new_dummy_token_bbbbbbbbbbbbbbbb"

# ---------------------------------------------------------------------------------------------------------------
out("0.sys.version", sys.version.split()[0])
out("0.uid", os.getuid())
# ---- 0. pure DesktopControl: no web app, no stubs -------------------------------------------------------------
home0 = new_home("p0")
db0 = home0 + "/s.db"
d1 = D.DesktopControl(db_path=db0)
cookie0, public0 = d1.new_session()
d1.close()
d2 = D.DesktopControl(db_path=db0)  # = process restart on the same database
out("0.new DesktopControl(db) -> old session_scope", d2.session_scope(cookie0) == (public0, "*"))
out("0.ui_sessions columns", [r[1] for r in d2._db.execute("PRAGMA table_info(ui_sessions)")])
out("0.DesktopControl.__init__ signature", str(inspect.signature(D.DesktopControl.__init__)))
out("0.DesktopControl public API", sorted(n for n in dir(d2) if not n.startswith("_")))
d2.close()

# ---- A. rotation via AGENTBOX_HUMAN_TOKEN, restart on same DB -------------------------------------------------
home = new_home("pa")
c, box, app = build(home, OLD)
r = post(c, "/login", data={"token": OLD})
cookie_old = r.cookies.get(D.COOKIE)
out("A1.POST /login(OLD) status", r.status_code)
out("A1.cookie issued", bool(cookie_old))
out("A1.set-cookie attrs", r.headers.get("set-cookie", "").split(";", 1)[-1].strip())
out("A1.baseline GET /ui/approvals with cookie_old", get(c, "/ui/approvals", ck(cookie_old)).status_code)
public_old = box.desktop.session_scope(cookie_old)[0]
box.close()

# owner rotates the secret and restarts (same AGENTBOX_HOME -> same agentbox.db)
c, box, app = build(home, NEW)
out("A2.same db file", os.path.exists(home + "/agentbox.db"))
out("A2.Bearer OLD  GET /sandboxes", get(c, "/sandboxes", bearer(OLD)).status_code)
out("A2.Bearer NEW  GET /sandboxes (control)", get(c, "/sandboxes", bearer(NEW)).status_code)
r = post(c, "/login", data={"token": OLD})
out("A2.POST /login(OLD) cookie issued", bool(r.cookies.get(D.COOKIE)))
r = post(c, "/login", data={"token": NEW})
cookie_new = r.cookies.get(D.COOKIE)
out("A2.POST /login(NEW) cookie issued (control)", bool(cookie_new))
forged = secrets.token_urlsafe(32)
out("A2.forged cookie GET /ui/approvals (control)", get(c, "/ui/approvals", ck(forged)).status_code)
out("A2.forged cookie GET /ui (control)", (lambda x: (x.status_code, x.headers.get("location")))(get(c, "/ui", ck(forged))))
out("A2.no cookie GET /ui/approvals (control)", get(c, "/ui/approvals").status_code)

# pending dummy approval (a dummy 'agent action' waiting for the human)
apr = box.approvals.create(sandbox_id="sb_v05dummy", tool="exec", args={"cmd": "echo v05-dummy"},
                           rule_id="dummy", rule_reason="v05 dummy", preview={})
aid = apr["id"]
out("A3.dummy approval status before", box.approvals.get(aid)["status"])

out("A3.STALE cookie_old GET /ui (index)", (lambda x: (x.status_code, x.headers.get("location")))(get(c, "/ui", ck(cookie_old))))
out("A3.STALE cookie_old GET /ui/approvals", get(c, "/ui/approvals", ck(cookie_old)).status_code)
out("A3.STALE cookie_old GET /ui/sandboxes", get(c, "/ui/sandboxes", ck(cookie_old)).status_code)
out("A3.STALE cookie_old GET /ui/audit", get(c, "/ui/audit", ck(cookie_old)).status_code)
out("A3.STALE cookie_old GET /ui/notify", get(c, "/ui/notify", ck(cookie_old)).status_code)
r = post(c, f"/ui/approvals/{aid}/deny", ck(cookie_old))
out("A3.STALE cookie_old POST /ui/approvals/<dummy>/deny", r.status_code)
a2 = box.approvals.get(aid)
out("A3.dummy approval after", {"status": a2["status"], "decided_by": a2["decided_by"]})
ev = [e for e in box.audit.list(limit=1000) if e["event"] == "approval_decision"]
out("A3.audit approval_decision payload", [e["payload"] for e in ev])
out("A3.stale session public id", public_old)
out("A3.audit session id == stale cookie's session id", any(e["payload"].get("session") == public_old for e in ev))

# the ws gate (api.py desktop_ws): stale cookie vs none; dummy sandbox does not exist so 1011 means 'past auth gates'
def ws_try(label, cookie):
    hdr = {"origin": "http://testserver"}
    if cookie:
        hdr["cookie"] = f"{D.COOKIE}={cookie}"
    try:
        with c.websocket_connect("/sandboxes/sb_v05dummy/desktop/ws?mode=view", headers=hdr) as w:
            w.receive_bytes()
        out(label, "accepted")
    except WebSocketDisconnect as e:
        out(label, f"closed code={e.code}")
    except Exception as e:  # noqa
        out(label, f"{type(e).__name__}: {e}")


ws_try("A3.WS view, STALE cookie_old (1011 = passed 4401/4403 gates)", cookie_old)
ws_try("A3.WS view, no cookie (control, 4401 expected)", None)
ws_try("A3.WS view, forged cookie (control, 4401 expected)", forged)

now = time.time()
rows = box.desktop._db.execute("SELECT public, scope, expires FROM ui_sessions ORDER BY created").fetchall()
out("A4.ui_sessions rows (public, scope, seconds_left)", [(p, s, int(e - now)) for p, s, e in rows])
paths = sorted({getattr(r_, "path", "") for r_ in app.routes})
out("A4.routes with session/revoke/logout in path", [p for p in paths if any(k in p for k in ("session", "revoke", "logout"))])
out("A4.DesktopControl/AgentBox attrs with revoke|logout|all_sessions",
    sorted(n for n in dir(box.desktop) + dir(box) if any(k in n.lower() for k in ("revoke", "logout", "all_sessions", "end_all", "kill"))))


def dep_names(dep, acc):
    for sub in dep.dependencies:
        acc.add(getattr(sub.call, "__name__", str(sub.call)))
        dep_names(sub, acc)


cookie_deps = {"screen_principal", "screen_human", "desktop_human"}
reach = []
for r_ in app.routes:
    dep = getattr(r_, "dependant", None)
    if dep is None:
        continue
    acc = set()
    dep_names(dep, acc)
    hit = acc & cookie_deps
    if hit:
        reach.append(f"{sorted(r_.methods or [])} {r_.path} <- {sorted(hit)}")
out("A4.routes whose auth dependency accepts the cookie principal", sorted(reach))

# C. login / ticket redemption over an existing cookie does not end the presented session
r = post(c, "/login", ck(cookie_old), data={"token": NEW})
c_login2 = r.cookies.get(D.COOKIE)
out("C1.POST /login(NEW) presenting stale cookie: new cookie issued", bool(c_login2))
out("C1.presented (replaced) session still valid", box.desktop.session_scope(cookie_old) is not None)
r = post(c, "/ui/ticket", bearer(NEW))
tpath = r.json()["path"]
out("C2.POST /ui/ticket (Bearer NEW) status", r.status_code)
r = get(c, tpath, ck(c_login2))
c_tkt = r.cookies.get(D.COOKIE)
out("C2.GET /login?ticket=* presenting cookie: new cookie issued", bool(c_tkt))
out("C2.presented (replaced) session still valid", box.desktop.session_scope(c_login2) is not None)
t3 = box.desktop.issue_ticket("sb_v05dummy")
r = get(c, f"/sandboxes/sb_v05dummy/desktop?ticket={t3}", ck(c_tkt))
c_scoped = r.cookies.get(D.COOKIE)
out("C3.GET /sandboxes/<sid>/desktop?ticket presenting '*' cookie: scoped cookie issued", bool(c_scoped))
out("C3.presented '*' session still valid", box.desktop.session_scope(c_tkt) is not None)
out("C3.scoped cookie GET /ui/approvals (scope check holds)", get(c, "/ui/approvals", ck(c_scoped)).status_code)
r = post(c, "/logout", ck(c_login2))
out("C4.POST /logout(cookie X) status", r.status_code)
out("C4.X valid after logout", box.desktop.session_scope(c_login2) is not None)
out("C4.other sessions untouched by logout (stale, c_tkt)",
    (box.desktop.session_scope(cookie_old) is not None, box.desktop.session_scope(c_tkt) is not None))

# D. only the 12 h TTL ends the stale session (negative control): push its expiry into the past
box.desktop._db.execute("UPDATE ui_sessions SET expires = ? WHERE hash = ?",
                        (time.time() - 1, hashlib.sha256(cookie_old.encode()).hexdigest()))
out("D1.after expiry: STALE cookie_old GET /ui/approvals", get(c, "/ui/approvals", ck(cookie_old)).status_code)
box.close()

# ---- B. rotation by regenerating data/human_token (no env var) -------------------------------------------------
homeb = new_home("pb")
c, box, app = build(homeb, None)
tok1 = open(homeb + "/human_token").read().strip()
r = post(c, "/login", data={"token": tok1})
cookie1 = r.cookies.get(D.COOKIE)
out("B1.login(token1) cookie issued", bool(cookie1))
box.close()
os.remove(homeb + "/human_token")
c, box, app = build(homeb, None)
tok2 = open(homeb + "/human_token").read().strip()
out("B2.token regenerated (differs)", tok1 != tok2)
out("B2.Bearer token1 GET /sandboxes", get(c, "/sandboxes", bearer(tok1)).status_code)
out("B2.Bearer token2 GET /sandboxes (control)", get(c, "/sandboxes", bearer(tok2)).status_code)
out("B2.STALE cookie1 GET /ui/approvals", get(c, "/ui/approvals", ck(cookie1)).status_code)
out("B2.STALE cookie1 GET /ui/sandboxes", get(c, "/ui/sandboxes", ck(cookie1)).status_code)
box.close()

# ---- E. prototype of the proposed fix (in-memory monkeypatch only; target files are read-only) ------------------
orig_init = D.DesktopControl.__init__
orig_new = D.DesktopControl.new_session
orig_scope = D.DesktopControl.session_scope


def fp(tok):
    return hashlib.sha256(tok.encode()).hexdigest()[:16]


def init_fix(self, *a, **k):
    orig_init(self, *a, **k)
    self._gen = fp(os.environ.get("AGENTBOX_HUMAN_TOKEN", ""))
    cols = [r_[1] for r_ in self._db.execute("PRAGMA table_info(ui_sessions)")]
    if "gen" not in cols:
        self._db.execute("ALTER TABLE ui_sessions ADD COLUMN gen TEXT NOT NULL DEFAULT ''")
    self._db.execute("DELETE FROM ui_sessions WHERE gen != ?", (self._gen,))
    self._db.execute("DELETE FROM ui_tickets")


def new_fix(self, scope="*"):
    cookie, public = orig_new(self, scope)
    with self._lock:
        self._db.execute("UPDATE ui_sessions SET gen = ? WHERE hash = ?", (self._gen, D._h(cookie)))
    return cookie, public


def scope_fix(self, cookie):
    got = orig_scope(self, cookie)
    if not got:
        return None
    with self._lock:
        row = self._db.execute("SELECT gen FROM ui_sessions WHERE hash = ?", (D._h(cookie),)).fetchone()
    return got if row and row[0] == self._gen else None


D.DesktopControl.__init__ = init_fix
D.DesktopControl.new_session = new_fix
D.DesktopControl.session_scope = scope_fix
homee = new_home("pe")
c, box, app = build(homee, OLD)
r = post(c, "/login", data={"token": OLD})
ce = r.cookies.get(D.COOKIE)
out("E1.(fix prototype) before rotation: cookie GET /ui/approvals", get(c, "/ui/approvals", ck(ce)).status_code)
box.close()
c, box, app = build(homee, NEW)
out("E2.(fix prototype) after rotation: old cookie GET /ui/approvals", get(c, "/ui/approvals", ck(ce)).status_code)
r = post(c, "/login", data={"token": NEW})
cn = r.cookies.get(D.COOKIE)
out("E3.(fix prototype) new token login works", get(c, "/ui/approvals", ck(cn)).status_code)
box.close()
c, box, app = build(homee, NEW)  # restart again with the same token: new sessions must survive
out("E4.(fix prototype) restart without rotation keeps login", get(c, "/ui/approvals", ck(cn)).status_code)
box.close()
D.DesktopControl.__init__ = orig_init
D.DesktopControl.new_session = orig_new
D.DesktopControl.session_scope = orig_scope

with open("/scratch/v05_rotation.out", "w") as f:
    f.write("\n".join(LINES) + "\n")
