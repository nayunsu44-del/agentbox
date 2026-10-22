"""h-session bounded harness: browser-session lifecycle vs human-token rotation, scope, lease keys.
Runs only inside sbx. Docker is replaced by a dummy client (no daemon). Dummy tokens only."""
import os, sys, shutil, types
sys.path.insert(0, "/target")
import docker

class _FakeClient:
    def info(self):
        return {"Runtimes": {"runc": {}}}
    def close(self):
        pass
docker.from_env = lambda *a, **k: _FakeClient()

# jinja2 is not installed in the sandbox toolchain: stub the template renderer only.
# Authorization dependencies run before render(), so this does not affect any auth decision.
from fastapi.responses import HTMLResponse
class _Env:
    def __init__(self):
        self.globals, self.filters = {}, {}
class _Tpl:
    def __init__(self, directory=None):
        self.env = _Env()
    def TemplateResponse(self, request, name, ctx, headers=None):
        return HTMLResponse(f"<rendered {name}>", headers=headers)
_m = types.ModuleType("fastapi.templating"); _m.Jinja2Templates = _Tpl
sys.modules["fastapi.templating"] = _m

from fastapi.testclient import TestClient
from agentbox import api, desktop as D

HOME = "/scratch/home"
shutil.rmtree(HOME, ignore_errors=True)
os.makedirs(HOME)
os.environ["AGENTBOX_HOME"] = HOME
H = {"host": "testserver"}

def out(k, v):
    print(f"{k}: {v}")

def build(token):
    os.environ["AGENTBOX_HUMAN_TOKEN"] = token
    app, box, ht = api.build()
    return TestClient(app, base_url="http://testserver", follow_redirects=False), box

# ---- 1. login with OLD token, get '*' cookie -------------------------------------------
c, box = build("hum_OLD_dummy_token_aaaaaaaaaaaa")
r = c.post("/login", data={"token": "hum_OLD_dummy_token_aaaaaaaaaaaa"})
cookie_old = r.cookies.get(D.COOKIE)
out("1.login_old_token.status", r.status_code)
out("1.cookie_issued", bool(cookie_old))
out("1.set-cookie attrs", r.headers.get("set-cookie").split(";", 1)[1].strip())
r = c.get("/ui/approvals", cookies={D.COOKIE: cookie_old})
out("1.ui_approvals_with_cookie.status", r.status_code)
box.close()

# ---- 2. owner rotates human token and restarts (same DB) ------------------------------
c, box = build("hum_NEW_dummy_token_bbbbbbbbbbbb")
r = c.get("/sandboxes", headers={"Authorization": "Bearer hum_OLD_dummy_token_aaaaaaaaaaaa"})
out("2.old_token_header.status", r.status_code)
r = c.post("/login", data={"token": "hum_OLD_dummy_token_aaaaaaaaaaaa"})
out("2.old_token_form_login.cookie_issued", bool(r.cookies.get(D.COOKIE)))
r = c.get("/ui/approvals", cookies={D.COOKIE: cookie_old})
out("2.OLD_COOKIE_ui_approvals.status", r.status_code)
r = c.get("/ui/sandboxes", cookies={D.COOKIE: cookie_old})
out("2.OLD_COOKIE_ui_sandboxes.status", r.status_code)
r = c.post("/ui/approvals/apr_dummy/deny", cookies={D.COOKIE: cookie_old})
out("2.OLD_COOKIE_post_ui_decide.status (auth passed; dummy id)", r.status_code)
r = c.get("/ui", cookies={D.COOKIE: cookie_old})
out("2.OLD_COOKIE_ui_index.status", r.status_code)
row = box.desktop._db.execute("SELECT public, scope, expires - strftime('%s','now') FROM ui_sessions").fetchall()
out("2.ui_sessions rows (public, scope, seconds_left)", [(a, b, int(cc)) for a, b, cc in row])
out("2.any API to revoke all sessions", [n for n in dir(box.desktop) if "revoke" in n or "all_sessions" in n])

# ---- 3. scope enforcement for desktop-link sessions -----------------------------------
sid = "sb_dummy01"
t = box.desktop.issue_ticket(sid)
r = c.get(f"/login?ticket={t}")
out("3.sandbox_ticket_at_/login.cookie_issued", bool(r.cookies.get(D.COOKIE)))
t = box.desktop.issue_ticket(sid)
r = c.get(f"/sandboxes/{sid}/desktop?ticket={t}", cookies={D.COOKIE: cookie_old})
cookie_scoped = r.cookies.get(D.COOKIE)
out("3.redeem_sandbox_ticket.status", r.status_code)
out("3.scope_of_new", box.desktop.session_scope(cookie_scoped)[1])
out("3.previous_star_session_still_valid_after_cookie_replaced", box.desktop.session_scope(cookie_old))
for path in ["/ui/approvals", "/ui/sandboxes", f"/sandboxes/{sid}/outbox", "/approvals/apr_x/capture.png"]:
    out(f"3.scoped_cookie GET {path}", c.get(path, cookies={D.COOKIE: cookie_scoped}).status_code)
out("3.scoped_cookie GET /ui (redirect=no session)", c.get("/ui", cookies={D.COOKIE: cookie_scoped}).headers.get("location"))
out("3.scoped_cookie state other sid", c.get("/sandboxes/sb_other/desktop/state", cookies={D.COOKIE: cookie_scoped}).status_code)
out("3.scoped_cookie takeover other sid", c.post("/sandboxes/sb_other/desktop/takeover", cookies={D.COOKIE: cookie_scoped}).status_code)
out("3.scoped_cookie handback other sid", c.post("/sandboxes/sb_other/desktop/handback", cookies={D.COOKIE: cookie_scoped}).status_code)
out("3.scoped session() for own sid", box.desktop.session(cookie_scoped, sid) is not None)
out("3.scoped session() for other sid", box.desktop.session(cookie_scoped, "sb_other"))
out("3.cross-origin state with star cookie", c.get(f"/sandboxes/{sid}/desktop/state", cookies={D.COOKIE: cookie_old},
                                                   headers={"origin": "http://evil.example"}).status_code)

# ---- 4. lease keyed by public id ------------------------------------------------------
dc = box.desktop
ca, pa = dc.new_session("*")
cb, pb = dc.new_session("*")
dc.take("sb_L", pa)
try:
    dc.take("sb_L", pb)
except PermissionError as e:
    out("4.take_by_other_session_error_contains_owner_public_id", pa in str(e))
out("4.may_connect control (other session)", dc.may_connect("sb_L", pb, "control"))
out("4.may_connect control (owner)", dc.may_connect("sb_L", pa, "control"))
# public ids are only ever derived from the cookie hash lookup; knowing pa does not yield a cookie
out("4.session() with public id as cookie", dc.session(pa, "sb_L"))
# ---- 5. logout ends only the presented session ----------------------------------------
r = c.post("/logout", cookies={D.COOKIE: ca})
out("5.logout.status", r.status_code)
out("5.lease_after_owner_logout", dc.lease("sb_L"))
out("5.other session still valid", dc.session(cb) is not None)
box.close()

# ---- 6. WebSocket upgrade gate (origin + cookie scope + lease) -------------------------
c, box = build("hum_NEW_dummy_token_bbbbbbbbbbbb")
from starlette.websockets import WebSocketDisconnect
dc = box.desktop
cs, ps = dc.new_session("*")
cl, pl = dc.new_session("sb_W")
def ws_try(label, path, cookie, origin):
    hdr = {"origin": origin} if origin else {}
    try:
        with c.websocket_connect(path, cookies={D.COOKIE: cookie} if cookie else {}, headers=hdr) as w:
            w.receive_bytes()
        out(label, "accepted")
    except WebSocketDisconnect as e:
        out(label, f"closed code={e.code}")
    except Exception as e:
        out(label, f"{type(e).__name__}: {e}")
ws_try("6.ws cross-origin star cookie view", "/sandboxes/sb_W/desktop/ws?mode=view", cs, "http://evil.example")
ws_try("6.ws same-origin no cookie", "/sandboxes/sb_W/desktop/ws?mode=view", None, "http://testserver")
ws_try("6.ws scoped cookie other sid", "/sandboxes/sb_X/desktop/ws?mode=view", cl, "http://testserver")
ws_try("6.ws star cookie control without lease", "/sandboxes/sb_W/desktop/ws?mode=control", cs, "http://testserver")
ws_try("6.ws bad mode", "/sandboxes/sb_W/desktop/ws?mode=admin", cs, "http://testserver")
ws_try("6.ws same-origin star cookie view (passes gate; dummy sandbox missing -> 1011)", "/sandboxes/sb_W/desktop/ws?mode=view", cs, "http://testserver")
ws_try("6.ws no Origin header star cookie view (passes gate -> 1011)", "/sandboxes/sb_W/desktop/ws?mode=view", cs, None)
box.close()
