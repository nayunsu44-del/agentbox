
# run-4 h-preauth: bounded local checks for the pre-authentication work-imbalance unit.
# Docker daemon is stubbed (no socket in the sandbox); target code is imported read-only from /target.
import asyncio, io, json, os, resource, shutil, tarfile, time

os.environ["AGENTBOX_HOME"] = "/scratch/ab6"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_preauth_test_token_0123456789"
os.environ["AGENTBOX_DESKTOP_IMAGE"] = "agentbox-desktop:0.1"
os.environ["TMPDIR"] = "/scratch"
OUT = {"checks": []}
def log(n, **kw):
    kw["check"] = n; OUT["checks"].append(kw); print(f"[{n}] {json.dumps(kw, ensure_ascii=False)[:1200]}", flush=True)

CREATES = []
class FakeContainer:
    def get_archive(self, path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            ti = tarfile.TarInfo("novnc/core/rfb.js"); ti.size = 8; tf.addfile(ti, io.BytesIO(b"/*rfb*/"))
        buf.seek(0); return buf, {}
    def remove(self, force=False): pass
class FakeContainers:
    def create(self, image, command=None, **kw):
        CREATES.append(image); return FakeContainer()
class FakeDocker:
    def __init__(self): self.containers = FakeContainers()
    def info(self): return {"Runtimes": {"runc": {}}}
import docker
docker.from_env = lambda: FakeDocker()

import starlette.requests as sreq, starlette.formparsers as sfp
JSON_CALLS, SPOOL = [], []
_real_json = sreq.Request.json
async def _json(self):
    JSON_CALLS.append(len(self._body)); return await _real_json(self)
sreq.Request.json = _json
_real_spool = sfp.SpooledTemporaryFile
class RecSpool(_real_spool):
    def __init__(self, *a, **k):
        super().__init__(*a, **k); self._n = 0; SPOOL.append({"spool_max_size": k.get("max_size", a[0] if a else None)})
    def write(self, b):
        n = super().write(b); self._n += len(b)
        if getattr(self, "_rolled", False) and not getattr(self, "_seen", False):
            self._seen = True
            try: SPOOL[-1]["rolled_on_disk_bytes"] = os.fstat(self._file.fileno()).st_size
            except Exception as e: SPOOL[-1]["stat_error"] = repr(e)
        return n
    def close(self):
        SPOOL[-1]["part_bytes_written"] = self._n; return super().close()
sfp.SpooledTemporaryFile = RecSpool

from agentbox.config import Settings
import agentbox.api as api
app, box, human_token = api.build(Settings())
log("build", runtime=box.sandboxes.runtime, home=str(box.sandboxes.settings.home), python=os.sys.version.split()[0])
def rss_kb(): return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

async def call(method, path, *, headers=None, body=b"", chunk=65536):
    hs = {"host": "127.0.0.1:8765", "content-length": str(len(body))}
    for k, v in (headers or {}).items(): hs[k] = v
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
             "headers": [(k.lower().encode(), str(v).encode()) for k, v in hs.items()],
             "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 8765), "state": {}}
    st = {"off": 0, "status": None, "err": None, "body": b"", "final": False}
    async def receive():
        await asyncio.sleep(0)
        if st["off"] < len(body):
            p = body[st["off"]:st["off"] + chunk]; st["off"] += len(p)
            return {"type": "http.request", "body": p, "more_body": st["off"] < len(body)}
        if not st["final"]:
            st["final"] = True; return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}
    async def send(m):
        if m["type"] == "http.response.start": st["status"] = m["status"]
        elif m["type"] == "http.response.body": st["body"] += m.get("body", b"")
    try: await app(scope, receive, send)
    except BaseException as e: st["err"] = type(e).__name__ + ": " + str(e)[:90]
    return {"status": st["status"], "err": st["err"], "consumed": st["off"], "body": st["body"]}
def run(c): return asyncio.run(c)

# ---- 1. pre-auth JSON body ----
for mib in (4, 16):
    n = mib * 1024 * 1024
    body = b'{"source_dir": null, "template": "cli", "pad": "' + b"A" * (n - 46) + b'"}'
    for path in ("/sandboxes", "/sandboxes/sid1/tools/exec", "/sandboxes/sid1/restore", "/approvals/apr1"):
        JSON_CALLS.clear(); before = rss_kb()
        r = run(call("POST", path, headers={"content-type": "application/json"}, body=body))
        log("preauth_json_body", path=path, status=r["status"], body_bytes=len(body),
            bytes_consumed_before_response=r["consumed"], json_decodes_before_auth=JSON_CALLS,
            rss_kb_growth=rss_kb() - before)
    del body
# ---- 2. pre-auth multipart spool ----
SPOOL.clear()
bnd = "X-BOUNDARY"; part = b"B" * (4 * 1024 * 1024)
body = (b"--" + bnd.encode() + b'\r\nContent-Disposition: form-data; name="files"; filename="a.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + part + b"\r\n--" + bnd.encode() + b"--\r\n")
r = run(call("POST", "/sandboxes/sid1/files", headers={"content-type": "multipart/form-data; boundary=" + bnd}, body=body))
log("preauth_multipart_spool", path="/sandboxes/sid1/files", status=r["status"], body_bytes=len(body),
    bytes_consumed_before_response=r["consumed"], spooled_temp_file=SPOOL,
    endpoint_per_file_cap_bytes=50 * 1024 * 1024, endpoint_body_ran=False, tmpdir="/scratch")
del body, part
# ---- 3. /login ----
def rows(ev): return box.audit.conn.execute("SELECT COUNT(*) FROM audit WHERE event=?", (ev,)).fetchone()[0]
base = rows("ui_login_failed")
r1 = run(call("POST", "/login", headers={"content-type": "application/x-www-form-urlencoded"}, body="token=%C3%BCn%C3%AFcode".encode()))
n1 = rows("ui_login_failed") - base
r2 = run(call("POST", "/login", headers={"content-type": "application/x-www-form-urlencoded"}, body=b"token=wrong-ascii-token"))
n2 = rows("ui_login_failed") - base
t0 = time.time()
for _ in range(50):
    run(call("POST", "/login", headers={"content-type": "application/x-www-form-urlencoded"}, body=b"token=nope"))
el = time.time() - t0
log("login_failed_audit", nonascii_status=r1["status"], nonascii_error=r1["err"],
    nonascii_rows_added=n1, ascii_wrong_status=r2["status"], ascii_wrong_rows_added=n2,
    rows_after_50_more=rows("ui_login_failed"), seconds_for_50=round(el, 3),
    audit_rows_total=box.audit.conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0],
    audit_db_bytes=os.path.getsize(str(box.sandboxes.settings.db_path)))
# ---- 4. unauthenticated surfaces ----
for path in ("/healthz", "/openapi.json", "/docs", "/redoc", "/static/htmx.min.js"):
    r = run(call("GET", path)); log("unauth_surface", path=path, status=r["status"])
h = run(call("GET", "/healthz"))
log("healthz_body", body=h["body"][:200].decode("utf-8", "replace"))
# ---- 5. novnc ----
home = box.sandboxes.settings.home; novnc = home / "novnc"
shutil.rmtree(novnc, ignore_errors=True); CREATES.clear()
r = run(call("GET", "/static/novnc/core/rfb.js"))
log("novnc_first_unauth", status=r["status"], docker_containers_created=len(CREATES),
    extracted=[str(p.relative_to(home)) for p in novnc.rglob("*")])
CREATES.clear(); r = run(call("GET", "/static/novnc/core/rfb.js"))
log("novnc_steady_state", status=r["status"], docker_containers_created=len(CREATES))
shutil.rmtree(novnc, ignore_errors=True); CREATES.clear()
async def burst(): return await asyncio.gather(*[call("GET", "/static/novnc/core/rfb.js") for _ in range(6)])
res = run(burst())
log("novnc_six_concurrent_unauth", statuses=[x["status"] for x in res], errors=[x["err"] for x in res],
    docker_containers_created=len(CREATES))
CREATES.clear()
for i in range(3):
    shutil.rmtree(novnc, ignore_errors=True)
    r = run(call("GET", "/static/novnc/does-not-exist.js"))
    log("novnc_missing_asset_unauth", attempt=i, status=r["status"], creates_so_far=len(CREATES))
shutil.rmtree(novnc, ignore_errors=True)
# ---- 6. access-control boundary with a sandbox-scoped session ----
conn = box.sandboxes.conn
for sid in ("sb-A", "sb-B"):
    conn.execute("INSERT OR REPLACE INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at, template)"
                 " VALUES (?,?,?,?,?,?,?,?,?)", (sid, "cnt-" + sid, "/host/secret-src-" + sid, "img", "runc", "hash", "running", "2026-01-01", "desktop"))
cookieA, pubA = box.desktop.new_session("sb-A")
ck = {"cookie": "agentbox_session=" + cookieA}
for m, p in [("GET", "/ui/sandboxes/sb-B"), ("GET", "/ui/sandboxes/sb-A"), ("GET", "/ui"),
             ("GET", "/ui/sandboxes"), ("GET", "/ui/audit"), ("GET", "/sandboxes/sb-B/outbox"),
             ("GET", "/sandboxes/sb-B/desktop"), ("GET", "/sandboxes/sb-B/desktop/state")]:
    r = run(call(m, p, headers=ck))
    log("scoped_session_probe", path=p, status=r["status"], err=r["err"],
        leaks_other_sid=(b"sb-B" in r["body"]) if p == "/ui/sandboxes/sb-B" else None)
log("scoped_session", public=pubA, scope="sb-A")
# ---- 7. non-ASCII bearer ----
for path in ("/sandboxes", "/approvals/apr1"):
    r = run(call("GET", path, headers={"authorization": "Bearer tok\u00fc"}))
    log("nonascii_bearer", path=path, status=r["status"], error=r["err"])
r = run(call("POST", "/approvals/apr-1", headers={"authorization": "Bearer tok\u00fc", "content-type": "application/json"},
             body=b'{"decision": "approve"}'))
log("nonascii_bearer_approval_post", status=r["status"], error=r["err"],
    approval_forbidden_rows=rows("approval_forbidden"))
try: box.close()
except Exception: pass
with open("/scratch/h.out", "w", encoding="utf-8") as f: json.dump(OUT, f, ensure_ascii=False, indent=1)
print("WROTE /scratch/h.out", flush=True)
