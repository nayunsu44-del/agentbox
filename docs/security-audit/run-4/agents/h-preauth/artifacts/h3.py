
import asyncio, io, json, os, shutil, tarfile

os.environ["AGENTBOX_HOME"] = "/scratch/ab5"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_preauth_test_token_0123456789"
os.environ["AGENTBOX_DESKTOP_IMAGE"] = "agentbox-desktop:0.1"
os.environ["TMPDIR"] = "/scratch"
OUT = {"steps": []}
def log(n, **kw):
    kw["step"] = n; OUT["steps"].append(kw)
    print(f"[{n}] {json.dumps(kw, ensure_ascii=False)[:1400]}", flush=True)

CREATES = []
class FakeContainer:
    def get_archive(self, path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data in (("novnc/core/rfb.js", b"/*rfb*/"),):
                ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        buf.seek(0); return buf, {}
    def remove(self, force=False): pass
class FakeContainers:
    def create(self, image, command=None, **kw):
        CREATES.append({"image": image, "command": str(command)}); return FakeContainer()
class FakeDocker:
    def __init__(self): self.containers = FakeContainers()
    def info(self): return {"Runtimes": {"runc": {}}}
import docker
docker.from_env = lambda: FakeDocker()
from agentbox.config import Settings
import agentbox.api as api
app, box, human_token = api.build(Settings())
log("build", runtime=box.sandboxes.runtime, home=str(box.sandboxes.settings.home))

async def call(method, path, *, headers=None, body=b"", chunk=65536):
    hs = {"host": "127.0.0.1:8765", "content-length": str(len(body))}
    for k, v in (headers or {}).items(): hs[k] = v
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": method, "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": [(k.lower().encode(), str(v).encode()) for k, v in hs.items()],
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
    except BaseException as e: st["err"] = type(e).__name__ + ": " + str(e)[:100]
    return {"status": st["status"], "err": st["err"], "consumed": st["off"], "body": st["body"]}
def run(c): return asyncio.run(c)

# E. novnc unauthenticated docker work
home = box.sandboxes.settings.home; novnc = home / "novnc"
shutil.rmtree(novnc, ignore_errors=True); CREATES.clear()
r = run(call("GET", "/static/novnc/core/rfb.js"))
log("novnc_first", status=r["status"], docker_containers_created=len(CREATES),
    extracted=[str(p.relative_to(home)) for p in novnc.rglob("*")][:4])
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
    log("novnc_missing_path_request", i=i, status=r["status"], creates_so_far=len(CREATES))
shutil.rmtree(novnc, ignore_errors=True)

# F. scoped desktop-link session vs /ui
conn = box.sandboxes.conn
for sid in ("sb-A", "sb-B"):
    conn.execute("INSERT OR REPLACE INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at, template)"
                 " VALUES (?,?,?,?,?,?,?,?,?)", (sid, "cnt-" + sid, "/host/secret-src-" + sid, "img", "runc", "hash", "running", "2026-01-01", "desktop"))
cookieA, pubA = box.desktop.new_session("sb-A")
ck = {"cookie": "agentbox_session=" + cookieA}
probes = [("GET", "/ui/sandboxes/sb-B", "other sandbox page (web.py:195-204)"),
          ("GET", "/ui/sandboxes/sb-A", "own sandbox page"),
          ("GET", "/ui", "index (web.py:164-168)"),
          ("GET", "/ui/sandboxes", "list fragment (browser_human)"),
          ("GET", "/ui/audit", "audit fragment (browser_human)"),
          ("GET", "/sandboxes/sb-B/outbox", "outbox (screen_human)"),
          ("GET", "/sandboxes/sb-B/desktop", "desktop page (session bound to sid)"),
          ("GET", "/sandboxes/sb-B/desktop/state", "desktop state (desktop_human)")]
for m, p, note in probes:
    r = run(call(m, p, headers=ck))
    log("scoped_probe", path=p, status=r["status"], note=note, err=r["err"],
        leaked_other_sid=(b"sb-B" in r["body"]) if p == "/ui/sandboxes/sb-B" else None,
        leaked_template=(b"desktop" in r["body"]) if p == "/ui/sandboxes/sb-B" else None)
log("scoped_session", public=pubA, scope="sb-A", cookie_len=len(cookieA))

# G. non-ASCII bearer on the JSON API
for path in ("/sandboxes", "/approvals/apr1", "/sandboxes/sb-A"):
    r = run(call("GET", path, headers={"authorization": "Bearer tok\u00fc"}))
    log("nonascii_bearer", path=path, status=r["status"], error=r["err"])
r = run(call("POST", "/approvals/apr-1", headers={"authorization": "Bearer tok\u00fc", "content-type": "application/json"},
             body=b'{"decision": "approve"}'))
log("nonascii_bearer_approval_post", status=r["status"], error=r["err"],
    approval_forbidden_rows=box.audit.conn.execute("SELECT COUNT(*) FROM audit WHERE event='approval_forbidden'").fetchone()[0])
try: box.close()
except Exception: pass
with open("/scratch/h3.out", "w", encoding="utf-8") as f: json.dump(OUT, f, ensure_ascii=False, indent=1)
print("WROTE /scratch/h3.out", flush=True)
