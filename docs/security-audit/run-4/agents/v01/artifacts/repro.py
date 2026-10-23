
import asyncio, inspect, json, os, resource, sys

os.environ["AGENTBOX_HOME"] = "/scratch/home"
os.environ["TMPDIR"] = "/scratch"

out = {}
import starlette, fastapi, uvicorn, starlette.requests as sreq, starlette.formparsers as sfp
out["versions"] = {"python": sys.version.split()[0], "starlette": starlette.__version__,
                   "fastapi": fastapi.__version__, "uvicorn": uvicorn.__version__}
out["uvicorn_run_params"] = sorted(inspect.signature(uvicorn.run).parameters)

# ---- fake docker client (no daemon in sandbox) ----
import docker
class FakeClient:
    def info(self):
        return {"Runtimes": {"runc": {}}}
    def __getattr__(self, name):
        def missing(*a, **k):
            raise RuntimeError("docker call attempted in sandbox: " + name)
        return missing
docker.from_env = lambda *a, **k: FakeClient()

# ---- instrumentation ----
decoded = []
_orig_json = sreq.Request.json
async def json_rec(self):
    raw = await self.body()
    val = await _orig_json(self)
    decoded.append(len(raw))
    return val
sreq.Request.json = json_rec

_OrigSpool = sfp.SpooledTemporaryFile
spools = []
class RecSpool(_OrigSpool):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.rec = {"max_size": getattr(self, "_max_size", None), "written": 0,
                    "rolled_to_disk": False, "disk_bytes": 0, "path": None}
        spools.append(self.rec)
    def write(self, data):
        n = super().write(data)
        r = self.rec
        r["written"] += len(data)
        if getattr(self, "_rolled", False):
            r["rolled_to_disk"] = True
            try:
                r["path"] = str(self.name)
            except Exception:
                pass
            try:
                r["disk_bytes"] = os.fstat(self._file.fileno()).st_size
            except Exception:
                pass
        return n
sfp.SpooledTemporaryFile = RecSpool

# source-visible parser bounds
mp = inspect.getsource(sfp.MultiPartParser)
out["multipart_bounds"] = [ln.strip() for ln in mp.splitlines()
                           if "max_part_size" in ln or "max_files" in ln or "max_fields" in ln
                           or "spool_max_size" in ln][:12]
out["form_kwargs"] = str(inspect.signature(sfp.MultiPartParser.__init__))
req_src = inspect.getsource(sreq.Request.form)
out["request_form_defaults"] = [ln.strip() for ln in req_src.splitlines() if "spool" in ln or "max" in ln]

# ---- real app ----
from agentbox.config import Settings
from agentbox import api
settings = Settings()
app, box, token = api.build(settings)
out["app_built"] = True
out["max_upload_bytes"] = settings.max_upload_bytes

CHUNK = 65536
async def drive(method, path, body, content_type, extra_headers=()):
    st = {"consumed": 0, "consumed_before_start": None, "status": None, "resp_bytes": 0}
    pos = 0
    async def receive():
        nonlocal pos
        if pos >= len(body):
            return {"type": "http.request", "body": b"", "more_body": False}
        c = body[pos:pos + CHUNK]
        pos += len(c)
        st["consumed"] += len(c)
        return {"type": "http.request", "body": c, "more_body": pos < len(body)}
    async def send(message):
        if message["type"] == "http.response.start":
            st["status"] = message["status"]
            if st["consumed_before_start"] is None:
                st["consumed_before_start"] = st["consumed"]
        elif message["type"] == "http.response.body":
            st["resp_bytes"] += len(message.get("body") or b"")
    headers = [(b"host", b"agentbox.example.com"), (b"content-type", content_type.encode()),
               (b"content-length", str(len(body)).encode())] + list(extra_headers)
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
             "query_string": b"", "root_path": "", "headers": headers, "state": {},
             "client": ("203.0.113.7", 50000), "server": ("agentbox.example.com", 443)}
    await app(scope, receive, send)
    return st

def pad_json(n, head, tail):
    room = max(0, n - len(head) - len(tail))
    return (head + "A" * room + tail).encode()

def rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

results = []

async def runall():
    # control: unauthenticated GET with no body
    r0 = await drive("GET", "/healthz", b"", "application/json")
    results.append({"case": "control GET /healthz", **r0, "json_decoded": None, "spools": []})

    big = pad_json(16 * 1024 * 1024, '{"source_dir": null, "template": "cli", "pad": "', '"}')
    before = rss_kb()
    dec0 = len(decoded)
    r = await drive("POST", "/sandboxes", big, "application/json")
    results.append({"case": "POST /sandboxes 16 MiB json", **r,
                    "json_decoded": decoded[dec0:], "body_bytes": len(big),
                    "peak_rss_kb": rss_kb(), "peak_rss_delta_kb": rss_kb() - before, "spools": []})

    for path, head, tail, name in [
        ("/sandboxes/sid1/tools/exec", '{"args": {"pad": "', '"}}', "POST /sandboxes/{sid}/tools/exec 4 MiB json"),
        ("/sandboxes/sid1/restore", '{"snapshot_id": "snap-1", "pad": "', '"}', "POST /sandboxes/{sid}/restore 4 MiB json"),
        ("/approvals/aid1", '{"decision": "approve", "pad": "', '"}', "POST /approvals/{aid} 4 MiB json"),
    ]:
        body = pad_json(4 * 1024 * 1024, head, tail)
        d0 = len(decoded)
        r = await drive("POST", path, body, "application/json")
        results.append({"case": name, **r, "json_decoded": decoded[d0:], "body_bytes": len(body), "spools": []})

    part = b"B" * (4 * 1024 * 1024)
    mp_body = (b"--X-BOUNDARY\r\n"
               b'Content-Disposition: form-data; name="files"; filename="a.bin"\r\n'
               b"Content-Type: application/octet-stream\r\n\r\n" + part + b"\r\n--X-BOUNDARY--\r\n")
    s0 = len(spools)
    r = await drive("POST", "/sandboxes/sid1/files", mp_body,
                    "multipart/form-data; boundary=X-BOUNDARY")
    results.append({"case": "POST /sandboxes/{sid}/files 4 MiB multipart, no cookie", **r,
                    "json_decoded": None, "body_bytes": len(mp_body), "part_bytes": len(part),
                    "spools": spools[s0:], "tempdir": os.environ.get("TMPDIR"),
                    "tmpdir_listing": sorted(os.listdir("/scratch"))})

asyncio.run(runall())
out["results"] = results
print(json.dumps(out, indent=1)[:200000])
