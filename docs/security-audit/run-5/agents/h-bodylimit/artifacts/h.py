"""h-bodylimit bounded harness: drives the real agentbox.api.build() ASGI app with raw ASGI messages.
Docker is replaced by a fake client (no daemon). No network, no server socket."""
import asyncio, gc, json, os, resource, sys, tracemalloc
from pathlib import Path

os.environ["AGENTBOX_HOME"] = "/scratch/home"
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_dummy_token_for_audit"

import docker


class _FakeClient:
    def info(self):
        return {"Runtimes": {"runc": {}}}

    def __getattr__(self, name):
        raise RuntimeError("docker not available in harness: " + name)


docker.from_env = lambda *a, **k: _FakeClient()

from agentbox import api  # noqa: E402

out = []


def log(*a):
    s = " ".join(str(x) for x in a)
    out.append(s)
    print(s, flush=True)


app, box, _tok = api.build()


async def call(method, path, headers, chunks, read_all_until_disconnect=True):
    """Send request through the full ASGI stack. chunks: list of bytes."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "root_path": "", "query_string": b"",
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers], "client": ("127.0.0.1", 5),
             "server": ("127.0.0.1", 8765)}
    msgs = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    stats = {"delivered": 0, "receives": 0}
    sent = []

    async def receive():
        stats["receives"] += 1
        if msgs:
            m = msgs.pop(0)
            stats["delivered"] += len(m["body"])
            return m
        await asyncio.sleep(3600)  # client idle

    async def send(m):
        sent.append(m)

    try:
        await asyncio.wait_for(app(scope, receive, send), 20)
        err = None
    except Exception as e:  # noqa: BLE001
        err = repr(e)[:200]
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body[:160], stats, err, len([m for m in sent if m["type"] == "http.response.start"])


async def lifespan_noop():
    pass


async def main():
    H = [("host", "127.0.0.1:8765")]
    J = H + [("content-type", "application/json")]

    # 1. Content-Length over JSON cap (8 MiB) on a JSON route -> 413 before reading
    r = await call("POST", "/sandboxes", J + [("content-length", str(9 * 1024 * 1024))], [b"{}"])
    log("T1 CL over json cap:", r)
    # 2. CL with '+' and space -> 413
    r = await call("POST", "/sandboxes", J + [("content-length", "+2")], [b"{}"])
    log("T2a CL '+2':", r)
    # 3. Duplicate CL: big first, small last -> dict keeps last; streaming counter must still cap
    big = [b"x" * (1024 * 1024)] * 10
    r = await call("POST", "/sandboxes", J + [("content-length", "999999999999"), ("content-length", "2")], big)
    log("T3 dup CL (big,small) + 10 MiB streamed:", r)
    # 4. No CL (chunked) 10 MiB streamed on JSON route
    r = await call("POST", "/sandboxes", J + [("transfer-encoding", "chunked")], big)
    log("T4 chunked 10 MiB on JSON route:", r)
    # 5. Upload path variants (method / trailing slash / double slash) choose json cap
    for m, p in [("PUT", "/sandboxes/sb_x/files"), ("POST", "/sandboxes/sb_x/files/"), ("POST", "//sandboxes/sb_x/files"),
                 ("POST", "/sandboxes/sb_x/files")]:
        r = await call(m, p, H + [("content-type", "multipart/form-data; boundary=b")], big)
        log("T5", m, p, "10 MiB streamed unauth:", r)
    # 6. /login form (unauth, Form) with 10 MiB urlencoded -> cap
    r = await call("POST", "/login", H + [("content-type", "application/x-www-form-urlencoded")], big)
    log("T6 /login 10 MiB urlencoded:", r)
    # 6b. /login multipart with many file parts within cap: parsed + spooled before any check
    parts = b"".join(b"--b\r\nContent-Disposition: form-data; name=\"f%d\"; filename=\"a\"\r\n\r\n" % i + b"y" * 1000 + b"\r\n"
                     for i in range(900))
    parts += b"--b\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nwrong\r\n--b--\r\n"
    r = await call("POST", "/login", H + [("content-type", "multipart/form-data; boundary=b"), ("content-length", str(len(parts)))], [parts])
    log("T6b /login multipart 900 file parts (%d bytes):" % len(parts), r[0], r[3])

    # 6c. 5000-digit Content-Length (int() digit limit) and root_path upload selection
    r = await call("POST", "/sandboxes", J + [("content-length", "9" * 5000)], [b"{}"])
    log("T6c 5000-digit CL:", r[0], r[3])
    import agentbox.api as A
    log("T6d upload regex with root_path-prefixed scope path matches:", bool(A._UPLOAD_PATH.fullmatch("/prefix/sandboxes/sb_x/files")))
    # 7. Pre-auth JSON amplification within the cap: unauthenticated POST /sandboxes/x/tools/exec
    for size_mib in (1, 2):
        n = (size_mib * 1024 * 1024 - 20) // 3
        payload = b'{"args":{"a":[' + b",".join([b"{}"] * n) + b"]}}"
        gc.collect()
        tracemalloc.start()
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        r = await call("POST", "/sandboxes/sb_x/tools/exec", J + [("content-length", str(len(payload)))], [payload])
        peak = tracemalloc.get_traced_memory()[1] - base
        tracemalloc.stop()
        log("T7 unauth tools/exec JSON %d bytes: status=%s peak_traced=%d bytes ratio=%.1fx detail=%s"
            % (len(payload), r[0], peak, peak / len(payload), r[1][:80]))
        del payload
    # 8. Event-loop stall: an unrelated GET /healthz issued while an unauthenticated 2 MiB JSON body is decoded
    import time
    n = (2 * 1024 * 1024 - 20) // 3
    payload = b'{"args":{"a":[' + b",".join([b"{}"] * n) + b"]}}"
    t0 = time.monotonic()
    r0 = await call("GET", "/healthz", H, [b""])
    base_ms = (time.monotonic() - t0) * 1000

    async def probe():
        await asyncio.sleep(0.01)
        t = time.monotonic()
        rr = await call("GET", "/healthz", H, [b""])
        return rr[0], (time.monotonic() - t) * 1000

    t1 = time.monotonic()
    a, b = await asyncio.gather(call("POST", "/sandboxes/sb_x/tools/exec", J + [("content-length", str(len(payload)))], [payload]), probe())
    log("T8 healthz alone %.1f ms status=%s; healthz during unauth 2 MiB JSON: status=%s %.1f ms; unauth request status=%s total %.1f ms"
        % (base_ms, r0[0], b[0], b[1], a[0], (time.monotonic() - t1) * 1000))
    log("maxrss_kib", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


asyncio.run(main())
Path("/scratch/h.out.txt").write_text("\n".join(out) + "\n")
