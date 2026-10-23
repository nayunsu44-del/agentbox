"""parent-live (run-5, h-bodylimit candidate): peak RSS of a real uvicorn agentbox server for unauthenticated
8 MiB JSON bodies (no Authorization header), single and concurrent, plus human /healthz latency meanwhile.

Runs inside a disposable container (network none, loopback only, --memory 1g) with the audited source at /target;
the server uses a dummy human token and a stub Docker client (no sandbox is created, Docker is never reached).

usage (inside the container): python3 parent_live_preauth_json.py /out/preauth.json
"""
import http.client
import json
import os
import subprocess
import sys
import threading
import time

OUT = sys.argv[1]
env = dict(os.environ, AGENTBOX_HOME="/scratch/abx", AGENTBOX_HUMAN_TOKEN="hum_" + "p" * 40)
# The container has no Docker socket; the unauthenticated requests never reach Docker, so the server gets a stub
# client that only answers SandboxManager's runtime probe.
SERVER = ("import docker, types, uvicorn\n"
          "docker.from_env = lambda: types.SimpleNamespace(info=lambda: {'Runtimes': {'runc': {}}})\n"
          "from agentbox.api import create_app\n"
          "uvicorn.run(create_app(), host='127.0.0.1', port=8765, log_level='warning')\n")
srv = subprocess.Popen([sys.executable, "-c", SERVER], env=env)


def rss(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) // 1024
    return -1


def hwm(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) // 1024
    return -1


for _ in range(100):
    try:
        c = http.client.HTTPConnection("127.0.0.1", 8765, timeout=5)
        c.request("GET", "/healthz")
        if c.getresponse().status:
            break
    except OSError:
        time.sleep(0.2)
CAP = 8 * 1024 * 1024
body = b'{"args":{"a":[' + b",".join([b"{}"] * ((CAP - 40) // 3)) + b"]}}"
body = body[: CAP - 3].rsplit(b",", 1)[0] + b"]}}"
res = {"body_bytes": len(body), "rss_idle_mb": rss(srv.pid)}


def post(results, i):
    t = time.monotonic()
    try:
        c = http.client.HTTPConnection("127.0.0.1", 8765, timeout=120)
        c.request("POST", "/sandboxes/sb_x/tools/exec", body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        r.read()
        results[i] = {"status": r.status, "s": round(time.monotonic() - t, 2)}
    except Exception as e:  # noqa: BLE001
        results[i] = {"error": repr(e), "s": round(time.monotonic() - t, 2)}


def health():
    t = time.monotonic()
    try:
        c = http.client.HTTPConnection("127.0.0.1", 8765, timeout=60)
        c.request("GET", "/healthz")
        c.getresponse().read()
        return round(time.monotonic() - t, 3)
    except Exception as e:  # noqa: BLE001
        return repr(e)


res["healthz_idle_s"] = health()
one = [None]
post(one, 0)
res["single"] = {"result": one[0], "rss_after_mb": rss(srv.pid), "hwm_mb": hwm(srv.pid)}
for n in (4, 8):
    out = [None] * n
    ths = [threading.Thread(target=post, args=(out, i)) for i in range(n)]
    for t in ths:
        t.start()
    time.sleep(0.5)
    hz = health()
    for t in ths:
        t.join()
    alive = srv.poll() is None
    res[f"concurrent_{n}"] = {"results": out, "healthz_during_s": hz, "server_alive": alive,
                              "hwm_mb": hwm(srv.pid) if alive else None, "exit": srv.poll()}
    if not alive:
        break
srv.terminate()
open(OUT, "w").write(json.dumps(res, indent=1) + "\n")
print(json.dumps(res, indent=1))
