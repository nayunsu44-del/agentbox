import sys, os, types, ipaddress
sys.path.insert(0, "/target")
print("python", sys.version.split()[0])
from agentbox import cli, sandbox
from agentbox.config import Settings

class FakeClient:
    def __init__(self, runtimes): self._r = runtimes
    def info(self): return {"Runtimes": {r: {} for r in self._r}}

# Runtimes reported by this host's Docker 29.9.1 (architecture.md section 3)
HOST = ["io.containerd.runc.v2", "runc"]

def detect(want, runtimes=HOST):
    m = sandbox.SandboxManager.__new__(sandbox.SandboxManager)
    os.environ["AGENTBOX_RUNTIME"] = want
    m.settings = Settings(); m.client = FakeClient(runtimes)
    try:
        return m._detect_runtime()
    except Exception as e:
        return f"ERROR: {e}"

for want in ["auto", "runc", "runsc", "io.containerd.runc.v2"]:
    rt = detect(want)
    print(f"AGENTBOX_RUNTIME={want!r:26} -> selected={rt!r}")
    if rt.startswith("ERROR"):
        print("    (startup fails before serve checks)"); continue
    exposed_problem = cli.runtime_problem(rt, exposed=True)
    print(f"    runtime_problem(selected, exposed=True) -> {'REFUSE (guard fires)' if exposed_problem else 'None (exposed serve allowed, no --allow-runc needed)'}")
    if not rt.startswith("ERROR"):
        print(f"    healthz dev_only == {rt == 'runc'};  UI runc badge shown == {rt == 'runc'}")

# cmd_serve 'exposed' gate inputs for the compose deployment
for host, tls, behind in [("0.0.0.0", False, True), ("127.0.0.1", False, False), ("0.0.0.0", False, False)]:
    print("bind_problem", host, tls, behind, "->", "refuse" if cli.bind_problem(host, tls, behind) else "ok",
          "| exposed =", tls or behind or not cli.is_loopback(host))
