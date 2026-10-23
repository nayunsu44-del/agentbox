"""v04 independent harness: exposed-serve runc guard vs the Docker runtime alias io.containerd.runc.v2.

Runs only inside the sbx sandbox (no network, no Docker socket, read-only target at /target, scratch at /scratch).
Uses the REAL agentbox.cli.runtime_problem / cmd_serve, the REAL SandboxManager._detect_runtime and the REAL
agentbox.desktop.page. Only the Docker client (fake info()) and uvicorn.run / agentbox.api.build are stubbed.
"""
import ast
import contextlib
import io
import os
import sys
import textwrap
import types

sys.path.insert(0, "/target")
LINES = []


def say(*a):
    s = " ".join(str(x) for x in a)
    LINES.append(s)
    print(s)


say("python", sys.version.split()[0], "euid", os.geteuid())
from agentbox import cli, desktop, sandbox  # noqa: E402
from agentbox.config import Settings  # noqa: E402


class FakeClient:
    """Stands in for docker.from_env(); only info() is used by _detect_runtime."""

    def __init__(self, runtimes):
        self._r = runtimes

    def info(self):
        return {"Runtimes": {r: {"path": "x"} for r in self._r}}


# Runtimes of the audit host per architecture.md section 3 (parent live check): Docker 29.9.1, no gVisor/Kata.
HOST = ["io.containerd.runc.v2", "runc"]


def detect(want, runtimes):
    if want is None:
        os.environ.pop("AGENTBOX_RUNTIME", None)
    else:
        os.environ["AGENTBOX_RUNTIME"] = want
    m = sandbox.SandboxManager.__new__(sandbox.SandboxManager)
    m.settings = Settings()
    m.client = FakeClient(runtimes)
    try:
        return m._detect_runtime(), None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


# ---- A. runtime selection and guard matrix ---------------------------------------------------------------
say("\n== A. _detect_runtime + cli.runtime_problem ==")
for label, rts in [("this host (arch.md s3)", HOST), ("hypothetical host +runsc", HOST + ["runsc"]),
                   ("hypothetical host +crun,+nvidia", HOST + ["crun", "nvidia"])]:
    say(f"-- Docker Runtimes = {sorted(rts)}  [{label}]")
    for want in [None, "auto", "runc", "io.containerd.runc.v2", "crun", "nvidia", "runsc"]:
        sel, err = detect(want, rts)
        tag = "unset" if want is None else repr(want)
        if err:
            say(f"   AGENTBOX_RUNTIME={tag:26} -> startup error: {err}")
            continue
        exposed_problem = cli.runtime_problem(sel, True)
        local_problem = cli.runtime_problem(sel, False)
        say(f"   AGENTBOX_RUNTIME={tag:26} -> selected={sel!r:26} guard_fires(exposed)={exposed_problem is not None!s:5}"
            f" guard_fires(local)={local_problem is not None}")

# ---- B. other sinks that compare against the literal -----------------------------------------------------
say("\n== B. dev-only indicators (real desktop.page, real healthz body, base.html condition) ==")
for rt in ["runc", "io.containerd.runc.v2"]:
    html = desktop.page("sb_test", rt)
    say(f"   desktop.page(runtime={rt!r}): red 'runc: dev only' badge={'개발 전용' in html}  "
        f"runtime name still printed ('격리: {rt}')={('격리: ' + rt) in html}")

api_src = open("/target/agentbox/api.py", encoding="utf-8").read()
node = next(n for n in ast.walk(ast.parse(api_src)) if isinstance(n, ast.FunctionDef) and n.name == "health")
fn_src = textwrap.dedent(ast.get_source_segment(api_src, node))
say(f"   api.py healthz source (lines {node.lineno}-{node.end_lineno}): "
    f"{' '.join(fn_src.split())[:200]}")
for rt in ["runc", "io.containerd.runc.v2"]:
    ns = {"box": types.SimpleNamespace(sandboxes=types.SimpleNamespace(runtime=rt)),
          "settings": types.SimpleNamespace(image="img", templates=lambda: {"cli": 1, "desktop": 2})}
    exec(compile(fn_src, "healthz", "exec"), ns)
    say(f"   healthz() with runtime={rt!r}: {ns['health']()}")

base = open("/target/agentbox/templates/base.html", encoding="utf-8").read().splitlines()
for i in (42, 43):
    say(f"   base.html:{i + 1}: {base[i].strip()}")

# ---- C. end-to-end cmd_serve with only uvicorn.run and api.build stubbed ---------------------------------
say("\n== C. real cli.main(['serve', ...]) end to end ==")
import uvicorn  # noqa: E402

calls = []
uvicorn.run = lambda app, **kw: calls.append(kw)
fake_api = types.ModuleType("agentbox.api")


def fake_build(s):
    m = sandbox.SandboxManager.__new__(sandbox.SandboxManager)
    m.settings, m.client = s, FakeClient(HOST)
    m.runtime = m._detect_runtime()  # REAL runtime selection under the env set by the scenario
    return object(), types.SimpleNamespace(sandboxes=m, close=lambda: None), "hum_dummy"


fake_api.build = fake_build
sys.modules["agentbox.api"] = fake_api


def serve(args, env):
    for k in ("AGENTBOX_RUNTIME", "AGENTBOX_ALLOW_RUNC", "AGENTBOX_BEHIND_TLS_PROXY"):
        os.environ.pop(k, None)
    os.environ.update(env)
    calls.clear()
    out, err, code = io.StringIO(), io.StringIO(), None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main(["serve", *args])
        except SystemExit as e:
            code = e.code
    return bool(calls), code, out.getvalue(), err.getvalue()


EXPOSED = ["--host", "0.0.0.0", "--behind-tls-proxy"]
scen = [
    ("exposed, AGENTBOX_RUNTIME unset(auto)           ", EXPOSED, {}),
    ("exposed, AGENTBOX_RUNTIME=runc                  ", EXPOSED, {"AGENTBOX_RUNTIME": "runc"}),
    ("exposed, AGENTBOX_RUNTIME=io.containerd.runc.v2 ", EXPOSED, {"AGENTBOX_RUNTIME": "io.containerd.runc.v2"}),
    ("exposed, runc + --allow-runc (explicit consent) ", EXPOSED + ["--allow-runc"], {"AGENTBOX_RUNTIME": "runc"}),
    ("exposed, alias + --allow-runc                   ", EXPOSED + ["--allow-runc"],
     {"AGENTBOX_RUNTIME": "io.containerd.runc.v2"}),
    ("loopback, runc                                  ", ["--host", "127.0.0.1"], {"AGENTBOX_RUNTIME": "runc"}),
    ("loopback, alias                                 ", ["--host", "127.0.0.1"],
     {"AGENTBOX_RUNTIME": "io.containerd.runc.v2"}),
]
for name, args, env in scen:
    started, code, out, err = serve(args, env)
    first_err = err.strip().splitlines()[0][:70] if err.strip() else "(no stderr warning)"
    banner = next((ln.strip() for ln in out.splitlines() if "격리 런타임" in ln), "")
    say(f"   {name} started={started!s:5} exit={'refused:' + code[:30] + '...' if isinstance(code, str) else code}")
    say(f"        stderr: {first_err}")
    if banner:
        say(f"        stdout banner: {banner}")

# ---- D. who can set AGENTBOX_RUNTIME? (static scan of the whole agentbox package + compose file) ----------
say("\n== D. static scan: writers of Settings.runtime / os.environ, compose pass-through ==")
pkg = "/target/agentbox"
for fn in sorted(os.listdir(pkg)):
    if not fn.endswith(".py"):
        continue
    tree = ast.parse(open(os.path.join(pkg, fn), encoding="utf-8").read())
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr == "runtime" and isinstance(n.ctx, ast.Store):
            say(f"   {fn}:{n.lineno}: assignment to .runtime")
        if isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store) and "environ" in ast.dump(n.value):
            say(f"   {fn}:{n.lineno}: write to os.environ[...]")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("putenv", "setdefault", "update") \
                and "environ" in ast.dump(n.func.value):
            say(f"   {fn}:{n.lineno}: os.environ.{n.func.attr}(...)")
    if fn == "config.py":
        for n in ast.walk(tree):
            if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "runtime":
                say(f"   config.py:{n.lineno}: Settings.runtime field default = env AGENTBOX_RUNTIME")
import yaml  # noqa: E402

comp = yaml.safe_load(open("/target/deploy/docker-compose.yml", encoding="utf-8"))
env = comp["services"]["agentbox"]["environment"]
say(f"   compose agentbox.environment keys = {sorted(env)}  (AGENTBOX_RUNTIME forwarded: {'AGENTBOX_RUNTIME' in env})")

with open("/scratch/v04_runtime_alias.out", "w", encoding="utf-8") as f:
    f.write("\n".join(LINES) + "\n")
