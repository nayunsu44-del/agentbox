"""v02 bounded harness (runs only inside sbx: no network, no Docker, uid 65534, scratch-only writes).

Question: do the web UI audit fragment and `agentbox audit` stop showing new audit rows once a sandbox
(or the system) holds more than 5000 rows, and can an agent token alone get there?

What is real:   agentbox.api.build() app, AuditLog, AgentBox/service.py, Policy + default_policy.yaml,
                DesktopControl/ApprovalStore, the web.py routes, cli.cmd_audit, sandbox.diff_manifest/gui_strays.
What is faked:  SandboxManager (needs the Docker daemon) and fastapi.templating (jinja2 is not importable in sbx).
                The template stub records the context web.py passes; the footer text is taken from the real
                _audit.html source line, not retyped.
Usage: python3.13 -I -B v02.py [FLOOD=5000] [OUTFILE]
"""
import contextlib
import io
import json
import os
import re
import shutil
import sys
import time
import types
from argparse import Namespace

sys.path.insert(0, "/target")
with contextlib.suppress(Exception):
    sys.stdout.reconfigure(encoding="utf-8")

FLOOD = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
OUTFILE = sys.argv[2] if len(sys.argv) > 2 else None
LINES = []


def p(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    LINES.append(s)


HOME = "/scratch/v02-home"
shutil.rmtree(HOME, ignore_errors=True)
os.makedirs(HOME)
os.environ["AGENTBOX_HOME"] = HOME
os.environ["AGENTBOX_HUMAN_TOKEN"] = "hum_v02_dummy_token_0000000000"

# ---------------------------------------------------------------- template stub (jinja2 absent in sbx)
TPL_SRC = open("/target/agentbox/templates/_audit.html", encoding="utf-8").read()
FOOT = re.search(r'\{% if total > rows \| length %\}<p class="mut">(.*?)</p>\{% endif %\}', TPL_SRC)
FOOTER_TPL = FOOT.group(1) if FOOT else None


class _Env:
    def __init__(self):
        self.globals, self.filters = {}, {}


class StubTemplates:
    def __init__(self, directory):
        self.env = _Env()

    def TemplateResponse(self, request, name, ctx, headers=None):
        from starlette.responses import JSONResponse
        rows = ctx.get("rows") or []
        total = ctx.get("total")
        rec = {"template": name, "ids": [r["id"] for r in rows], "events": [r["event"] for r in rows], "total": total,
               "payload_text": json.dumps([r["payload"] for r in rows], ensure_ascii=False)}
        if name == "_audit.html" and FOOTER_TPL and total is not None and total > len(rows):
            rec["footer"] = FOOTER_TPL.replace("{{ rows | length }}", str(len(rows))).replace("{{ total }}", str(total))
        return JSONResponse(rec, headers=headers)


_stub = types.ModuleType("fastapi.templating")
_stub.Jinja2Templates = StubTemplates
sys.modules["fastapi.templating"] = _stub

# ---------------------------------------------------------------- fake SandboxManager (no Docker)
from agentbox.sandbox import SandboxError  # noqa: E402  (real)


class _Tpl:
    def __init__(self, desktop):
        self.desktop = desktop


class _Client:
    def close(self):
        pass


class FakeSM:
    def __init__(self, settings, db):
        import sqlite3
        self.settings, self.runtime = settings, "runc"
        self.conn, self.client = sqlite3.connect(":memory:"), _Client()
        self.tokens = {"agt_v02_flood": "sb_v02", "agt_v02_other": "sb_other"}
        self.snaps = {}
        self.ws = {"sb_v02": {"important.txt": (120, "1.0", "1.0"), "notes.md": (50, "1.0", "1.0")}, "sb_other": {}}
        self.extra_procs, self.killed = [], []

    def sandbox_for_token(self, token):
        return self.tokens.get(token)

    def get(self, sid):
        if sid not in self.tokens.values():
            raise SandboxError("no such sandbox")
        return {"id": sid, "status": "running", "template": "desktop", "runtime": "runc"}

    def list(self):
        return [self.get(s) for s in sorted(set(self.tokens.values()))]

    def template_of(self, sid):
        return _Tpl(sid == "sb_v02")

    def snapshot_count(self, sid):
        return len(self.snaps.get(sid, []))

    def snapshot(self, sid, reason="manual"):
        lst = self.snaps.setdefault(sid, [])
        sid_ = f"snap_{len(lst) + 1:04d}"
        rec = {"id": sid_, "sandbox_id": sid, "image": f"agentbox-snap:{sid}-{sid_}", "reason": reason}
        lst.append(rec)
        return rec

    def exec(self, sid, command):
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}

    def list_dir(self, sid, path):
        return {"path": path, "listing": "total 0"}

    def workspace_manifest(self, sid):
        return dict(self.ws[sid]), False

    def desktop_processes(self, sid):
        base = [{"pid": 1, "ppid": 0, "sid": 1, "uid": 0, "args": "/sbin/init"},
                {"pid": 100, "ppid": 1, "sid": 100, "uid": 1001, "args": "Xvfb :0"}]
        return base + list(self.extra_procs), set()

    def kill_processes(self, sid, pids):
        self.killed += list(pids)
        self.extra_procs = [q for q in self.extra_procs if q["pid"] not in pids]

    def click(self, sid, x, y, button="left", double=False):
        return {"clicked": [x, y]}

    def screenshot(self, sid):                      # only reached when an approval card tries to attach a capture
        raise SandboxError("no display in this harness")


import agentbox.api as api  # noqa: E402
import agentbox.cli as cli  # noqa: E402
import agentbox.desktop as D  # noqa: E402
import agentbox.web as web  # noqa: E402
from agentbox.audit import AuditLog  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

api.SandboxManager = FakeSM
app, box, human_token = api.build()
sm = box.sandboxes

cookie, sess = box.desktop.new_session()               # a logged-in browser session (scope '*'), like the UI page
UI = {"Cookie": f"{D.COOKIE}={cookie}"}
AG = {"Authorization": "Bearer agt_v02_flood"}         # agent token of sb_v02 (lowest-trust principal)
AG2 = {"Authorization": "Bearer agt_v02_other"}        # agent token of an unrelated sandbox
HU = {"Authorization": f"Bearer {human_token}"}
db = box.audit.conn


def dbrow(q, *a):
    return db.execute(q, a).fetchall()


def ui(sid="sb_v02"):
    r = c.get("/ui/audit", params={"sandbox_id": sid}, headers=UI)
    return r.status_code, r.json()


R = {"flood_requests": FLOOD}
with TestClient(app) as c:
    # ---- 0. agent token cannot decide approvals, but the refused attempt is itself recorded ----
    t0 = time.time()
    first = c.post("/approvals/apr_probe", json={"decision": "approve"}, headers=AG)
    p("0. agent POST /approvals/apr_probe ->", first.status_code, first.json())
    n0 = dbrow("SELECT COUNT(*) FROM audit")[0][0]
    p("   rows after 1 refused request:", n0, dbrow("SELECT event, actor, sandbox_id FROM audit ORDER BY id DESC LIMIT 1"))
    # rows added per allowed tool call (policy default allow / read-only-exec), for the "3 rows per call" claim
    for tool, args in (("exec", {"command": "ls"}), ("list_dir", {"path": "/workspace"}), ("exec", {"command": "true"})):
        before = dbrow("SELECT COUNT(*) FROM audit")[0][0]
        rr = c.post(f"/sandboxes/sb_v02/tools/{tool}", json={"args": args}, headers=AG)
        after_ = dbrow("SELECT COUNT(*) FROM audit")[0][0]
        evs = [x[0] for x in dbrow("SELECT event FROM audit WHERE id > ? ORDER BY id", before)]
        p(f"   allowed {tool} {args} -> {rr.status_code}; rows added={after_ - before} {evs}")
    n0 = dbrow("SELECT COUNT(*) FROM audit")[0][0]

    # ---- 1. agent-only flood: one cheap refused request per row, no approval, no Docker ----
    bad = 0
    for i in range(FLOOD - n0):
        r = c.post(f"/approvals/apr_{i}", json={"decision": "approve"}, headers=AG)
        if r.status_code != 403:
            bad += 1
    cnt, lo, hi = dbrow("SELECT COUNT(*), MIN(id), MAX(id) FROM audit")[0]
    ev = dbrow("SELECT event, actor, sandbox_id, COUNT(*) FROM audit GROUP BY 1,2,3")
    refused = 1 + (FLOOD - n0)                          # the step-0 probe plus the loop below
    p(f"1. flood: {refused} refused agent POSTs (+{n0 - 1} rows from the 3 step-0 probe tool calls), non-403={bad}, "
      f"{time.time() - t0:.1f}s; rows={cnt} ids {lo}..{hi}; by kind={ev}")
    R["rows_after_flood"], R["flood_non_403"] = cnt, bad

    # ---- 2. boundary control: with exactly 5000 rows the newest row IS shown ----
    st, j = ui()
    p(f"2. UI poll with {cnt} rows: status={st} shown={len(j['ids'])} ids {min(j['ids'])}..{max(j['ids'])} total={j['total']} "
      f"newest_in_db={hi} newest_shown={max(j['ids'])}")
    R["boundary_newest_shown"] = max(j["ids"])

    # ---- 3. what the agent (or an ordinary long session) does next ----
    r_exec = c.post("/sandboxes/sb_v02/tools/exec", json={"args": {"command": "echo AFTER_FLOOD_MARKER"}}, headers=AG)
    p("3a. later allowed exec (policy read-only-exec):", r_exec.status_code, r_exec.json().get("status"))
    r_click = c.post("/sandboxes/sb_v02/tools/click", json={"args": {"x": 10, "y": 10}}, headers=AG)
    p("3b. later GUI click (opens a GUI burst + snapshot):", r_click.status_code, r_click.json().get("status"))
    # the GUI session's effect inside the (fake) container: a file is deleted and a background process is left behind
    sm.ws["sb_v02"].pop("important.txt")
    sm.extra_procs.append({"pid": 200, "ppid": 100, "sid": 200, "uid": 1001, "args": "sh -c 'sleep 600 &'"})
    box._gui_input_at["sb_v02"] -= 61                     # input went idle > gui_snapshot_idle (same lever tests/test_m2 uses)
    r_o = c.post("/sandboxes/sb_other/tools/exec", json={"args": {"command": "echo OTHER_SANDBOX_MARKER"}}, headers=AG2)
    p("3c. unrelated sandbox sb_other later exec:", r_o.status_code, r_o.json().get("status"))

    # ---- 4. the human's live view (what sandbox.html polls every 3 s); it also closes the idle GUI burst ----
    st, j = ui()
    later = dbrow("SELECT id, actor, event, tool, sandbox_id FROM audit WHERE id > 5000 ORDER BY id")
    total_db = dbrow("SELECT COUNT(*), MAX(id) FROM audit")[0]
    p(f"4. DB rows total={total_db[0]} max_id={total_db[1]}; rows with id>5000 ({len(later)}):")
    for row in later:
        p("     ", row)
    p(f"   UI poll: status={st} template={j['template']} shown={len(j['ids'])} ids {min(j['ids'])}..{max(j['ids'])} total={j['total']}")
    p("   UI events shown:", sorted(set(j["events"])))
    p("   footer:", j.get("footer"))
    shown_later = [i for i in j["ids"] if i > 5000]
    p("   ids > 5000 shown in UI:", shown_later, "| gui_changes shown:", "gui_changes" in j["events"],
      "| gui_processes_stopped shown:", "gui_processes_stopped" in j["events"],
      "| AFTER_FLOOD_MARKER shown:", "AFTER_FLOOD_MARKER" in j["payload_text"])
    gc = dbrow("SELECT id, payload FROM audit WHERE event='gui_changes' ORDER BY id DESC LIMIT 1")
    if gc:
        full = box.audit.list(after_id=gc[0][0] - 1, limit=1)[0]
        p(f"   gui_changes row id={gc[0][0]}; what the human would read if it were shown: {web.describe(full)}")
        R["gui_changes_id"] = gc[0][0]
    R.update(ui_shown=len(j["ids"]), ui_min=min(j["ids"]), ui_max=max(j["ids"]), ui_total=j["total"],
             ui_shows_gui_changes="gui_changes" in j["events"], db_total=total_db[0], db_max=total_db[1],
             killed=sm.killed)
    # the UI window is per sandbox: the unrelated sandbox's page is not affected by sb_v02's volume
    st2, j2 = ui("sb_other")
    p(f"   UI poll for unrelated sb_other: status={st2} shown={len(j2['ids'])} ids {j2['ids']} total={j2['total']} "
      f"OTHER_SANDBOX_MARKER shown={'OTHER_SANDBOX_MARKER' in j2['payload_text']}")

    # ---- 5. `agentbox audit` (real cmd_audit) via a shim that injects the human token ----
    class HumanShim:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, **kw):
            kw.setdefault("headers", HU)
            return c.get(url, **kw)

    cli._client = lambda: HumanShim()

    def run_cli(sandbox):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.cmd_audit(Namespace(sandbox=sandbox))
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        ids = [int(ln.split()[0]) for ln in lines]
        return lines, ids

    for label, sbx_arg in (("default (system-wide)", None), ("--sandbox sb_v02", "sb_v02"), ("--sandbox sb_other", "sb_other")):
        lines, ids = run_cli(sbx_arg)
        txt = "\n".join(lines)
        p(f"5. agentbox audit {label}: lines={len(lines)} first_id={ids[0]} last_id={ids[-1]} "
          f"AFTER_FLOOD_MARKER={'AFTER_FLOOD_MARKER' in txt} OTHER_SANDBOX_MARKER={'OTHER_SANDBOX_MARKER' in txt} "
          f"gui_changes={'gui_changes' in txt} gui_processes_stopped={'gui_processes_stopped' in txt}")
        R[f"cli_{sbx_arg}"] = {"lines": len(lines), "last_id": ids[-1]}

    # ---- 6. the data is not lost: /audit paging by after_id returns it, chain verifies ----
    pg = c.get("/audit", params={"after_id": 5000, "limit": 5000}, headers=HU).json()
    vv = c.get("/audit/verify", headers=HU).json()
    p(f"6. GET /audit?after_id=5000 -> ids {[e['id'] for e in pg]} events {[e['event'] for e in pg]}")
    p("   GET /audit/verify ->", vv)
    p("   GET /audit (default limit=500) newest id:", c.get("/audit", headers=HU).json()[-1]["id"])

    # ---- 7. proposed remediation, exercised on the same DB (does not touch target code) ----
    def recent(self, sandbox_id=None, limit=400):
        where, args = (" WHERE sandbox_id = ?", [sandbox_id]) if sandbox_id else ("", [])
        cols = "id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash"
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM audit" + where, args).fetchone()[0]
            rows = self.conn.execute(f"SELECT {cols} FROM audit{where} ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()
        return [{"id": r[0], "event": r[4], "sandbox_id": r[2]} for r in rows], total

    rows7, total7 = recent(box.audit, "sb_v02", 400)
    p(f"7a. newest-N + COUNT(*) fix: shown={len(rows7)} ids {rows7[-1]['id']}..{rows7[0]['id']} total={total7} "
      f"gui_changes shown={'gui_changes' in [r['event'] for r in rows7]}")
    allrows, after = [], 0
    while True:
        page = c.get("/audit", params={"limit": 5000, "after_id": after}, headers=HU).json()
        if not page:
            break
        allrows += page
        after = page[-1]["id"]
    p(f"7b. CLI after_id paging loop: rows={len(allrows)} first={allrows[0]['id']} last={allrows[-1]['id']} "
      f"(db max={total_db[1]})")
    sb_cnt, sb_max = dbrow("SELECT COUNT(*), MAX(id) FROM audit WHERE sandbox_id='sb_v02'")[0]
    R["fix_ok"] = (rows7[0]["id"] == sb_max and total7 == sb_cnt and len(allrows) == total_db[0]
                   and allrows[-1]["id"] == total_db[1])
    p(f"   fix check: sb_v02 newest id in DB={sb_max} count={sb_cnt}; fix_ok={R['fix_ok']}")

p("RESULT", json.dumps(R, sort_keys=True))
shutil.rmtree(HOME, ignore_errors=True)
if OUTFILE:
    with open(OUTFILE, "w", encoding="utf-8") as f:
        f.write("\n".join(LINES) + "\n")
