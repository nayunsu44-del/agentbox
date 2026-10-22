You are Phase 5 final-record verifier `p5-v02` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.
- A fix for this record was committed after Phase 3 as `3587c9c` (`git -C /home/user/agentbox show 3587c9c`). Use it only to judge check 6 (does the proposed remediation enforce the invariant). It is never evidence that the record is wrong for the audited source.

# Execution boundary (verbatim from the skill)

```text
You did not write this candidate. Try to refute it from repository source and bounded
local evidence. Do not contact deployed endpoints or external/shared services. Run
target-controlled code only inside the approved OS-enforced sandbox: no external
network, empty allowlisted environment, read-only target and tools, scratch-only
writes, and explicit low resource and wall-clock limits. If any control is unavailable,
do not execute; retain the exact missing capability as a needs_validation blocker.
Treat every scratch entry as target-controlled after execution. After the sandbox and
all its processes terminate, only trusted parent-side code may promote a predeclared
scratch-relative file, following the promotion procedure block included verbatim in
this prompt. You and target code never write retained artifacts. If promotion is
unavailable or fails, do not use that file as evidence.
```

# Phase 5 checks for a `confirmed` record (verbatim from the skill)

```text
1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.
```

A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# Final record (from findings.json)

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines",
 "title": "The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view",
 "description": "The sandbox page's audit fragment (GET /ui/audit, re-polled every 3 s) and `agentbox audit` both fetch rows with AuditLog.list(limit=5000) and no after_id. AuditLog.list is `WHERE id > ? [AND sandbox_id = ?] ORDER BY id LIMIT ?`, so it returns the OLDEST 5000 matching rows, and nothing is ever pruned. Once a sandbox (sandbox page, `agentbox audit --sandbox`) or the whole system (default `agentbox audit`) holds more than 5000 rows, the UI shows the last 400 of the oldest window (ids 4601-5000, total capped at 5000) and the CLI prints rows 1-5000. Every later row (tool_request/tool_result, snapshot, human_takeover/handback, gui_processes_stopped, gui_changes) is never shown, while the UI footer keeps saying it shows the most recent 400 of 5000. The UI window is per sandbox; the default CLI view is system-wide, so one sandbox's volume also hides other sandboxes' later events from it. A prompt-injected agent that holds only its own sandbox's agent token can reach the threshold without any approval: one approval_forbidden row per refused POST /approvals/{any id} (no Docker, no rate limit; needs raw API access with the token), or three rows per allowed tool call such as list_dir or exec of an allowlisted read-only command (about 1,670 calls through the ordinary MCP tools). Correction to the hunter's example: `exec true` is not an approval-free path, because default_policy.yaml lists true/false unquoted (line 27) and PyYAML parses them as booleans, so that call returns 202 and needs approval; `exec ls`, `exec echo` and list_dir are allowed. Long-lived ordinary sandboxes reach the same threshold without any attacker. The rows stay in the database, GET /audit?after_id=... returns them, verify passes and the approval queue is unaffected; only the two views humans actually use stop updating.",
 "root_cause": "AuditLog.list (audit.py:190-197) can only return the oldest `limit` rows after `after_id` (ORDER BY id ascending). Both human-facing consumers call it with limit=5000 and no after_id and then treat the result as the newest window: web.py audit_frag takes rows[-400:] and total=len(rows), and cli.py cmd_audit prints the whole list. Beyond 5000 rows the 'tail' is the tail of the oldest 5000, never the newest rows, and total is capped at 5000. Neither the UI nor the CLI has a paging control and the audit table is never pruned, so the freeze is permanent for that sandbox or system.",
 "intended_behavior": "The sandbox page timeline (footer: only the most recent N shown, total M) and `agentbox audit` show the newest audit events with the real total, or page through all rows. The volume of rows an agent can create must not hide its later events from the human's oversight views, in particular the gui_changes and gui_processes_stopped records that the README (line 198) names as the way the human sees changes made through the ungated GUI path.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 241,
   "scope": "decide (POST /approvals/{aid})",
   "description": "An agent token (lowest-trust principal) calling POST /approvals/{any id} with a valid {\"decision\": ...} body is authenticated by principal() and refused with 403, but the refusal path records an audit row first. Ordinary allowed tool calls (POST /sandboxes/{sid}/tools/{tool}: list_dir, read_file, exec of an allowlisted command, GUI tools) also add rows, three each via service.py:297, 305 and 359."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 245,
   "scope": "decide",
   "description": "audit.append(actor='agent', event='approval_forbidden', sandbox_id=p.sandbox_id): one row per request, tagged with the agent's own sandbox id. No request-rate limit (none in the app or in deploy/), no tool_pool slot, no Docker call and no row cap; tool_concurrency only bounds simultaneous tool calls."
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 196,
   "scope": "AuditLog.list",
   "description": "'WHERE id > ? [AND sandbox_id = ?] ORDER BY id LIMIT ?' returns the oldest rows first. Rows are never deleted (UPDATE/DELETE triggers), so once the limit is exceeded newer rows are only reachable by paging with after_id."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 262,
   "scope": "audit_frag (GET /ui/audit)",
   "description": "rows = box.audit.list(sandbox_id=sandbox_id, limit=5000): the oldest 5000 rows of that sandbox, no after_id. This is the fragment sandbox.html:19 re-requests every 3 s."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 263,
   "scope": "audit_frag (GET /ui/audit)",
   "description": "render(_audit.html, rows=rows[-400:][::-1], total=len(rows)) passes ids 4601-5000 and total 5000 (reproduced); newer rows, including gui_processes_stopped and gui_changes, are never rendered, and _audit.html:10 then prints the footer '최근 400개만 표시 (전체 5000개)'."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 196,
   "description": "' ORDER BY id LIMIT ?' is ascending, so any limit keeps the oldest rows; the same query serves the unpaged UI/CLI callers and the after_id paging API."
  },
  {
   "file": "agentbox/web.py",
   "line": 263,
   "description": "The UI takes the tail of the oldest-5000 window and reports total as len(rows), which cannot exceed 5000."
  },
  {
   "file": "agentbox/templates/_audit.html",
   "line": 10,
   "description": "Footer '최근 {{ rows|length }}개만 표시 (전체 {{ total }}개)' (most recent N shown, total M) is false beyond 5000 rows; the harness printed '최근 400개만 표시 (전체 5000개)' with 5012 rows in the database."
  },
  {
   "file": "agentbox/cli.py",
   "line": 258,
   "description": "cmd_audit requests /audit with limit=5000 and no after_id and prints everything it gets; there is no paging flag, and without --sandbox the query is system-wide. Real cmd_audit printed ids 1..5000 only."
  },
  {
   "file": "agentbox/api.py",
   "line": 259,
   "description": "GET /audit returns list(..., after_id=after_id, limit=min(limit, 5000)) with a default limit of 500: an unpaged call returns the oldest 500 rows (measured: newest id 500 of 5012); only after_id paging reaches newer rows, and neither the UI nor the CLI pages."
  },
  {
   "file": "agentbox/templates/sandbox.html",
   "line": 19,
   "description": "The sandbox page polls /ui/audit?sandbox_id=... on load, every 3 s and on audit-changed: this is the live oversight view, and its only other audit-related control is the verify button."
  },
  {
   "file": "agentbox/service.py",
   "line": 297,
   "description": "Every tool call appends tool_request here, policy_decision at line 305 and (when allowed and executed) tool_result at line 359: measured exactly 3 rows each for exec ls and list_dir."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 10,
   "description": "default: allow, so list_dir, read_file, write_file and the GUI tools have no rule and need no approval; the read-only-exec allowlist (lines 25-27) allows ls, echo, cat and similar."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 27,
   "description": "true and false are unquoted, so yaml.safe_load yields booleans and the allowlist holds 'True'/'False', not 'true'/'false'; measured: exec true returns 202 (approval requested), so the hunter's `exec true` example is wrong (the root cause is unaffected)."
  },
  {
   "file": "agentbox/service.py",
   "line": 243,
   "description": "gui_changes (and gui_processes_stopped at line 225) are written only to the audit log and rendered only by web.py describe (line 62) and cli.py (line 280), so the two timelines are the only human-facing surface for them."
  },
  {
   "file": "README.md",
   "line": 198,
   "description": "Documents the timeline as where the human sees the 'deleted: ...' list and the snapshot id for GUI-path changes; the README's known limitations do not mention a 5000-row cap."
  },
  {
   "file": "tests/test_m2_acceptance.py",
   "line": 242,
   "description": "The suite asserts that the /ui/audit page shows '삭제됨: old-report.md', confirming the timeline is the designed surface for gui_changes; no test brings a sandbox anywhere near the 5000-row limit."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Holder of the victim sandbox's agent token (prompt-injected agent). Rows can be created through the ordinary tool endpoints and MCP tools (list_dir, read_file, exec of an allowlisted command: 3 rows per call) or, with raw API access, by refused POST /approvals/{id} (1 row per call)."
  },
  {
   "kind": "data_state",
   "description": "More than 5000 audit rows for the sandbox (sandbox page, `agentbox audit --sandbox`) or for the whole system (default `agentbox audit`). Agent-causable within minutes; long-lived ordinary sandboxes reach it too."
  },
  {
   "kind": "user_interaction",
   "description": "The human relies on the sandbox page timeline or `agentbox audit` output rather than paging GET /audit with after_id; the UI and CLI have no paging control."
  },
  {
   "kind": "system_configuration",
   "description": "Default policy (default: allow plus the read-only-exec allowlist) so list_dir, read_file, ls and echo need no approval. The refused-POST path does not depend on the policy."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding its sandbox's agent token wants its later exec and GUI activity, and the gui_processes_stopped and gui_changes records the system writes about it, to stay out of the human's timeline; it first pads the audit table with cheap approval-free rows until the oldest-first window is full.",
  "payloads": [
   "POST /approvals/apr_<n>  Authorization: Bearer <agent token of sb_v02>  body {\"decision\":\"approve\"}, repeated 4,991 times: each returns 403 and appends one approval_forbidden row tagged sb_v02; together with 9 rows from three probe tool calls the table holds exactly 5000 rows (ids 1..5000)",
   "POST /sandboxes/sb_v02/tools/exec {\"args\":{\"command\":\"echo AFTER_FLOOD_MARKER\"}}; POST /sandboxes/sb_v02/tools/click {\"args\":{\"x\":10,\"y\":10}} (opens a GUI burst; the fake container then deletes /workspace/important.txt and leaves a background process, and the burst is aged 61 s); POST /sandboxes/sb_other/tools/exec {\"args\":{\"command\":\"echo OTHER_SANDBOX_MARKER\"}}: ids 5001-5012, including gui_processes_stopped 5008 and gui_changes 5009",
   "Human side: GET /ui/audit?sandbox_id=sb_v02 with a browser-session cookie; the real cli.cmd_audit with sandbox=None, 'sb_v02' and 'sb_other'; GET /audit?after_id=5000&limit=5000 and GET /audit/verify with the human token"
  ],
  "instructions": [
   "In sbx (no network, no Docker) run: sbx v02 /usr/bin/python3.13 -I -B /scratch/v02.py 5000 /scratch/v02.out (artifacts agents/v02/artifacts/v02.py and agents/v02/artifacts/v02.out; 512 MiB, 1 CPU, 64 pids, 120 s, uid 65534; about 17 s). It builds the real agentbox.api.build() app under a scratch AGENTBOX_HOME and replaces only SandboxManager (needs Docker) and fastapi.templating (jinja2 is not importable in sbx); the template stub records the context web.py passes and takes the footer text from the real _audit.html source line.",
   "Step 0-1: with the sandbox's agent token send POST /approvals/apr_probe (403) and three probe tool calls (exec ls and list_dir are allowed and add 3 rows each; exec true returns 202 and needs approval), then 4,990 more refused POST /approvals/apr_N so the table holds exactly 5000 rows for sb_v02. Step 2: GET /ui/audit?sandbox_id=sb_v02 with a session cookie from box.desktop.new_session(): boundary control, the newest row (5000) is shown.",
   "Step 3-4: as the agent run exec echo AFTER_FLOOD_MARKER and a GUI click (opens a GUI burst), alter the fake container (delete important.txt, leave a stray uid-1001 process), age the burst by 61 s, run an exec in an unrelated sandbox; poll /ui/audit again, which closes the burst so the real service code appends gui_processes_stopped and gui_changes. Inspect the template context and the unrelated sandbox's page.",
   "Step 5-7: call the real cli.cmd_audit (default, --sandbox sb_v02, --sandbox sb_other) through a shim that injects the human token; GET /audit (default and after_id=5000) and /audit/verify; exercise the proposed remediation (newest-N plus COUNT(*) query, CLI after_id paging loop) on the same database."
  ],
  "observed_result": "With exactly 5000 rows the sandbox page showed ids 4601..5000 and the newest shown id equalled the newest in the database (boundary control). After 12 more rows (ids 5001-5012: exec and click tool_request/policy_decision/tool_result, snapshot 5006, gui_processes_stopped 5008, gui_changes 5009 for sb_v02; 5010-5012 for sb_other) the poll for sb_v02 returned status 200, template _audit.html, 400 rows, ids 4601..5000 (all approval_forbidden), total 5000, footer '최근 400개만 표시 (전체 5000개)', with no id above 5000, no gui_changes, no gui_processes_stopped and no AFTER_FLOOD_MARKER; the unrelated sb_other page still showed its own rows 5010-5012. Real cmd_audit printed 5000 lines, ids 1..5000, and none of the markers for both the default and --sandbox sb_v02; --sandbox sb_other printed ids 5010-5012. An unpaged GET /audit returned the oldest 500 rows (newest id 500). GET /audit?after_id=5000 returned ids 5001-5012 and /audit/verify returned ok=True over 5012 rows, so nothing is lost, only not shown. Proposed fix on the same database: the newest-400 plus COUNT(*) query returned ids 4610..5009 with total 5009 including gui_changes, and the CLI paging loop returned all 5012 rows. A second run gave identical numbers. Not executed: real Jinja2 rendering (unavailable in sbx), Docker-backed SandboxManager."
 },
 "remediation": {
  "strategy": "Make the human views read the newest rows and report the real total. Add AuditLog.recent(sandbox_id, limit) = SELECT COUNT(*) plus 'ORDER BY id DESC LIMIT ?' under the same lock, use it in web.audit_frag (newest first, matching the existing template), and make `agentbox audit` page /audit with after_id until an empty page (optionally add a --tail N flag or a newest-first /audit option so large logs are not transferred in full). Replace the same oldest-first pattern in web.verify_frag (web.py:270, limit=100000) with a point lookup of the broken id. Optionally add an index on audit(sandbox_id, id) for the filtered COUNT and reverse scans (CREATE INDEX does not conflict with the append-only triggers). Regression tests: append 5100 rows for one sandbox, assert GET /ui/audit renders id 5100 with total 5100 and that cmd_audit's fetch includes id 5100; assert the same for a sandbox filter when another sandbox holds most of the rows.",
  "code_changes": [
   {
    "file_name": "agentbox/audit.py",
    "fixed_code": "    def recent(self, sandbox_id: str | None = None, limit: int = 400) -> tuple[list[dict[str, Any]], int]:\n        \"\"\"Newest `limit` rows (newest first) and the real row count for the same filter.\"\"\"\n        where, args = (\" WHERE sandbox_id = ?\", [sandbox_id]) if sandbox_id else (\"\", [])\n        with self._lock:\n            total = self.conn.execute(\"SELECT COUNT(*) FROM audit\" + where, args).fetchone()[0]\n            rows = self.conn.execute(\n                \"SELECT id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash FROM audit\" + where\n                + \" ORDER BY id DESC LIMIT ?\", args + [limit]).fetchall()\n        return [\n            {\"id\": r[0], \"ts\": r[1], \"sandbox_id\": r[2], \"actor\": r[3], \"event\": r[4], \"tool\": r[5],\n             \"payload\": json.loads(r[6]), \"prev_hash\": r[7], \"hash\": r[8]}\n            for r in rows\n        ], total"
   },
   {
    "file_name": "agentbox/web.py",
    "fixed_code": "    @app.get(\"/ui/audit\", include_in_schema=False)\n    def audit_frag(request: Request, sandbox_id: str | None = None, p=Depends(browser_human)):\n        box.close_idle_gui_bursts()\n        rows, total = box.audit.recent(sandbox_id=sandbox_id, limit=400)   # newest first, real total\n        return render(request, \"_audit.html\", rows=rows, total=total, broken=None)"
   },
   {
    "file_name": "agentbox/cli.py",
    "fixed_code": "def cmd_audit(a: argparse.Namespace) -> None:\n    with _client() as c:\n        params = {\"sandbox_id\": a.sandbox} if a.sandbox else {}\n        rows, after = [], 0\n        while True:   # /audit is oldest-first: page with after_id so the newest rows are included\n            page = _check(c.get(\"/audit\", params=params | {\"limit\": 5000, \"after_id\": after}))\n            if not page:\n                break\n            rows += page\n            after = page[-1][\"id\"]"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "No approval and no Docker work are needed: the rows come from the agent's own requests. In the harness 4,991 refused POST /approvals/{id} calls (one row each; needs raw API access with the agent token) took about 15 s in-process, and each allowed list_dir/read_file/exec of an allowlisted command adds exactly 3 rows (about 1,670 calls through the ordinary MCP tools, no raw API access needed). tool_concurrency (4 simultaneous) only slows this; there is no request-rate limit or row cap. Long-lived ordinary sandboxes cross 5000 rows without any attacker. It needs a human who relies on the timeline rather than paging /audit, and the frozen window stays visible (400 rows, constant total), so an attentive operator could notice that it stopped advancing."
  },
  "impact": {
   "score": "medium",
   "reason": "Both human timelines (the sandbox page polled every 3 s, and `agentbox audit`) stop advancing while the UI footer claims to show the most recent rows, so later tool_request/tool_result, snapshot, takeover/handback, gui_processes_stopped and gui_changes rows are not shown. The README names the timeline as the way the human sees gui_changes, the compensating control for the ungated GUI path, so the lowest-trust principal can silence that control for itself at will. The default CLI is system-wide, so one sandbox's volume also hides other sandboxes' later events from `agentbox audit` without --sandbox; the per-sandbox UI window of an unrelated sandbox was not affected (checked). Bounded: no row is lost or altered (GET /audit?after_id= returns them, verify passes), the approval queue, snapshots, stray-process kill and tool gating are unaffected, and there is no disclosure or privilege gain."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Reproduced twice with identical numbers through the real api.build() app: agent-token HTTP requests created the rows, the real service.py code wrote gui_processes_stopped and gui_changes, and the real web.py audit_frag route and real cli.cmd_audit ran. Only Docker (SandboxManager) and Jinja2 rendering were stubbed, and the footer text came from the real _audit.html line. The boundary control (exactly 5000 rows shows the newest row), the unrelated-sandbox control and the paging/verify checks support the causal reading, and the ordering, the limit, the missing paging and the absence of any documented cap are direct from source. The hunters' artifacts (h-audit, h-wild) agree."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Architecture facts

# agentbox architecture summary (run-3)

Source ref: `0e4b958` on `ccr-e10bee8e-6wt669` (PR #5 head; `agentbox/` identical after merge to `main`). Profile `standard`, whole repo.

## 1. Product, principals, protected resources

agentbox is a self-hosted control plane (FastAPI + SQLite) that gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. A desktop mode adds Xvfb/Xfce/noVNC so a human can watch or take over the screen.

- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full API.
- **Web UI cookie session**, scope `*` (token login form or one-time `*` ticket): full UI (`web.py:208-242`, `desktop.py`).
- **Desktop-link session**, scope = one sandbox id (redeemed per-sandbox ticket): only that sandbox's desktop page/state/takeover/handback/WS (`api.py:134-140,298-336`, `desktop.py:147-152`).
- **Agent token** `agt_…` per sandbox (hash stored): tool calls on its own sandbox, read own sandbox/approval/desktop state (`api.py:160-230,315`). Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (tool execs), uid 1001 `desktop` (X session, GUI tools, x11vnc; member of the agent group, `/workspace` group-writable). Container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listings, file names) is attacker-controlled input to the control plane.
- **MCP stdio server / agent.py LLM loop**: hold an agent token; inherit trust from the local launcher.

Protected resources: the human token and approval authority; host filesystem and Docker daemon (control plane holds `docker.sock` = host root); other sandboxes; integrity of `/workspace` restore points (AP-2 snapshots before destructive actions); audit-log integrity and secret masking; control-plane availability (shared thread pool, memory, host disk via `docker commit`).

## 2. Comparable baseline

No source-grounded comparable product. Components: MCP (FastMCP stdio), VNC/RFB via x11vnc+noVNC, gVisor/Kata runtimes. A runc sandbox shares the host kernel; the code refuses runc only when the control plane is exposed (`cli.py:79-115`).

## 3. Stack, deployment, offline limits

Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: local `agentbox serve` (127.0.0.1), direct TLS, `--behind-tls-proxy` (compose + Caddy, `forwarded_allow_ips="*"` by default), `--insecure`, and the bare `uvicorn agentbox.api:create_app --factory` path that skips serve-time checks. Container flags: `network_mode=none`, `/source` read-only bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits; no userns, default seccomp (`sandbox.py:367-388`). Host: Docker 29.9.1, runtimes `runc` and `io.containerd.runc.v2` only (no gVisor/Kata), cgroup v1, images `agentbox-desktop:0.1`, `buildpack-deps:noble-curl`. Pure-function harnesses and the three unit test modules fit the parent's `sbx` sandbox; anything that builds the app needs the Docker daemon (parent-live checks).

## 4. Entry surfaces and important paths

- JSON API `POST /sandboxes/{sid}/tools/{tool}` → `service.call_tool` (per-sandbox concurrency 4, 429) → audit → `policy.decide` → allow / approval queue → `sandbox.exec|read_file|write_file|delete_file|list_dir|gui_*` (`docker exec` as uid 1000/1001), dedicated 32-thread `tool_pool` (`api.py:81`). Exec output streamed and capped (`_Head`, 64 KB).
- Approvals `POST /approvals/{aid}` (human only) → atomic claim → pre-snapshot → run with the agent's original args; terminal approver `cli.py` renders args through `_safe()`.
- Snapshots: `docker commit` before write/delete overwrite and per GUI burst; quota 50 → approval (`service.py:199-204`); per-sandbox `_snap_locks`.
- GUI bursts (`service.py:186-260`): snapshot + manifest + baseline pids at burst start; at close, kill new uid-1001 processes classified by `gui_strays` from root `ps` output and `xdotool` window pids (`sandbox.py:174-225,686-697`), diff `find -printf` manifest (8 MB cap) and log `gui_changes`. Closed on idle from `expire_stale`, `call_tool`, `GET /audit`, UI audit fragment, takeover, end_desktop.
- Files: `read_file` (`timeout` + `[ -f ]` FIFO guard), `outbox_list/read`, `POST /sandboxes/{sid}/files` upload, `source_dir` copy at create (refuses overlap with `settings.home`/DB dir).
- Desktop: tickets (60 s, one-time, hashed), sessions (12 h, hashed, `scope`), leases keyed by public session id `hs_`+32 bits, WS `/desktop/ws` (cookie + same_origin; control needs lease; re-check every 30 s, `session_ended` handback), logout `end_ui_session`.
- Audit: hash chain with append-only triggers, `mask_text` regex set (`audit.py`), UI/CLI timelines render container-controlled strings (`web.py describe`, Jinja autoescape; `cli._safe`).
- Serve: `bind_problem`, `runtime_problem` (literal `"runc"` only), `--allow-runc`/`AGENTBOX_ALLOW_RUNC`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc here) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot, `gui_changes`, stray kill (partial, N-1) |
| Agent → human authority | token kinds, `human_only`, scope checks, source_dir overlap check |
| Agent → control-plane availability | tool_pool, tool_concurrency, `_Head`, snapshot quota, read timeouts |
| Container output → control plane | parsers `_parse_ps`, `_parse_manifest`, `_parse_outbox`; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin` (missing Origin allowed) |
| Desktop-link session → rest of UI | `scope` column, `desktop_human` |
| Network → control plane | `bind_problem` TLS gate; proxy trust `*` |

## 6. Starting paths

`agentbox/service.py`, `sandbox.py`, `api.py`, `policy.py`, `desktop.py`, `audit.py`, `web.py`, `cli.py`, `config.py`, `approvals.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

run-1 (`7fc501f`, standard, source-only) ledger: 15 units; run-2 validated live. 9 confirmed records, all with changed source (fixed in PR #1–#5; N-1 GUI bypass only partially mitigated) → `prior_confirmed_changed_source` revalidation units, not excluded from hunting. One rejected claim (`desktop.py:redeem:sandbox-scoped-ticket-mints-unscoped-full-admin-session`): source changed (scope column), so the unit is current work. No same-source confirmed exclusions. Changed since `7fc501f`: 9 source files (+598/−67) — first priority.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent-driven work consumes the shared pool, memory, host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: browser UI with htmx and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 desktop helper killed/inspected by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release/signing path; CI only runs tests), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker/RPC beyond HTTP/WS/MCP stdio covered elsewhere).


# Execution paths

- Agent ID `p5-v02`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v02/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v02 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v02/artifacts/<file>`.

```text
Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker.
```


# report-schema.json branches (verbatim): confirmed, needs_validation, rejected

```json
{
 "type": "object",
 "description": "A source-grounded vulnerability that was independently demonstrated.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "confirmed"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
   "description": "A stable source-derived identifier that does not change between validation states."
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "intended_behavior": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "conditions": {
   "type": "array",
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "authentication_level",
       "authorization_role",
       "user_interaction",
       "system_configuration",
       "network_routing",
       "environmental_dependency",
       "data_state",
       "timing_dependency",
       "third_party_dependency"
      ]
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "execution": {
   "type": "object",
   "description": "Target-neutral reproduction in the target's native interface.",
   "properties": {
    "attacker_perspective": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "payloads": {
     "type": "array",
     "minItems": 1,
     "uniqueItems": true,
     "items": {
      "type": "string"
     }
    },
    "instructions": {
     "type": "array",
     "minItems": 1,
     "items": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "observed_result": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "attacker_perspective",
    "payloads",
    "instructions",
    "observed_result"
   ],
   "additionalProperties": false
  },
  "remediation": {
   "type": "object",
   "properties": {
    "strategy": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "code_changes": {
     "type": "array",
     "items": {
      "type": "object",
      "properties": {
       "file_name": {
        "type": "string",
        "minLength": 1
       },
       "fixed_code": {
        "type": "string"
       }
      },
      "required": [
       "file_name",
       "fixed_code"
      ],
      "additionalProperties": false
     }
    }
   },
   "required": [
    "strategy"
   ],
   "additionalProperties": false
  },
  "severity": {
   "type": "object",
   "properties": {
    "likelihood": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "impact": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "overall_severity": {
     "type": "string",
     "enum": [
      "informational",
      "low",
      "medium",
      "high",
      "critical"
     ]
    }
   },
   "required": [
    "likelihood",
    "impact",
    "overall_severity"
   ],
   "additionalProperties": false
  },
  "confidence": {
   "type": "object",
   "properties": {
    "score": {
     "type": "string",
     "enum": [
      "low",
      "medium",
      "high"
     ]
    },
    "reason": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "score",
    "reason"
   ],
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "root_cause",
  "intended_behavior",
  "trace",
  "evidence",
  "conditions",
  "execution",
  "remediation",
  "severity",
  "confidence"
 ],
 "additionalProperties": false
}

{
 "type": "object",
 "description": "A source-grounded candidate whose decisive validation is blocked.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "needs_validation"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$"
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "claimed_root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "blockers": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "string",
    "minLength": 1,
    "visibleContent": true
   }
  },
  "validation_plan": {
   "type": "object",
   "properties": {
    "local": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "deployment": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "claimed_root_cause",
  "trace",
  "evidence",
  "blockers",
  "validation_plan"
 ],
 "additionalProperties": false
}

{
 "type": "object",
 "description": "A source-grounded candidate refuted during validation.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "rejected"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$"
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "claimed_root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "reason": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "claimed_root_cause",
  "trace",
  "evidence",
  "reason"
 ],
 "additionalProperties": false
}
```


# Output

Return exactly one JSON object with no prose and no markdown fence, one of:
{"decision": "verified", "fingerprint": "<the record's fingerprint>"}
{"decision": "replace", "reason": "<what failed and why>", "record": {...}, "artifacts_to_promote": [...]}
A replacement record must match its `confirmed`, `needs_validation`, or `rejected` branch exactly (additionalProperties: false) and keep the same fingerprint unless you identified a genuinely different root cause. `artifacts_to_promote` is optional. Overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
