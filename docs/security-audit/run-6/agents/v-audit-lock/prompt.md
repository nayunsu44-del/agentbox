You are candidate verifier `v-audit-lock` in run-6 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at commit `530b29e` (after fix PRs #24 and #25). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory",
 "title": "Unindexed audit table scan in recent() and full-table fetchall in verify() hold global AuditLog._lock, causing availability stalls and memory exhaustion as table grows",
 "description": "The audit table schema defines no index on sandbox_id, yet GET /ui/audit (polled every 3 seconds by the sandbox UI) invokes AuditLog.recent(), which executes unindexed 'SELECT COUNT(*) FROM audit WHERE sandbox_id = ?' and 'SELECT ... WHERE sandbox_id = ?' queries under the global in-process AuditLog._lock. When an agent grows the table with realistic tool call payloads and previews (up to 128 KiB each), these queries must scan every leaf and overflow page. Furthermore, AuditLog.verify() executes 'SELECT ... FROM audit ORDER BY id' and calls .fetchall() under AuditLog._lock, holding the lock while loading all rows into Python memory at once (~487 MiB for 10,000 rows). Because AuditLog.append() (used by all tool logging and fail-closed log_human operations) serializes on AuditLog._lock, these operations block all human and agent actions for seconds, and verify() risks container OOM termination.",
 "root_cause": "AuditLog._lock is a coarse-grained process-wide lock held across long-running database read operations. The audit table lacks an index on sandbox_id, forcing full table scans on frequent UI polling (every 3s), and AuditLog.verify() unconditionally fetches all rows across the table's entire history into memory under the same lock rather than streaming, chunking, or querying via a non-blocking read connection in WAL mode.",
 "intended_behavior": "UI polling via recent() should be satisfied rapidly using an index on audit(sandbox_id) without scanning unrelated overflow pages. Verification in verify() should stream or paginate rows using fetchmany() outside the append lock, and should not hold the primary write lock across full-table queries.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/templates/sandbox.html",
   "line": 19,
   "scope": "sandbox.html",
   "description": "Operator viewing sandbox page triggers automatic polling of GET /ui/audit?sandbox_id={sid} every 3 seconds via htmx"
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 293,
   "scope": "audit_frag",
   "description": "audit_frag invokes box.audit.recent(sandbox_id=sandbox_id, limit=400)"
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 325,
   "scope": "AuditLog.recent",
   "description": "AuditLog.recent acquires self._lock and executes unindexed SELECT COUNT(*) and SELECT ... WHERE sandbox_id = ? scanning every leaf and overflow page"
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 293,
   "scope": "AuditLog.append",
   "description": "Every concurrent AuditLog.append call, including fail-closed log_human operator actions and agent tool calls, blocks on with self._lock"
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 27,
   "description": "audit table schema defines only id as primary key without any index on sandbox_id"
  },
  {
   "file": "agentbox/audit.py",
   "line": 325,
   "description": "AuditLog.recent executes unindexed table scan under self._lock for every poll"
  },
  {
   "file": "agentbox/audit.py",
   "line": 340,
   "description": "AuditLog.verify executes fetchall() of the entire audit table under self._lock, buffering all payloads in Python memory"
  },
  {
   "file": "agentbox/templates/sandbox.html",
   "line": 19,
   "description": "Audit timeline polls /ui/audit every 3s, causing continuous lock contention as row count and payload sizes grow"
  },
  {
   "file": "agentbox/service.py",
   "line": 705,
   "description": "Human operations serialized through log_human block on self._lock while long-running queries or fetchall hold the lock"
  }
 ],
 "conditions": [
  {
   "kind": "data_state",
   "description": "The audit table has accumulated thousands of rows containing realistic tool payloads and approval previews (16-32 KiB each) within the 90-day retention window"
  },
  {
   "kind": "user_interaction",
   "description": "A human operator opens the web UI sandbox view (triggering 3s polling) or clicks verify chain"
  }
 ],
 "execution": {
  "attacker_perspective": "An unprivileged agent generating ordinary tool executions (e.g. exec, write_file) with 16-25 KiB arguments or previews populates the audit table up to tens of thousands of rows. When a human administrator views the sandbox UI (which polls /ui/audit every 3s) or triggers /ui/verify, the unindexed table scan and full table fetchall hold the global AuditLog._lock for seconds at a time and allocate hundreds of megabytes of memory, degrading control-plane responsiveness and blocking all tool logging and human admin actions.",
  "payloads": [
   "python3 /scratch/bench_realistic.py"
  ],
  "instructions": [
   "Create an AuditLog database with 1,200 rows containing realistic ~25 KiB tool call/preview payloads (~30.5 MiB database size).",
   "Invoke AuditLog.recent('sb_other', limit=25) to measure unindexed leaf/overflow page scan duration under self._lock.",
   "Invoke AuditLog.verify() to measure lock hold time and peak heap memory allocation during self.conn.execute(...).fetchall() under self._lock."
  ],
  "observed_result": "In an isolated 512 MiB sandbox with 1,200 rows of 25.2 KiB payloads (30.49 MiB DB), recent('sb_other', limit=25) held AuditLog._lock for 113.31ms. Full table fetchall in verify() held AuditLog._lock for 1264.15ms (1.26s) with a peak memory allocation of 58.45 MiB. Extrapolated to 10,000 rows (~200 MiB table), verify() holds AuditLog._lock for ~10.5s while consuming ~487 MiB of memory, and 3-second polling by sandbox.html holds the lock for ~0.94s per poll (occupying over 30% of total available time), blocking all concurrent audit.append and log_human calls."
 },
 "remediation": {
  "strategy": "1. Add an index on audit(sandbox_id) in SCHEMA (CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id)) so that recent() queries for a specific sandbox only read relevant rows rather than scanning the entire table and all overflow pages./n2. In AuditLog.verify(), avoid holding self._lock across the entire fetchall() or iterate through rows in bounded batches (or fetch only necessary columns such as id, ts, prev_hash, hash, payload with fetchmany) outside the lock, or run verification queries on a separate read connection under SQLite WAL mode without blocking the in-process append lock.",
  "code_changes": [
   {
    "file_name": "agentbox/audit.py",
    "fixed_code": "CREATE TABLE IF NOT EXISTS audit (/n    id          INTEGER PRIMARY KEY,/n    ts          TEXT NOT NULL,/n    sandbox_id  TEXT,/n    actor       TEXT NOT NULL,/n    event       TEXT NOT NULL,/n    tool        TEXT,/n    payload     TEXT NOT NULL,/n    prev_hash   TEXT NOT NULL,/n    hash        TEXT NOT NULL/n);/nCREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id);/n"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Any active agent operating over several hours or days naturally generates thousands of audit entries with previews and tool arguments, and the web UI polls /ui/audit automatically every 3 seconds whenever a human operator views the sandbox page."
  },
  "impact": {
   "score": "medium",
   "reason": "Global lock contention on AuditLog._lock stalls all concurrent tool executions and human administrative operations for seconds at a time; whole-table fetchall() during verify() loads hundreds of megabytes into Python memory, risking out-of-memory container termination in constrained environments."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Demonstrated directly via controlled local execution in the sandbox, measuring exact lock hold durations and memory allocation on realistic payload sizes."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "AuditLog._lock%20as%20a%20global%20contention%20point%20reachable%20by%20agent-grown%20table%20size%20and%20by%20unauthenticated%20traffic%3A%20GET%20%2Fui%2Faudit%20%28polled%20every%203%20s%20by%20templates%2Fsandbox.html%29%2C%20GET%20%2Fui%2Fverify%2C%20GET%20%2Faudit%2Fverify%2C%20AuditLog.recent%20%28unindexed%20COUNT%28%2A%29%20WHERE%20sandbox_id%29%2C%20AuditLog.verify%20%28fetchall%20of%20the%20whole%20table%2C%20audit.py%3A336-350%29%2C%20AuditLog.list%2C%20versus%20every%20AuditLog.append%2Finsert_record%20from%20agent%20tool%20calls%20and%20every%20fail-closed%20log_human%3B%20plus%20the%20unauthenticated%20POST%20%2Flogin%20failure%20throttle%20%28web.py%3A93-114%29%20and%20extract_novnc%20single-flight%20%28sandbox_desktop.py%3A174%29::Agent%20and%20unauthenticated%20clients%20to%20human%20availability%20and%20audit%20evidence%3A%20AuditLog.recent%2Fverify%20scan%20the%20agent-grown%20table%20under%20the%20same%20_lock%20append%20needs%20%28fail-closed%20log_human%20returns%20503%20while%20it%20is%20held%29%2C%20verify%20loads%20the%20whole%20table%2C%20the%20F8%20login%20throttle%20shares%20one%20global%20window%2C%20and%20F5%20extract_novnc%20holds%20a%20global%20lock%20across%20docker%20create.%20Invariant%3A%20no%20agent%20or%20unauthenticated%20sequence%20holds%20these%20locks%20long%20enough%20to%20refuse%20human%20actions%2C%20exhaust%20memory%2C%20or%20hide%20credential-guessing%20evidence.::agentbox%2Faudit.py%23recent%2Fverify%2Flist%2Fappend%2Finsert_record%2F_lock%20%2B%20agentbox%2Fweb.py%23note_login_failure%2Faudit%20and%20verify%20routes%20%2B%20agentbox%2Fapi.py%23%2Faudit%2Fverify%20%2B%20agentbox%2Fsandbox_desktop.py%23extract_novnc%2F_NOVNC_LOCK%20%2B%20agentbox%2Ftemplates%2Fsandbox.html%20%283%20s%20poll%29::Resource%20exhaustion%3A%20lock%20contention%20and%20pre-authentication%20work%20imbalance",
  "surface": "AuditLog._lock as a global contention point reachable by agent-grown table size and by unauthenticated traffic: GET /ui/audit (polled every 3 s by templates/sandbox.html), GET /ui/verify, GET /audit/verify, AuditLog.recent (unindexed COUNT(*) WHERE sandbox_id), AuditLog.verify (fetchall of the whole table, audit.py:336-350), AuditLog.list, versus every AuditLog.append/insert_record from agent tool calls and every fail-closed log_human; plus the unauthenticated POST /login failure throttle (web.py:93-114) and extract_novnc single-flight (sandbox_desktop.py:174)",
  "boundary": "Agent and unauthenticated clients to human availability and audit evidence: AuditLog.recent/verify scan the agent-grown table under the same _lock append needs (fail-closed log_human returns 503 while it is held), verify loads the whole table, the F8 login throttle shares one global window, and F5 extract_novnc holds a global lock across docker create. Invariant: no agent or unauthenticated sequence holds these locks long enough to refuse human actions, exhaust memory, or hide credential-guessing evidence.",
  "local_checks": [
   {
    "agent_id": "h-locks-ws",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/service.py"
    ],
    "invariant": "AuditLog._lock hold duration and serialization with fail-closed log_human",
    "method": "local",
    "result": "Benchmarked AuditLog.recent() and verify() hold times over a 10,000-row table (~31ms recent query hold time). Concurrently tested log_human() while AuditLog._lock was held: log_human() blocked cleanly on with self._lock until release and succeeded; Python threading.Lock has no timeout and does not raise AuditWriteError or trigger a 503 ServiceError under lock contention.",
    "artifact": "agents/h-locks-ws/artifacts/h_locks_ws.out"
   },
   {
    "agent_id": "h-locks-ws",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/templates/sandbox.html",
     "agentbox/web.py"
    ],
    "invariant": "Authorization gates on audit table read and verification endpoints",
    "method": "source",
    "result": "Verified that GET /ui/audit (polled every 3s in sandbox.html) and GET /ui/verify in web.py:291,297 require browser_human (screen_human, scope '*'), and GET /audit and GET /audit/verify in api.py:356,362 require human_only. Neither unauthenticated clients nor agent tokens can invoke recent(), verify(), or list(), preventing untrusted table scanning or verification memory amplification.",
    "artifact": null
   },
   {
    "agent_id": "h-locks-ws",
    "reviewed_paths": [
     "agentbox/sandbox_desktop.py",
     "agentbox/web.py"
    ],
    "invariant": "Isolation of login failure throttle and noVNC extraction single-flight lock",
    "method": "source",
    "result": "Confirmed in web.py:93-114 that note_login_failure() uses an in-memory fails_lock held only for sub-microsecond dict mutations, logging up to 5 individual failures per 60s window and aggregating excess into suppressed_before on the next window to prevent audit lock contention without dropping guessing evidence. In sandbox_desktop.py:174-192, _NOVNC_LOCK is fast-path bypassed once rfb.js exists and is isolated strictly to extract_novnc, with a 60s retry backoff on failure, preventing docker create thrashing and cross-subsystem contention.",
    "artifact": null
   },
   {
    "agent_id": "h-locks-ws",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "AuditLog._lock hold duration during unindexed UI polling and full-table verify fetchall under realistic payload sizes",
    "method": "local",
    "result": "Demonstrated that with realistic ~25 KiB payloads (30.5 MiB DB across 1,200 rows), unindexed recent() holds AuditLog._lock for 113.3ms per poll, and verify() holds AuditLog._lock for 1,264ms during fetchall while peaking at 58.5 MiB memory. Extrapolated to 10,000 rows (~200 MiB), verify() holds the lock for ~10.5s while consuming ~487 MiB memory, and 3-second UI polling holds the lock for ~0.94s per poll, stalling all concurrent tool execution and human log_human calls.",
    "artifact": "agents/h-locks-ws/artifacts/bench_realistic.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint

```json
- none
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-6)
Source ref: `530b29e` (`main`, after fix PRs #24 and #25). Profile `standard`, focused follow-up, budget 30 (all subagents `flash`). This file is the run-4/run-5 architecture plus a parent-written delta in section 0 covering every file changed since `346df29` (PRs #24 and #25: 13 non-test files in `agentbox/` and `deploy/`) and the run-5 delta from `9805d91` to `346df29`. No reconnaissance agent was spent in run-6: the parent inspected the full diff `346df29..530b29e`. **Line numbers in section 0.1 are exact at `530b29e`; section 0.2 has `346df29` numbers; sections 1-8 are `9805d91` numbers.**
## 0.1 Run-6 delta (changes in PRs #24 and #25, exact line numbers at `530b29e`)
- **Pre-read credential gate and anonymous body cap (`api.py`, `config.py`, `cli.py`, `deploy/`, PR #25 — run-5 N1 fix).**
  - `api.py:52-54`: `_UPLOAD_PATH = re.compile(r"/sandboxes/[^/]+/files")`, `_ANON_BODY_PATHS = {"/login"}`, `_ANON_BODY_MAX = 64 * 1024`.
  - `api.py:57-128` `_BodyLimit`: takes `authenticated` callback (`api.py:63-65`, wired at `api.py:185-201`). Rejects invalid/over-20-digit/over-cap `Content-Length` with 413 (`api.py:84-86`). Computes `has_body = (length is not None and int(length) > 0) or b"transfer-encoding" in headers` (`api.py:87`). If `has_body` and `scope["path"] in _ANON_BODY_PATHS`, lowers `cap = min(cap, _ANON_BODY_MAX)` (64 KiB) and rechecks `Content-Length` (`api.py:88-91`). Otherwise, if `has_body and self.authenticated and not await run_in_threadpool(self.authenticated, headers)`, rejects with 401 before reading any body (`api.py:92-95`). Streamed bodies remain capped at `cap` in `limited_receive` (`api.py:98-115`).
  - `api.py:185-199` `authenticated(headers)`: checks `Authorization: Bearer <token>` via `secrets.compare_digest` against `human_token` or `box.sandboxes.sandbox_for_token(token) is not None`, else parses `Cookie` with `http.cookies.SimpleCookie` and checks `box.desktop.session_scope(got.value)` for `D.COOKIE`. Route-level authorization (`human_only`, sandbox ownership, `same_origin`) still runs in route dependencies.
  - `config.py:68`: `max_connections` (`AGENTBOX_MAX_CONNECTIONS`, default 256; 0 disables); `cli.py:126-127` passes `limit_concurrency=s.max_connections` to `uvicorn.run`.
  - `deploy/Caddyfile:8-15`: `@upload path_regexp ^/sandboxes/[^/]+/files$` gets `AGENTBOX_PROXY_MAX_BODY` (256MB), `@other` gets `AGENTBOX_PROXY_MAX_JSON` (8MiB). `deploy/docker-compose.yml:20`: `mem_limit: ${AGENTBOX_MEM_LIMIT:-2g}`.
- **Desktop lock split and WebSocket threadpool offload (`desktop.py`, `desktop_ws.py`, `api.py`, PR #24 — run-5 F4 fix).**
  - `desktop.py:93-94`: `DesktopControl` splits `self._lock` (in-memory `_leases`, `_conns`, `_gui_locks`) from `self._db_lock` (SQLite `self._db`). Documented lock order when acquiring both: `_db_lock -> _lock`.
  - Ticket and session methods (`issue_ticket:116`, `redeem:124`, `start_session:139`, `end_session:147`, `session_scope:153`) take only `_db_lock`.
  - Lease and connection methods that touch both (`take:194`, `release:215`, `leftover_leases:235`, `forget_lease:246`, `close_all:299`) take `_db_lock` then `_lock`. In-memory-only methods (`lease`, `touch`, `is_stale`, `gui_lock`, `may_connect`, `add_conn`, `drop_conn`, `conns`, `end_session_conns`) take only `_lock`.
  - `api.py:441`: `desktop_ws` runs `await run_in_threadpool(box.desktop.session, cookie, sid)` before `same_origin(ws.headers)` (`api.py:442`, `same_origin` at `api.py:221-223`).
  - `desktop_ws.py:21-22`: `relay` runs `vnc_command` and `log_human("desktop_connect")` via `run_in_threadpool`. Periodic session recheck (`desktop_ws.py:76`) also uses `run_in_threadpool`. `finally` block (`desktop_ws.py:93-113`) runs `log_best_effort("desktop_disconnect")` on default executor inside `await asyncio.shield(logged)` before `box.desktop.drop_conn(conn)`.
- **GUI burst under takeover lease (`service.py`, PR #24 — run-5 F2 fix).**
  - `service.py:265-284` `_snapshot`: for `tool in GUI_INPUT`, after `sandboxes.snapshot`, acquires `with self._gui_locked(sid, "GUI 구간 열기"):`, runs `self._check_control(sid)`; only if no `HumanControl` is raised does it call `bursts.mark_snapshot(sid)` and `bursts.open(sid, snap["id"])`. Always appends the `snapshot` audit record (`service.py:280-281`), then if `human` was caught calls `self.bursts.reset_timers(sid)` and raises `human` (`service.py:282-284`).
  - `service.py:396-397`: `call_tool` catches `HumanControl` from `_snapshot` and delegates to `_human_blocked` (`service.py:411-419`, returns 423 and logs `tool_blocked`).
  - `service.py:498-514` `decide`: before `_snapshot`, if `tool in GUI_INPUT` and active lease or `_takeover_pending(sid)`, finishes approval as `FAILED` without taking a snapshot or opening a burst; also catches `HumanControl` from `_snapshot` (`service.py:511-514`).
- **Tool argument length cap, policy re-lex skip, and preview caps (`service.py`, `policy.py`, `preview.py`, `sandbox.py`, PR #24 — run-5 F1/F5/F6 fixes).**
  - `service.py:49`: `TOOL_ARG_MAX = 16 * 1024`. In `_call_tool` (`service.py:323-329`), before `tool_request` audit and `policy.decide`, rejects any arg `k != "content"` whose `len(v if isinstance(v, str) else json.dumps(v, default=str)) > TOOL_ARG_MAX` with 413 (`argument_too_long`).
  - `service.py:357-362`: in the `REQUIRE_APPROVAL` branch, applies `preview = bound_payload(preview)` before storing the pending approval row, and re-checks `if actor == "agent" and self.disk_low():` raising 507 before `_capture` and `approvals.create`.
  - `policy.py:27, 40-49, 73`: `_LEX_PUNCT = set(";&|()<>")`; `_relex_changes(t)` returns `False` for tokens consisting solely of `_LEX_PUNCT` or tokens with no whitespace, `_LEX_PUNCT`, quotes, or backslashes (e.g. `'x$'`), avoiding redundant recursive `_words(t, depth + 1)` calls.
  - `preview.py:70-71`: `PREVIEW_CALLS_MAX = 40`, `NOTES_MAX = 50`. `preview_command` (`preview.py:74-160`) deduplicates `rm` operands via `dict.fromkeys(operands)` (`:105`), caps total `expand`/`walk` calls at 40 via `budget()`, appends a Korean note when `skipped > 0` (`:154-156`), and truncates `notes` to `NOTES_MAX` plus a summary note (`:157-159`).
  - `sandbox.py:39, 104-106, 578-594`: `_PREVIEW_TIMEOUT = 10`; `_expand` and `_walk` wrap their container `sh -c` in `_timed(_PREVIEW_TIMEOUT, ...)` and call `_preview_ok(res)` (raises `SandboxError` on exit code 124 or 137).
- **Retention prune post-COMMIT archive safety (`retention.py`, PR #24 — run-5 F3 fix).**
  - `retention.py:104-108`: unlinks partial archive if `_write_archive` raises before the transaction.
  - `retention.py:131-145`: on exception inside the transaction block, rolls back only `if conn.in_transaction`; in the outer handler, queries `SELECT 1 FROM audit_anchor WHERE archive = ? AND archive_sha256 = ?` (defaulting `committed = True` on `sqlite3.Error`) and only unlinks the archive if `not committed`.
## 0.2 Run-5 delta (changes in PRs #16-#23, `346df29` line numbers)
- **Body cap (F1 fix, PR #16)**, **Audit cap (F3 fix, PR #16)**, **GUI gate (F2) and quota recheck (F7, PR #17)**, **Lifecycle lock (F6), F4 NUL-separated preview `_expand`/`_walk`, F5 single-flight `extract_novnc`, F8 login failure rate limit (PR #18)**, **Control-character filter `display.escape_controls` Cc/Cf/Zl/Zp (N5, PR #19)**, **Disk guard `disk_low` and finished-approval compaction (N2 stage 1, PR #20)**, **Host CLI `agentbox prune` and `audit_anchor` (N2 stage 2, PR #21)**, **Window owner via XRes `XResQueryClientIds` (N4, PR #22)**.
- **LLM-provider data path (PR #23)**: documented owner-accepted limitation; out of scope for hunting.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py`): full JSON API (`api.py` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default, and the bare `create_app` factory (`api.py`) that skips the serve-time gates. Container flags (`sandbox.py`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Windows 11 with Docker Desktop WSL2 Linux engine 29.9.2, runtimes `runc`/`io.containerd.runc.v2`, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1`, `agentbox-audit-sbx:1`. Agent-run code goes through `tools/sbx.py` (no network, read-only target at `/target`, writable `/scratch`, uid 65534, 512 MiB, 64 pids, 120 s). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`, `test_m5_unit.py`, `test_retention.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (16 KiB arg cap `TOOL_ARG_MAX` → audit with capped args `_logged_args` → `policy.decide` → quota → approval with bounded preview & `disk_low` recheck or `_snapshot` → `_run_tool`) on the 32-thread `tool_pool`. Pending approvals capped at 20.
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide`: atomic claim, GUI lease check, snapshot, run stored args. Preview (`preview.py` `preview_command` with `_expand`/`_walk` callbacks, 40-call budget, 10 s timeout per call) and capture run before the approval exists.
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per san

# Relevant companion blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance -->
**Pre-authentication work imbalance**
Expensive parsing, key lookup, cryptography, decompression, or external requests happen before authentication and the earliest size/rate gate. Compare minimal requester effort to shared service cost and check upstream limits.

# Verifier instructions (verbatim)

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

1. Verify every trace and evidence file, positive line number, scope, and description.
   Confirm the first entry is a real lower-trust entrypoint and the last is the
   claimed sink or boundary effect.
2. Reconstruct the strongest source-visible validation, identity, authorization,
   normalization, lifecycle, framework, and containment controls on the path.
   Where the architecture summary names a comparable baseline, note whether it
   shares the pattern — as calibration, never as grounds to dismiss.
3. For a proposed confirmed candidate, independently reproduce the minimum observed
   result when possible. Verify inputs, interface shape, conditions, and affected
   dummy principal/resource. Do not infer a stronger result or continue after it.
4. Verify that likelihood, impact, confidence, and the proposed source fix match only
   what the evidence establishes.
5. For a proposed needs_validation candidate, decide whether the blocker is genuinely
   outside source/local observation. If source refutes the trace, reject it. If the
   missing fact remains decisive, keep needs_validation and make the local and
   owner-observed plans exact and non-destructive.
6. Preserve the fingerprint for the same source-derived root cause across every state.

Return exactly one JSON object and no surrounding prose:
{"decision": "confirmed|needs_validation|rejected", "record": { ... }}
where record exactly matches the decision's verdict branch of the schema included
in this prompt. A corrected record replaces the hunter's wording.
```

# Artifact promotion procedure (verbatim)

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

# Execution boundary and paths

- Agent ID `v-audit-lock`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/v-audit-lock/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-audit-lock <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-audit-lock /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-audit-lock/artifacts/<file>`.
- Your final message must be ONLY the JSON object `{"decision": ..., "record": {...}}` plus that optional field. No prose, no code fence.

# report-schema.json branches (verbatim)

## `confirmed`

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
```

## `needs_validation`

```json
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
```

## `rejected`

```json
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
