You are candidate verifier `v-ws` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop",
 "title": "Desktop WebSocket handler blocks the shared event loop on SQLite and audit locks, so one desktop connect stalls every HTTP route",
 "description": "The async route /sandboxes/{sid}/desktop/ws (api.py:408-418) and desktop_ws.relay make synchronous SQLite, threading.Lock and Docker SDK calls directly on the asyncio event loop: session lookup, the log_human audit write, vnc_command (_rec + containers.get), the per-message touch(), the 30 s session re-check and the disconnect audit write. While another SQLite connection holds the write lock (retention.prune's BEGIN IMMEDIATE) or a worker holds AuditLog._lock or DesktopControl._lock, a single desktop WS connect or disconnect freezes the whole control plane: every route, including human approvals and deletes, agent tool responses and /healthz, for up to the 5 s busy timeout or the remaining lock hold. A desktop-link session scoped to one sandbox can repeat this by reconnecting, and the desktop page itself auto-reconnects 1.5 s after a server close. An unauthenticated upgrade with any junk cookie also stalls the loop when DesktopControl._lock is held by a worker that is waiting on a SQLite write. This undoes the design intent at api.py:158-160, which isolates blocking work so it cannot stop the human API.",
 "root_cause": "desktop_ws (api.py:410-418) and relay (desktop_ws.py:20-21,41,57,72,91) call blocking functions without run_in_threadpool: DesktopControl.session_scope (desktop.py:152-160), AgentBox.log_human / log_best_effort -> AuditLog.append (BEGIN IMMEDIATE under AuditLog._lock, default 5 s busy timeout; audit.py:259,292-296), SandboxManager._rec / containers.get (sandbox.py:185-186,230) and DesktopControl.touch/add_conn. DesktopControl also holds its in-memory _lock across SQLite writes (desktop.py:113-115,120-127,135-139,197-198,204), so the event loop inherits any SQLite write wait that a worker thread is in.",
 "intended_behavior": "The event loop never waits on SQLite, threading locks held across I/O, or the Docker daemon. A slow or locked database, or a slow audit read, should only delay the request that needs it, and should never delay unrelated HTTP and WebSocket traffic or responses for other sandboxes.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 409,
   "scope": "desktop_ws",
   "description": "Async WebSocket route; the cookie comes from the upgrade request."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 411,
   "scope": "desktop_ws",
   "description": "box.desktop.session(cookie, sid) is called synchronously on the event loop."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 152,
   "scope": "DesktopControl.session_scope",
   "description": "Takes threading.Lock _lock, which workers hold across SQLite writes (new_session/take/release), and blocks the loop thread while it waits."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop_ws.py",
   "line": 20,
   "scope": "relay",
   "description": "vnc_command -> _rec (SandboxManager._lock + SQLite) and containers.get (Docker HTTP) on the loop."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop_ws.py",
   "line": 21,
   "scope": "relay",
   "description": "box.log_human runs on the loop."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 294,
   "scope": "AuditLog.append",
   "description": "Under AuditLog._lock, BEGIN IMMEDIATE waits up to the default 5 s busy timeout for the write lock, and the whole event loop is blocked during the wait."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/desktop_ws.py",
   "line": 91,
   "description": "The disconnect audit write (log_best_effort) also runs on the loop in finally, so closing a tab stalls the loop too."
  },
  {
   "file": "agentbox/desktop_ws.py",
   "line": 57,
   "description": "touch() takes DesktopControl._lock on the loop for every client message in control mode."
  },
  {
   "file": "agentbox/retention.py",
   "line": 106,
   "description": "prune holds the SQLite write lock (BEGIN IMMEDIATE) for its whole delete transaction."
  },
  {
   "file": "agentbox/audit.py",
   "line": 338,
   "description": "verify() reads the whole audit table under AuditLog._lock; recent() (audit.py:311-316) does an unindexed COUNT(*) under the same lock, polled every 3 s by the sandbox page."
  },
  {
   "file": "agentbox/api.py",
   "line": 158,
   "description": "Comment states the design intent: blocking tool work is kept off shared execution so the agent cannot freeze the human API."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 135,
   "description": "new_session holds _lock across DELETE+INSERT, so it waits the busy timeout while holding the lock the loop needs."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "For the 5 s audit stall: a valid desktop-link session (scope one sandbox) or a full UI session. For the DesktopControl._lock stall: none (any cookie value)."
  },
  {
   "kind": "timing_dependency",
   "description": "A concurrent long holder must exist: retention.prune's BEGIN IMMEDIATE on the same DB (operator maintenance), a worker inside AuditLog._lock (verify/recent over a large, agent-grown table), or a human desktop write (login/ticket/takeover/handback) that is waiting on the SQLite write lock."
  },
  {
   "kind": "data_state",
   "description": "The stall length is bounded by the 5 s default sqlite busy timeout for each write attempt, or by the remaining audit-lock hold, which grows linearly with audit rows."
  }
 ],
 "execution": {
  "attacker_perspective": "A holder of a desktop link (scoped human session), or just an open desktop tab that auto-reconnects, connects to the desktop WebSocket while another SQLite connection holds the write lock or a worker holds the audit lock.",
  "payloads": [
   "/home/user/agentbox/docs/security-audit/run-5/tools/sbx h-ws /usr/bin/python3.13 /scratch/h.py (h.py: real agentbox.api.build() app with docker.from_env replaced by an in-process fake; dummy human token hum_ddd..., sandbox sb_x template desktop, desktop-link session from box.desktop.new_session('sb_x'))"
  ],
  "instructions": [
   "Ran in the parent-approved sandbox (no network, no Docker, uid 65534, 512 MiB, 120 s), with AGENTBOX_HOME=/scratch/home, AGENTBOX_DOCKER_CLI=/bin/false and AGENTBOX_MIN_FREE=0.",
   "For each scenario, started a contention holder in a thread: (a) a second sqlite3 connection running BEGIN IMMEDIATE for 7 s, (b) a worker inside AuditLog._lock for 4 s, or (c) BEGIN IMMEDIATE plus a worker calling box.desktop.new_session().",
   "Opened TestClient.websocket_connect('/sandboxes/sb_x/desktop/ws?mode=view') with the link-session cookie, a junk cookie or no cookie, then 0.3 s later timed GET /healthz on the same app."
  ],
  "observed_result": "Baseline healthz 0.0 s. Link-session WS under the write lock: healthz 4.72 s, WS closed 1011 after 5.02 s. Junk/no cookie under the write lock: 0.0 s. Junk cookie while new_session waited on the write lock: healthz 4.41 s. Link-session WS while AuditLog._lock was held 4 s: healthz 3.53 s. Junk cookie under the audit lock: 0.0 s."
 },
 "remediation": {
  "strategy": "Move every blocking call in desktop_ws/relay off the event loop (run_in_threadpool, or the dedicated pool for audit writes), and stop holding DesktopControl._lock across SQLite I/O by using a separate DB lock, so that touch/add_conn/lease never wait on a database. Regression test: while a second connection holds BEGIN IMMEDIATE, or a thread holds AuditLog._lock, a desktop WS connect must leave GET /healthz latency under 0.5 s.",
  "code_changes": [
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "    @app.websocket(\"/sandboxes/{sid}/desktop/ws\")\n    async def desktop_ws(ws: WebSocket, sid: str, mode: str = \"view\"):\n        cookie = ws.cookies.get(D.COOKIE)\n        if mode not in (\"view\", \"control\") or not same_origin(ws.headers) or not cookie:\n            await ws.close(code=4401)\n            return\n        session = await run_in_threadpool(box.desktop.session, cookie, sid)\n        if not session:\n            await ws.close(code=4401)\n            return\n        if not await run_in_threadpool(box.desktop.may_connect, sid, session, mode):\n            await ws.close(code=4403)\n            return\n        await relay(ws, box, sid, session, mode, cookie)"
   },
   {
    "file_name": "agentbox/desktop_ws.py",
    "fixed_code": "    try:\n        argv = await run_in_threadpool(box.sandboxes.vnc_command, sid, mode == \"view\")\n        await run_in_threadpool(box.log_human, \"desktop_connect\", sid, {\"session\": session, \"mode\": mode})\n    except (SandboxError, ServiceError):\n        ...\n    # session_watch: if not await run_in_threadpool(box.desktop.session, cookie, sid): ...\n    # finally: schedule box.log_best_effort(...) on a worker thread (e.g. loop.run_in_executor) instead of calling it inline"
   },
   {
    "file_name": "agentbox/desktop.py",
    "fixed_code": "# keep self._lock for the in-memory dicts only; guard self._db with a separate self._db_lock,\n# and never take self._db_lock while holding self._lock, so touch()/lease()/add_conn() never wait on SQLite"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Needs a concurrent long SQLite/audit lock holder (operator prune, a human audit view over a large table, or a human desktop write during such a hold) to coincide with a desktop WS event. A desktop-link holder can repeat connects, but cannot create the lock hold itself."
  },
  "impact": {
   "score": "low",
   "reason": "Temporary freeze of all control-plane HTTP/WS traffic (observed 3.5-4.7 s per event, repeatable by reconnecting while the condition lasts). No data or authority gain."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The event-loop stall was observed with real handler, audit and SQLite code in the sandbox. Real prune durations and Docker daemon latency were not measured (Docker was faked)."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20upgrade%20before%20ws.accept%28%29::agentbox%2Fapi.py%23desktop_ws%20async%20handler%3A%20synchronous%20SQLite%20%28session%2C%20lease%29%20and%20Docker%20SDK%20calls%20on%20the%20event%20loop%20before%20accept%20%2B%20agentbox%2Fdesktop_ws.py%23relay%20setup::agentbox%2Fapi.py%20%2B%20agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation",
  "surface": "agentbox/api.py#WebSocket /sandboxes/{sid}/desktop/ws upgrade before ws.accept()",
  "boundary": "agentbox/api.py#desktop_ws async handler: synchronous SQLite (session, lease) and Docker SDK calls on the event loop before accept + agentbox/desktop_ws.py#relay setup",
  "local_checks": [
   {
    "agent_id": "h-ws",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/desktop.py"
    ],
    "invariant": "Pre-authentication work imbalance: an unauthenticated WS upgrade to /sandboxes/{sid}/desktop/ws must not do expensive or blocking work before it is rejected.",
    "method": "source",
    "result": "api.py:408-416 (desktop_ws) runs on the event loop. With no cookie, desktop.session -> session_scope returns None before any DB access (desktop.py:150-151). With any cookie value it does one SHA-256 plus a primary-key SELECT under DesktopControl._lock (desktop.py:152-160). The DELETE branch only runs for an existing row that is expired or has the wrong gen, so an unauthenticated client cannot reach a write. The DB is in WAL mode (audit.py:260), so the SELECT never waits on a writer. The per-request cost is about the same as any cookie route, so there is no pre-auth imbalance on its own. The only pre-auth stall is through DesktopControl._lock contention (see the local check, S5), and that needs a concurrent human desktop write plus another SQLite writer.",
    "artifact": null
   },
   {
    "agent_id": "h-ws",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/desktop_ws.py",
     "agentbox/desktop.py",
     "agentbox/audit.py",
     "agentbox/service.py"
    ],
    "invariant": "Worker/event-loop starvation: a desktop WS connect (pre- or post-auth) must not block the shared asyncio event loop on SQLite locks, audit locks or Docker calls, which would stall every HTTP route.",
    "method": "local",
    "result": "Harness h.py ran in tools/sbx with the real agentbox.api.build() app and the Docker SDK faked in-process. It timed GET /healthz (a sync route) sent 0.3 s after a WS upgrade. Baseline 0.0 s. S2: desktop-link session WS while another SQLite connection held BEGIN IMMEDIATE (as retention.prune does) gave healthz 4.72 s and WS close 1011 after 5.02 s; log_human waited out the 5 s default busy timeout on the event loop. S3/S4: junk cookie or no cookie under the same write lock gave 0.0 s. S5: junk-cookie (unauthenticated) WS while a human new_session() waited on the write lock holding DesktopControl._lock gave healthz 4.41 s. S6: link-session WS while a worker held AuditLog._lock for 4 s gave healthz 3.53 s. S7: junk cookie under the same audit lock gave 0.0 s. S8: audit.verify() over 100k rows held the lock briefly (verify 0.84 s total, healthz 0.13 s). The event-loop stall is shown with real handler code.",
    "artifact": "agents/h-ws/artifacts/h.out"
   },
   {
    "agent_id": "h-ws",
    "reviewed_paths": [
     "agentbox/desktop_ws.py",
     "agentbox/sandbox_desktop.py",
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "Relay setup and teardown work must run off the event loop.",
    "method": "source",
    "result": "These synchronous calls run on the event loop. Setup: relay -> box.sandboxes.vnc_command (desktop_ws.py:20) -> _desktop -> template_of/_require_running -> _rec (SandboxManager._lock + SQLite, sandbox.py:185-186) and client.containers.get, a blocking Docker HTTP call (sandbox.py:230). Then box.log_human, an audit BEGIN IMMEDIATE under AuditLog._lock (desktop_ws.py:21, service.py:658-662, audit.py:292-296). Per connection: add_conn and touch(), and touch() takes DesktopControl._lock on every client message in control mode (desktop_ws.py:41,57). Session re-check every 30 s (desktop_ws.py:72). Teardown: log_best_effort audit append in finally (desktop_ws.py:91). Only the x11vnc subprocess spawn and the I/O are async. How Docker daemon latency affects containers.get cannot be observed offline (the client is faked); the SQLite and lock paths are enough for the stall.",
    "artifact": null
   },
   {
    "agent_id": "h-ws",
    "reviewed_paths": [
     "agentbox/retention.py",
     "agentbox/audit.py",
     "agentbox/web.py",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "Which principals can create the long lock holds that the event loop then waits on.",
    "method": "source",
    "result": "Long holders found: retention.prune keeps the SQLite write lock for its whole BEGIN IMMEDIATE transaction (retention.py:91,106-129; timeout=30), started by the host operator. AuditLog.verify fetches the whole table under _lock (audit.py:338-340), reached from human /audit/verify and /ui/verify. AuditLog.recent runs COUNT(*) WHERE sandbox_id under _lock with no index on sandbox_id (audit.py:26-37,311-316); the sandbox page polls it every 3 s (templates/sandbox.html:19, web.py:290-293). The agent cannot hold these locks itself. It can only grow the audit table, which makes the human-run reads take longer (measured 0.034 s for recent and 0.84 s for verify per 100k rows). The trigger is a desktop WS connect, disconnect or auto-reconnect from a human or desktop-link session.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-4 wording)

```json
- none
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-5)
Source ref: `346df29` (`main`, after fix PRs #16-#23). Profile `standard`, focused follow-up, budget 30. This file is the run-4 architecture (built at `9805d91` from recon-1a..1d) plus a parent-written delta in section 0. No reconnaissance agent was spent in run-5: the parent re-read every file changed since `9805d91` (15 files, +712/-148 in `agentbox/`). **Line numbers in sections 1-8 are run-4 (`9805d91`) numbers and are approximate in this tree; section 0 numbers are current.**
## 0. Run-5 delta (current line numbers, `346df29`)
- **Body cap (F1 fix, PR #16).** `api.py:89-148` `_BodyLimit` pure-ASGI middleware, added at `api.py:170`, runs before routing and auth for every `http` scope (not `websocket`). Cap = `max_upload_body_bytes` (`AGENTBOX_MAX_UPLOAD_BODY`, 256 MiB) when `POST` and path fullmatches `/sandboxes/[^/]+/files` (`api.py:86`), else `max_body_bytes` (`AGENTBOX_MAX_BODY`, 8 MiB) (`config.py:65-66`). Content-Length over cap or non-digit → 413 without reading; streamed bodies are counted in `limited_receive` and cut with a fake `http.disconnect`. Upload route `api.py:335-352` authenticates (`screen_human`) then reads `request.form()` and each file with `read(limit+1)` (`max_upload_bytes` 50 MiB). `deploy/Caddyfile` adds `request_body` caps. `web.py` has its own upload form (`web.py:~229`).
- **Audit cap (F3 fix, PR #16).** `audit.py:126-152` `_bound`/`bound_payload` bound every payload before hashing (strings 64 KiB, lists 200, row 128 KiB); `AuditLog.append` (`audit.py:281`).
- **GUI gate (F2) and quota recheck (F7), PR #17.** `_run_tool` refuses GUI input without an open burst (`GuiBursts.covers`, `gui_bursts.py:68`); allow-path commit rechecks `_over_snapshot_quota` (`service.py:254`) and logs `tool_blocked`/`snapshot_quota_changed`.
- **Lifecycle lock (F6), F4, F5, F8, PR #18.** `AgentBox._lifecycle` (`service.py:500`) serialises pause/resume/snapshot/restore/delete per sandbox; `SandboxManager.restore` refuses `deleted`. Preview `_expand`/`_walk` use NUL-separated output. `extract_novnc` (`sandbox_desktop.py:174`) single-flight with 60 s negative cache. Login failures rate-logged (`web.py:102-114`, 5/min + `suppressed_before`); token compare on bytes.
- **Control-character filter (N5, PR #19).** `display.escape_controls` escapes Unicode categories Cc/Cf/Zl/Zp; shared by `web._shown` and `cli._safe`.
- **Disk guard and approval compaction (N2 stage 1, PR #20).** `AgentBox.disk_low` (`service.py:388-404`) uses `shutil.disk_usage(db_path.parent).free < min_free_bytes` (`AGENTBOX_MIN_FREE`, 256 MiB; 0 disables); `call_tool` (`service.py:279-285`) refuses **agent** calls with 507; `api.py:313` skips the agent `approval_forbidden` row while low; state changes log `disk_low`/`disk_ok` only on transitions. `_finish` (`service.py:406-411`) rewrites finished approval rows' `args` with `_logged_args` (size/sha256/16 KiB head) and `preview` with `bound_payload` via `ApprovalStore.finish(..., args, preview)` (`approvals.py:91-100`, `COALESCE`). Pending rows still hold raw args/preview (`approvals.py:49-59`). `decide` maps a `claim` `sqlite3.Error` to 503; `expire_stale` (`service.py:422-438`) returns on `sqlite3.Error`. `_approvals.html` shows `args.args_head` for compacted rows.
- **Prune and anchor (N2 stage 2, PR #21).** `retention.py` (new): `prune(db_path, before, archive, dry_run)` — host CLI only (`cli.py:319` `cmd_prune`, `agentbox prune --before --archive [--dry-run]`), never HTTP. Plan: audit rows with `id < MIN(id WHERE ts >= cutoff)`, approvals with status in denied/executed/failed/expired and `created_at < cutoff` (`retention.py:54-64`). Archive written outside the DB lock with `open(path, "xb")` + gzip + fsync, sha256 (`:67-84`). Then `BEGIN IMMEDIATE`: concurrent-prune check, `DROP TRIGGER audit_no_delete`, `DELETE`, recreate trigger from `NO_DELETE_SQL`, insert `audit_anchor` row (always, even approvals-only), delete approvals, `insert_record(... "audit_pruned" ...)`, `COMMIT`; on any exception rollback and unlink the archive (`:105-132`). `audit.py`: `audit_anchor` table with no-update/no-delete triggers (`:44-55`), `latest_anchor:178`, `check_chain:184`, `read_archive:208` (gzip JSON Lines, header format check), `insert_record:228` (chains from last row else latest anchor else GENESIS; `append` uses it), `verify:336` (starts at latest anchor; anchor + empty table fails), `verify_archives:351` (GENESIS → each archive must match its anchor's sha256/last row → live table). `cli.py:299` `cmd_verify --archive` runs `verify_archives` locally against `Settings().db_path`. Known limit (README): anchor lives in the same DB, so a DB writer can forge it.
- **Window owner via XRes (N4, PR #22).** `sandbox_desktop.py:42-75` `_WINDOW_OWNERS` ctypes script (libX11 + libXRes `XResQueryClientIds` mask 2 → `XResGetClientPid`); `desktop_processes` (`:77-~95`) runs `sh -c 'xdotool search --onlyvisible --name . 2>/dev/null | xargs -r /usr/bin/python3 -I -c "$0"' <script>` as the desktop user inside the container; nonzero exit → no window pids (fail-closed: more strays). `gui_state._new_processes:53` returns `(stray, kept)`; `gui_kept:95`. `gui_bursts._stop_strays:89` stores `_kept[sid] = (container_id, pids)` and logs `gui_processes_kept`; `open:73` removes kept pids from the next baseline when the container id matches.
- **Docs (PR #23).** LLM-provider data path documented as an accepted limitation; out of scope for hunting.
Unchanged since run-4 and not re-hunted: N1 (`same_origin` scheme) and N3 (container output readers) remain needs_validation.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full JSON API (`api.py:115` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py:157` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py:356`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates, `cli.py:68-111`; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default (`cli.py:124-126`), and the bare `create_app` factory (`api.py:376`) that skips the serve-time gates. Container flags (`sandbox.py:243-265`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Docker 29.9.1, runtimes `runc`/`io.containerd.runc.v2` only, cgroup v1, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1` (rebuilt from this tree). Agent-run code goes through `tools/sbx` (no network, read-only target, 256 MiB loop scratch, uid 65534, 512 MiB, 64 pids, 120 s; `agentbox.web`/`api` importable). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`; fakes for `GuiBursts`/`AgentBox` in `test_m2_unit.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (`service.py:268`, per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (`service.py:290`: audit with capped args `_logged_args:181` → `policy.decide` → quota → approval or `_snapshot:250` → `_run_tool`) on the 32-thread `tool_pool` (`api.py:103`). Pending approvals capped at 20 (`service.py:44`).
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide` (`service.py:389`): atomic claim, snapshot, run stored args. Runs on the Starlette threadpool, outside `tool_pool`, `_busy` and `_snap_locks`. Preview (`preview.py:67` `preview_command` with `_expand`/`_walk` callbacks, `sandbox.py:557-569`) and capture run before the approval exists.
- **Lifecycle** (refactor PR 1): `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` (`service.py:444-475`), called by `api.py` and `web.py` inside `guard`. Restore: log → `end_desktop` → `sandboxes.restore` → `bursts.reset_timers` → log. Delete: log → `end_desktop` → delete → `drop_captures`. Pause: log → `bursts.end` → pause. None takes `gui_lock` or `_snap_locks`.
- **GUI bursts** (`gui_bursts.py:23`, refactor PR 2): `needs_snapshot:52`, `open:65` (fail-closed baseline, bound to `container_id`), `close:100`/`_finish:113` (stray kill via `gui_state.gui_strays` from root `ps` + `_NET_WM_PID`, manifest diff → `gui_changes`), `close_idle:137` on a dedicated pool from `expire_stale` callers, `end:157`. Timestamps `_gui_input_at`/`_gui_snap_at` are written without a lock.
- **Desktop**: tickets (60 s, one-time, hashed), sessions (12 h, scoped), leases; takeover/handback (`service.py:503,523`, `bursts.close` under `gui_lock`); WS route `api.py:344` (cookie, `same_origin` with missing Origin allowed, mode, `may_connect`) → `desktop_ws.relay:18` (no auth of its own; session re-check every 30 s; x11vnc without `-noremote`/`-safer`).
- **Files**: `read_file`/`write_file`/`delete_file`/`list_dir` (`safe_path`), upload, outbox list/read; `list_dir`, `exists`, `is_dir`, `outbox_list`, `_expand` run `exec_run` with no container-side timeout and full buffering.
- **Rendering**: Jinja autoescape + `finalize=_shown` → `display.escape_controls:18` (shared with `cli._safe`); `_NoFraming` middleware (`api.py:63`) on HTTP responses.
- **Audit**: hash chain + append-only triggers, `mask_text`; `log_human` fails closed with 503 (`service.py:590`); tool results and burst records are best-effort.
## 5. Trust boundaries and strongest control
| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc on this host) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>`/`$` gate |
| Agent → approval 

# Relevant companion blocks (verbatim)

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

- Agent ID `v-ws`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-ws/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-ws <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-ws /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish.
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
