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
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per sandbox by `AgentBox._lifecycle`.
- **GUI bursts** (`gui_bursts.py`): `needs_snapshot`, `open` (fail-closed baseline, bound to `container_id`), `covers` (checks `sid in _gui_burst`), `close`/`_finish` (stray kill via `gui_state.gui_strays` from root `ps` + XRes window owners, manifest diff → `gui_changes`), `close_idle` on a dedicated pool, `end`.
- **Desktop**: tickets (60 s, one-time, hashed), sessions (12 h, scoped), leases; takeover/handback (`bursts.close` under `gui_lock`); WS route `api.py:desktop_ws` (cookie session via threadpool, `same_origin` with missing Origin allowed, mode, `may_connect`) → `desktop_ws.relay` (threadpool `vnc_command`/`log_human`, session recheck every 30 s, shielded disconnect log before `drop_conn`).
- **Files**: `read_file`/`write_file`/`delete_file`/`list_dir` (`safe_path`), upload, outbox list/read; `list_dir`, `exists`, `is_dir`, `outbox_list` run `exec_run` with no container-side timeout and full buffering (`_expand`/`_walk` now have 10 s timeout via `_timed`, `_walk` uses `head -z`, `_expand` still buffers all matching names).
- **Rendering**: Jinja autoescape + `finalize=_shown` → `display.escape_controls` (shared with `cli._safe`); `_NoFraming` middleware on HTTP responses.
- **Audit**: hash chain + append-only triggers, `mask_text`, `bound_payload`; `log_human` fails closed with 503; tool results and burst records are best-effort; `retention.prune` exports archives and installs `audit_anchor`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc on this host) |
| Agent → approval gate (exec) | `TOOL_ARG_MAX` + `policy.simple_programs` allowlist + `_relex_changes` + `has_bash_comment` + `>`/`$` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot under `gui_lock` + lease check, `covers()`, fail-closed open, `gui_changes`, XRes stray kill |
| Agent → human authority | token kinds, `human_only`, scope checks, `samefile` source_dir overlap check |
| Agent → control-plane availability | `_BodyLimit` auth check, `TOOL_ARG_MAX`, `PREVIEW_CALLS_MAX`, `_PREVIEW_TIMEOUT`, `tool_pool`, tool concurrency, `_Head`, snapshot quota, pending cap, `disk_low` |
| Container output → control plane | `_parse_ps`, `_parse_manifest`, `_parse_outbox`, preview parsing; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin`, XFO/frame-ancestors |
| Desktop-link session → rest of UI | `scope`, `desktop_human` |
| Network → control plane | `bind_problem`; `_BodyLimit` credential gate; proxy trust `*`; unauthenticated login/novnc routes |
