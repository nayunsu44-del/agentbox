You are `critic-1`, the post-wave coverage critic immediately after the hunter wave, in run-6 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at `530b29e`. Your only writable directory is `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/critic-1/scratch/`, and you need not write anything.

# architecture.md (verbatim)

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

# Full coverage ledger

Read it at `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/coverage-ledger.json` (11 units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

# Current candidate fingerprints and states

```json
[
 {
  "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
  "state": "ledger unit Approval-preview%20truthfulness%20after%20the%20F4%20change%3A%20preview_command%20%28rm%20operand%20expansion%20via%20_expand%2C%20recursive%20_walk%2C%20curl%20upload%20detection%2C%20_split_segments%20and%20_WRAPPERS%20handling%29%20versus%20what%20the%20approved%20shell%20command%20really%20does::Human%20approval%20binding%3A%20the%20card%20the%20human%20decides%20on%20is%20computed%20by%20a%20separate%20shell-parse%20and%20container%20glob%2Ffind%2C%20not%20by%20the%20executing%20shell.%20The%20run-4%20F4%20fix%20replaced%20newline%20output%20with%20NUL-separated%20records%20and%20head%20-z%2C%20and%20no%20run-5%20unit%20re-checks%20the%20card%20against%20real%20behaviour.%20Cases%20to%20test%3A%20brace%20and%20tilde%20expansion%2C%20dotfile%20globs%2C%20rm%20-f%2F--no-preserve-root%2C%20operands%20after%20%27--%27%2C%20symlinks%2C%20names%20with%20newlines%20or%20leading%20%27-%27%2C%20commands%20the%20preview%20marks%20%27no%20effect%20computed%27%2C%20and%20the%20200-item%20display%20truncation%20hiding%20later%20deletions.::agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fservice.py%23_preview%2Fdecide%20%2B%20agentbox%2Ftemplates%2F_approvals.html::Action-confirmation%20and%20approval%20binding%20%28preview%20does%20not%20match%20execution%29: candidate",
  "unit": "Approval-preview%20truthfulness%20after%20the%20F4%20change%3A%20preview_command%20%28rm%20operand%20expansion%20via%20_expand%2C%20recursive%20_walk%2C%20curl%20upload%20detection%2C%20_split_segments%20and%20_WRAPPERS%20handling%29%20versus%20what%20the%20approved%20shell%20command%20really%20does::Human%20approval%20binding%3A%20the%20card%20the%20human%20decides%20on%20is%20computed%20by%20a%20separate%20shell-parse%20and%20container%20glob%2Ffind%2C%20not%20by%20the%20executing%20shell.%20The%20run-4%20F4%20fix%20replaced%20newline%20output%20with%20NUL-separated%20records%20and%20head%20-z%2C%20and%20no%20run-5%20unit%20re-checks%20the%20card%20against%20real%20behaviour.%20Cases%20to%20test%3A%20brace%20and%20tilde%20expansion%2C%20dotfile%20globs%2C%20rm%20-f%2F--no-preserve-root%2C%20operands%20after%20%27--%27%2C%20symlinks%2C%20names%20with%20newlines%20or%20leading%20%27-%27%2C%20commands%20the%20preview%20marks%20%27no%20effect%20computed%27%2C%20and%20the%20200-item%20display%20truncation%20hiding%20later%20deletions.::agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fservice.py%23_preview%2Fdecide%20%2B%20agentbox%2Ftemplates%2F_approvals.html::Action-confirmation%20and%20approval%20binding%20%28preview%20does%20not%20match%20execution%29"
 },
 {
  "fingerprint": "agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory",
  "state": "ledger unit AuditLog._lock%20as%20a%20global%20contention%20point%20reachable%20by%20agent-grown%20table%20size%20and%20by%20unauthenticated%20traffic%3A%20GET%20%2Fui%2Faudit%20%28polled%20every%203%20s%20by%20templates%2Fsandbox.html%29%2C%20GET%20%2Fui%2Fverify%2C%20GET%20%2Faudit%2Fverify%2C%20AuditLog.recent%20%28unindexed%20COUNT%28%2A%29%20WHERE%20sandbox_id%29%2C%20AuditLog.verify%20%28fetchall%20of%20the%20whole%20table%2C%20audit.py%3A336-350%29%2C%20AuditLog.list%2C%20versus%20every%20AuditLog.append%2Finsert_record%20from%20agent%20tool%20calls%20and%20every%20fail-closed%20log_human%3B%20plus%20the%20unauthenticated%20POST%20%2Flogin%20failure%20throttle%20%28web.py%3A93-114%29%20and%20extract_novnc%20single-flight%20%28sandbox_desktop.py%3A174%29::Agent%20and%20unauthenticated%20clients%20to%20human%20availability%20and%20audit%20evidence%3A%20AuditLog.recent%2Fverify%20scan%20the%20agent-grown%20table%20under%20the%20same%20_lock%20append%20needs%20%28fail-closed%20log_human%20returns%20503%20while%20it%20is%20held%29%2C%20verify%20loads%20the%20whole%20table%2C%20the%20F8%20login%20throttle%20shares%20one%20global%20window%2C%20and%20F5%20extract_novnc%20holds%20a%20global%20lock%20across%20docker%20create.%20Invariant%3A%20no%20agent%20or%20unauthenticated%20sequence%20holds%20these%20locks%20long%20enough%20to%20refuse%20human%20actions%2C%20exhaust%20memory%2C%20or%20hide%20credential-guessing%20evidence.::agentbox%2Faudit.py%23recent%2Fverify%2Flist%2Fappend%2Finsert_record%2F_lock%20%2B%20agentbox%2Fweb.py%23note_login_failure%2Faudit%20and%20verify%20routes%20%2B%20agentbox%2Fapi.py%23%2Faudit%2Fverify%20%2B%20agentbox%2Fsandbox_desktop.py%23extract_novnc%2F_NOVNC_LOCK%20%2B%20agentbox%2Ftemplates%2Fsandbox.html%20%283%20s%20poll%29::Resource%20exhaustion%3A%20lock%20contention%20and%20pre-authentication%20work%20imbalance: candidate",
  "unit": "AuditLog._lock%20as%20a%20global%20contention%20point%20reachable%20by%20agent-grown%20table%20size%20and%20by%20unauthenticated%20traffic%3A%20GET%20%2Fui%2Faudit%20%28polled%20every%203%20s%20by%20templates%2Fsandbox.html%29%2C%20GET%20%2Fui%2Fverify%2C%20GET%20%2Faudit%2Fverify%2C%20AuditLog.recent%20%28unindexed%20COUNT%28%2A%29%20WHERE%20sandbox_id%29%2C%20AuditLog.verify%20%28fetchall%20of%20the%20whole%20table%2C%20audit.py%3A336-350%29%2C%20AuditLog.list%2C%20versus%20every%20AuditLog.append%2Finsert_record%20from%20agent%20tool%20calls%20and%20every%20fail-closed%20log_human%3B%20plus%20the%20unauthenticated%20POST%20%2Flogin%20failure%20throttle%20%28web.py%3A93-114%29%20and%20extract_novnc%20single-flight%20%28sandbox_desktop.py%3A174%29::Agent%20and%20unauthenticated%20clients%20to%20human%20availability%20and%20audit%20evidence%3A%20AuditLog.recent%2Fverify%20scan%20the%20agent-grown%20table%20under%20the%20same%20_lock%20append%20needs%20%28fail-closed%20log_human%20returns%20503%20while%20it%20is%20held%29%2C%20verify%20loads%20the%20whole%20table%2C%20the%20F8%20login%20throttle%20shares%20one%20global%20window%2C%20and%20F5%20extract_novnc%20holds%20a%20global%20lock%20across%20docker%20create.%20Invariant%3A%20no%20agent%20or%20unauthenticated%20sequence%20holds%20these%20locks%20long%20enough%20to%20refuse%20human%20actions%2C%20exhaust%20memory%2C%20or%20hide%20credential-guessing%20evidence.::agentbox%2Faudit.py%23recent%2Fverify%2Flist%2Fappend%2Finsert_record%2F_lock%20%2B%20agentbox%2Fweb.py%23note_login_failure%2Faudit%20and%20verify%20routes%20%2B%20agentbox%2Fapi.py%23%2Faudit%2Fverify%20%2B%20agentbox%2Fsandbox_desktop.py%23extract_novnc%2F_NOVNC_LOCK%20%2B%20agentbox%2Ftemplates%2Fsandbox.html%20%283%20s%20poll%29::Resource%20exhaustion%3A%20lock%20contention%20and%20pre-authentication%20work%20imbalance"
 },
 {
  "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
  "state": "ledger unit Browser-origin%20checks%20on%20cookie-authenticated%20routes%3A%20api.py%20same_origin%20%28api.py%3A221-223%29%20used%20by%20screen_principal%20%28api.py%3A235%2C%20every%20%2Fui%20and%20screen%20route%29%2C%20the%20login%2Fticket%20handlers%20%28web.py%3A159%2C169%29%20and%20the%20desktop%20WebSocket%20upgrade%20%28api.py%3A442%29%3B%20a%20missing%20Origin%20header%20is%20accepted::Cross-site%20or%20downgraded-scheme%20browser%20request%20to%20human%20authority%3A%20same_origin%20compares%20only%20urlsplit%28origin%29.netloc%20to%20the%20Host%20header%2C%20with%20no%20scheme%20check%2C%20and%20treats%20an%20absent%20Origin%20as%20same-origin.%20Behind%20a%20TLS%20proxy%20with%20forwarded_allow_ips%3D%27%2A%27%20a%20plain-HTTP%20origin%20on%20the%20same%20host%20passes.%20This%20is%20run-4%20N1%20%28needs_validation%2C%20source%20unchanged%29%20and%20no%20run-5%20unit%20owns%20it.%20The%20WS%20and%20body-cap%20units%20excluded%20CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use%20by%20pointing%20to%20an%20%27existing%20h-session%20unit%27%20that%20is%20not%20in%20this%20ledger.::agentbox%2Fapi.py%23same_origin%2Fscreen_principal%2Fdesktop_ws%20%2B%20agentbox%2Fweb.py%20login%20and%20ticket%20routes%20%2B%20agentbox%2Fdesktop.py%20cookie%20attributes%20%28SameSite%2C%20Secure%2C%20scope%29%20%2B%20deploy%2FCaddyfile%20Host%2FOrigin%20forwarding::Cross-site%20WebSocket%20and%20cross-origin%20request%20forgery%20against%20cookie%20sessions%20%28scheme%20and%20missing-Origin%20gaps%29: candidate",
  "unit": "Browser-origin%20checks%20on%20cookie-authenticated%20routes%3A%20api.py%20same_origin%20%28api.py%3A221-223%29%20used%20by%20screen_principal%20%28api.py%3A235%2C%20every%20%2Fui%20and%20screen%20route%29%2C%20the%20login%2Fticket%20handlers%20%28web.py%3A159%2C169%29%20and%20the%20desktop%20WebSocket%20upgrade%20%28api.py%3A442%29%3B%20a%20missing%20Origin%20header%20is%20accepted::Cross-site%20or%20downgraded-scheme%20browser%20request%20to%20human%20authority%3A%20same_origin%20compares%20only%20urlsplit%28origin%29.netloc%20to%20the%20Host%20header%2C%20with%20no%20scheme%20check%2C%20and%20treats%20an%20absent%20Origin%20as%20same-origin.%20Behind%20a%20TLS%20proxy%20with%20forwarded_allow_ips%3D%27%2A%27%20a%20plain-HTTP%20origin%20on%20the%20same%20host%20passes.%20This%20is%20run-4%20N1%20%28needs_validation%2C%20source%20unchanged%29%20and%20no%20run-5%20unit%20owns%20it.%20The%20WS%20and%20body-cap%20units%20excluded%20CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use%20by%20pointing%20to%20an%20%27existing%20h-session%20unit%27%20that%20is%20not%20in%20this%20ledger.::agentbox%2Fapi.py%23same_origin%2Fscreen_principal%2Fdesktop_ws%20%2B%20agentbox%2Fweb.py%20login%20and%20ticket%20routes%20%2B%20agentbox%2Fdesktop.py%20cookie%20attributes%20%28SameSite%2C%20Secure%2C%20scope%29%20%2B%20deploy%2FCaddyfile%20Host%2FOrigin%20forwarding::Cross-site%20WebSocket%20and%20cross-origin%20request%20forgery%20against%20cookie%20sessions%20%28scheme%20and%20missing-Origin%20gaps%29"
 },
 {
  "fingerprint": "agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore",
  "state": "ledger unit Container%20identity%20binding%20of%20the%20F2%20GUI-input%20gate%3A%20GuiBursts.covers%20%28gui_bursts.py%3A68-71%29%20checks%20only%20%27sid%20in%20_gui_burst%27%2C%20called%20from%20_run_tool%20under%20gui_lock%20%28service.py%3A145%29%2C%20versus%20burst%5B%27container_id%27%5D%20set%20in%20open%28%29%20and%20the%20restore%2Fdelete%20path::Agent%20GUI%20input%20to%20the%20burst-based%20change%20recorder%20after%20restore%3A%20a%20burst%20opened%20on%20the%20pre-restore%20container%20can%20satisfy%20covers%28%29%20for%20an%20input%20that%20runs%20on%20the%20restored%20container%2C%20so%20no%20stray%20kill%20or%20gui_changes%20applies%20and%20the%20started%20processes%20join%20the%20next%20baseline.%20h-lifecycle%20recorded%20this%20as%20hardening%2C%20and%20its%20only%20candidate%20was%20rejected%20on%20a%20different%20claim.%20The%20PR%20%2317%20gate%20has%20no%20unit%20that%20reproduces%20or%20refutes%20this%20schedule.::agentbox%2Fgui_bursts.py%23covers%2Fopen%2Fend%2Freset_timers%20%2B%20agentbox%2Fservice.py%23_run_tool%2F_snapshot%2Frestore_sandbox::Race%20and%20check-then-act%20on%20security-control%20state%20%28container%20identity%20across%20restore%29: candidate",
  "unit": "Container%20identity%20binding%20of%20the%20F2%20GUI-input%20gate%3A%20GuiBursts.covers%20%28gui_bursts.py%3A68-71%29%20checks%20only%20%27sid%20in%20_gui_burst%27%2C%20called%20from%20_run_tool%20under%20gui_lock%20%28service.py%3A145%29%2C%20versus%20burst%5B%27container_id%27%5D%20set%20in%20open%28%29%20and%20the%20restore%2Fdelete%20path::Agent%20GUI%20input%20to%20the%20burst-based%20change%20recorder%20after%20restore%3A%20a%20burst%20opened%20on%20the%20pre-restore%20container%20can%20satisfy%20covers%28%29%20for%20an%20input%20that%20runs%20on%20the%20restored%20container%2C%20so%20no%20stray%20kill%20or%20gui_changes%20applies%20and%20the%20started%20processes%20join%20the%20next%20baseline.%20h-lifecycle%20recorded%20this%20as%20hardening%2C%20and%20its%20only%20candidate%20was%20rejected%20on%20a%20different%20claim.%20The%20PR%20%2317%20gate%20has%20no%20unit%20that%20reproduces%20or%20refutes%20this%20schedule.::agentbox%2Fgui_bursts.py%23covers%2Fopen%2Fend%2Freset_timers%20%2B%20agentbox%2Fservice.py%23_run_tool%2F_snapshot%2Frestore_sandbox::Race%20and%20check-then-act%20on%20security-control%20state%20%28container%20identity%20across%20restore%29"
 },
 {
  "fingerprint": "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap",
  "state": "ledger unit Container%20output%20readers%20that%20fully%20buffer%20attacker-controlled%20bytes%3A%20sandbox.py%20exec_run%20without%20a%20read%20cap%20or%20container-side%20timeout%20%28list_dir%20ls%20-la%20%3A442%2C%20exists%20%3A475%2C%20delete%20%3A497%2C%20outbox_list%20find%20-printf%20%3A548%2C%20is_dir%20%3A537%2C%20plus%20_expand%20glob%20%3A578%20and%20_walk%20find%20-print0%20%3A584%20which%20gained%20_PREVIEW_TIMEOUT%20in%20PR%20%2324%29%20versus%20the%20capped%20_Head%20exec%20path%20%28%3A85%2C%3A427%29::Agent-owned%20container%20filesystem%20output%20to%20control-plane%20memory%20and%20tool_pool%2Frequest%20threads.%20An%20agent%20can%20create%20millions%20of%20names%2C%20deep%20trees%20or%20huge%20glob%20matches%2C%20so%20a%20human-triggered%20or%20preview-triggered%20listing%20buffers%20an%20unbounded%20demux%20result%20in%20the%20single%20control-plane%20process.%20Run-4%20N3%20%28needs_validation%2C%20not%20re-hunted%29.%20The%20h-xres%20and%20h-policy-cpu%20units%20excluded%20Unbounded%20buffering%20and%20cardinality%20citing%20N3%2C%20so%20no%20unit%20owns%20it%2C%20and%20PR%20%2318%20changed%20_expand%2F_walk%20%28NUL-separated%20output%2C%20head%20-z%29%20without%20a%20reader-cap%20review.::agentbox%2Fsandbox.py%23list_dir%2Fexists%2Fdelete_file%2Foutbox_list%2Fis_dir%2F_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fsandbox_common.py%23_timed%20%2B%20agentbox%2Fsandbox_desktop.py%23_x%2Fdesktop_processes%20%2B%20agentbox%2Fpreview.py::Unbounded%20buffering%20and%20cardinality%20of%20container-controlled%20output: candidate",
  "unit": "Container%20output%20readers%20that%20fully%20buffer%20attacker-controlled%20bytes%3A%20sandbox.py%20exec_run%20without%20a%20read%20cap%20or%20container-side%20timeout%20%28list_dir%20ls%20-la%20%3A442%2C%20exists%20%3A475%2C%20delete%20%3A497%2C%20outbox_list%20find%20-printf%20%3A548%2C%20is_dir%20%3A537%2C%20plus%20_expand%20glob%20%3A578%20and%20_walk%20find%20-print0%20%3A584%20which%20gained%20_PREVIEW_TIMEOUT%20in%20PR%20%2324%29%20versus%20the%20capped%20_Head%20exec%20path%20%28%3A85%2C%3A427%29::Agent-owned%20container%20filesystem%20output%20to%20control-plane%20memory%20and%20tool_pool%2Frequest%20threads.%20An%20agent%20can%20create%20millions%20of%20names%2C%20deep%20trees%20or%20huge%20glob%20matches%2C%20so%20a%20human-triggered%20or%20preview-triggered%20listing%20buffers%20an%20unbounded%20demux%20result%20in%20the%20single%20control-plane%20process.%20Run-4%20N3%20%28needs_validation%2C%20not%20re-hunted%29.%20The%20h-xres%20and%20h-policy-cpu%20units%20excluded%20Unbounded%20buffering%20and%20cardinality%20citing%20N3%2C%20so%20no%20unit%20owns%20it%2C%20and%20PR%20%2318%20changed%20_expand%2F_walk%20%28NUL-separated%20output%2C%20head%20-z%29%20without%20a%20reader-cap%20review.::agentbox%2Fsandbox.py%23list_dir%2Fexists%2Fdelete_file%2Foutbox_list%2Fis_dir%2F_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fsandbox_common.py%23_timed%20%2B%20agentbox%2Fsandbox_desktop.py%23_x%2Fdesktop_processes%20%2B%20agentbox%2Fpreview.py::Unbounded%20buffering%20and%20cardinality%20of%20container-controlled%20output"
 },
 {
  "fingerprint": "agentbox/service.py:disk_low-unmonitored-docker-data-root",
  "state": "ledger unit Docker%20data-root%20growth%20that%20AgentBox.disk_low%20does%20not%20measure%3A%20container%20writable%20layers%20%28AGENTBOX_DISK%20default%20empty%20so%20no%20storage_opt%29%2C%20docker%20commit%20snapshot%20images%20%28snapshot_quota%2050%20per%20sandbox%2C%20unlimited%20sandboxes%29%2C%20and%20the%20exec%2Fwrite_file%20calls%20that%20an%20admitted%20call%20can%20run%20for%20up%20to%20exec_timeout::Agent%20to%20host%20disk%20outside%20the%20guard%3A%20disk_low%20checks%20shutil.disk_usage%28db_path.parent%29%20only%20%28service.py%3A395%29%2C%20while%20the%20growth%20lands%20in%20the%20Docker%20root.%20When%20DB%20and%20Docker%20root%20are%20on%20different%20filesystems%2C%20or%20one%20admitted%20exec%20fills%20the%20layer%2C%20the%20507%20guard%20never%20trips.%20h-approvals%20recorded%20this%20only%20as%20hardening%20and%20did%20not%20test%20per-sandbox%20or%20aggregate%20snapshot%20disk.::agentbox%2Fservice.py%23disk_low%2Fcall_tool%20%2B%20agentbox%2Fsandbox.py%23_run_container%2Fsnapshot%2Fwrite_file%20%2B%20agentbox%2Fconfig.py%23disk_limit%2Fmin_free_bytes%2Fsnapshot_quota%20%2B%20deploy%2Fdocker-compose.yml%20volume%20layout::Quota-accounting%20scope%20and%20reset%20gaps%20%28disk%20accounting%20measured%20on%20the%20wrong%20filesystem%29: candidate",
  "unit": "Docker%20data-root%20growth%20that%20AgentBox.disk_low%20does%20not%20measure%3A%20container%20writable%20layers%20%28AGENTBOX_DISK%20default%20empty%20so%20no%20storage_opt%29%2C%20docker%20commit%20snapshot%20images%20%28snapshot_quota%2050%20per%20sandbox%2C%20unlimited%20sandboxes%29%2C%20and%20the%20exec%2Fwrite_file%20calls%20that%20an%20admitted%20call%20can%20run%20for%20up%20to%20exec_timeout::Agent%20to%20host%20disk%20outside%20the%20guard%3A%20disk_low%20checks%20shutil.disk_usage%28db_path.parent%29%20only%20%28service.py%3A395%29%2C%20while%20the%20growth%20lands%20in%20the%20Docker%20root.%20When%20DB%20and%20Docker%20root%20are%20on%20different%20filesystems%2C%20or%20one%20admitted%20exec%20fills%20the%20layer%2C%20the%20507%20guard%20never%20trips.%20h-approvals%20recorded%20this%20only%20as%20hardening%20and%20did%20not%20test%20per-sandbox%20or%20aggregate%20snapshot%20disk.::agentbox%2Fservice.py%23disk_low%2Fcall_tool%20%2B%20agentbox%2Fsandbox.py%23_run_container%2Fsnapshot%2Fwrite_file%20%2B%20agentbox%2Fconfig.py%23disk_limit%2Fmin_free_bytes%2Fsnapshot_quota%20%2B%20deploy%2Fdocker-compose.yml%20volume%20layout::Quota-accounting%20scope%20and%20reset%20gaps%20%28disk%20accounting%20measured%20on%20the%20wrong%20filesystem%29"
 }
]
```

# Hunter-reported `uncovered` boundaries

```json
[]
```

# Prior-ledger gap summary

- run-6 is a focused follow-up audit at 530b29e. Its ledger holds all seven units deferred in run-5
  (the top 4: same_origin scheme, container output reader caps, approval preview truthfulness, and
  AuditLog._lock contention; plus the remaining 3: Docker data-root disk accounting, GUI burst covers()
  container_id binding, and control-character filter sink completeness) plus four units covering every
  file changed in PRs #24 and #25 (_BodyLimit pre-read credential gate and deploy caps, DesktopControl
  lock split and WS threadpool/retention cleanup, GUI burst takeover lease gate in _snapshot/decide,
  and TOOL_ARG_MAX/preview caps/_relex_changes).
- Every other unit from run-4 and run-5 was covered at 9805d91 or 346df29 and its code is unchanged;
  proposing them again needs a concrete changed-code or cross-unit interaction reason.
- The LLM-provider data path (tool results sent to the model API) is a documented owner-accepted
  limitation and is out of scope for this run.

# Your task (verbatim from the skill)

```text
Immediately after each hunter wave, spend the reserved invocation on one fresh `research` post-wave coverage critic. It receives `architecture.md`, the full coverage ledger including each assignment block map, current candidate fingerprints and states, and the prior-ledger gap summary. It reads source but does not write or run targets. Require exactly this JSON:

```json
{
  "missing_units": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{"block": "FILE.md#section", "reason": "..."}],
      "reason": "source-backed coverage gap"
    }
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}
```

The critic checks for unmapped entry points, unchecked parallel paths, missing lifecycle modes, selected companion classes without a unit, unjustified exclusions, units closed without paths/checks, and prior `needs_validation` or changed-source gaps that no unit addresses. It proposes coverage, not findings. `stop` is the critic's own assessment: `true` only when it accepts no `missing_units` and no `reassign_ids`; the parent's loop condition below, not `stop` alone, decides whether another wave runs. For each fingerprint in `resolved_prior_leads`, the parent marks the linked unit or prior-lead entry resolved and records the critic's source-backed reason.

The parent rejects proposed units outside the review scope or source/local boundary, derives canonical IDs for accepted units, and deduplicates them against current units. A prior same-source completed unit may supply evidence; prior `deferred`, `blocked`, `out_of_scope`, or changed-source units become current work and never suppress an accepted unit. Fail rather than merge a canonical ID collision. For each legitimate `reassign_id` with live `blocked`, `covered`, or `candidate` evidence, append that exact terminal record to the unit's `attempts` with the critic's source-backed `reassignment_reason`. Preserve its owner, checks, artifacts, fingerprints, and unresolved facts in that archive. Increment the live `wave`; the next hunter must be a fresh owner and receives an `in_progress` unit with empty live evidence. The hunter's terminal result writes only its new evidence into the live fields. Never copy an archived owner's checks or artifacts into the new live attempt. Sort IDs and validate the ledger before another assignment. In `standard` and `deep`, when the post-wave critic reports no accepted `missing_units` or legitimate `reassign_ids` and no `planned` units remain, spend the separately reserved invocation on a distinct final-clean critic. Complete coverage only when that critic also returns no accepted work. If it finds work, queue it and repeat the wave, post-wave critic, and final-clean process. If time or resources force an early stop, mark every untouched unit `deferred`, preserve the critic's reason, and disclose the gap in the report. Never use a silent wave or agent cap as evidence of complete coverage.
```

Budget note: Subagent budget: 6 of 30 calls spent on wave-1 hunters; 14 calls reserved for Phase 3 (6 candidates), Phase 5 (6 records), critic-1 and critic-2.

Return exactly one JSON object and nothing else (no prose, no code fence):
```json
{
  "missing_units": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{"block": "FILE.md#section", "reason": "..."}],
      "reason": "source-backed coverage gap"
    }
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}
```
