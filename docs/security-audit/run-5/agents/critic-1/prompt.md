You are `critic-1`, the post-wave coverage critic immediately after the hunter wave, in run-5 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at `346df29`. Your only writable directory is `/home/user/agentbox/docs/security-audit/run-5/agents/critic-1/scratch/`, and you need not write anything.

# architecture.md (verbatim)

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
| Agent → approval gate (GUI) | none by design; burst snapshot, fail-closed open, `gui_changes`, stray kill (N-1 partial) |
| Agent → human authority | token kinds, `human_only`, scope checks, `samefile` source_dir overlap check |
| Agent → control-plane availability | `tool_pool`, tool concurrency, `_Head`, snapshot quota, pending cap, `_timed` X/manifest execs |
| Container output → control plane | `_parse_ps`, `_parse_manifest`, `_parse_outbox`, preview parsing; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin`, XFO/frame-ancestors |
| Desktop-link session → rest of UI | `scope`, `desktop_human` |
| Network → control plane | `bind_problem`; proxy trust `*`; unauthenticated login/novnc routes |

## 6. Starting paths

`agentbox/service.py`, `gui_bursts.py`, `gui_state.py`, `sandbox.py`, `sandbox_desktop.py`, `sandbox_common.py`, `preview.py`, `api.py`, `desktop_ws.py`, `web.py`, `display.py`, `desktop.py`, `policy.py`, `audit.py`, `approvals.py`, `cli.py`, `config.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `templates/`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

Prior ledgers: run-1 (`7fc501f`) and run-3 (`0e4b958`/`8e4db9e`, incomplete, 29 units); run-2 validated run-1 live. Every run-3 confirmed record (11) was fixed and the refactor moved the code, so all are `prior_confirmed_changed_source` revalidation units, not hunter exclusions. Five run-3 `needs_validation` records (v01 same_origin scheme, v09 burst open, v10 gui_lock, v14 framing, v15 `gui_strays` window ownership) are current work. Three critic-3 units deferred in run-3 (GUI-burst state races, disk/SQLite pressure, pre-auth work) are current work. Two rejected claims (runc alias, backgrounded-children pid exhaustion) suppress only those exact claims. No same-source confirmed exclusions. Recon-flagged seams: lifecycle methods without `gui_lock`/`_snap_locks`, `decide` outside the snapshot lock, synchronous burst closes on human threads, unbounded/untimed preview and listing execs, error/preview strings that bypass the audit arg cap, unauthenticated audit growth, x11vnc remote-control plus `from_exec` stray exemption, root `/tmp` operations in the desktop start script.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent work consumes shared pools, memory, SQLite and host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: htmx UI and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 helper inspected and killed by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader, lifecycle consolidation.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release or signing path; CI runs tests with read-only contents), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker or RPC beyond HTTP/WS/MCP stdio covered elsewhere).

# Full coverage ledger

Read it at /home/user/agentbox/docs/security-audit/run-5/coverage-ledger.json (7 units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

# Current candidate fingerprints and states

```json
[
 {
  "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
  "state": "final record: needs_validation",
  "title": "Unauthenticated JSON bodies are still decoded before principal(); one 8 MiB request costs about 200 MB of transient memory and 0.4-0.7 s of event-loop time before the 401"
 },
 {
  "fingerprint": "agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt",
  "state": "final record: confirmed",
  "title": "Interrupted prune deletes the only archive of audit rows it has already committed as pruned"
 },
 {
  "fingerprint": "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease",
  "state": "ledger unit A%20GUI%20burst%20opened%20while%20a%20human%20takeover%20lease%20is%20held%3A%20%28a%29%20POST%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2Fapprove%20for%20an%20approved%20click%2Ftype%2Fkey%2C%20which%20is%20reachable%20once%20the%20snapshot%20quota%20turns%20GUI%20input%20into%20REQUIRE_APPROVAL%20or%20a%20policy%20gates%20GUI%20tools%2C%20and%20%28b%29%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%7D%20whose%20pre-input%20docker%20commit%20races%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover.%20The%20burst%20is%20then%20closed%20by%20close_idle%2C%20which%20any%20agent%20tool%20call%20triggers%2C%20or%20by%20the%20next%20burst%20after%20handback.::Agent%20GUI-burst%20enforcement%20%28stray%20kill%2C%20gui_kept%2Fgui_changes%20attribution%29%20versus%20the%20human%20desktop%20session%20during%20a%20takeover%3A%20takeover%20closes%20the%20burst%20under%20gui_lock%20before%20installing%20the%20lease%20%28service.py%3A571-589%2C%20close%20at%20582%29%2C%20but%20_snapshot%20%28service.py%3A261-277%29%20closes%20and%20opens%20a%20burst%20without%20gui_lock%20or%20a%20lease%20check%2C%20reached%20from%20decide%20%28service.py%3A440%29%20and%20from%20call_tool%20after%20a%20needs_snapshot%20lease%20check%20%28gui_bursts.py%3A55%29%20that%20precedes%20a%20multi-second%20commit%3B%20an%20opened%20burst%20may%20survive%20the%20lease%20so%20close_idle%20%28gui_bursts.py%3A154%29%20or%20the%20next%20burst%20kills%20processes%20the%20human%20started%20or%20charges%20human%20edits%20to%20the%20agent.::agentbox%2Fservice.py%23decide%2F_snapshot%2Fcall_tool%2Ftakeover%2F_handback_locked%20%2B%20agentbox%2Fgui_bursts.py%23needs_snapshot%2Fopen%2Fclose_idle%2F_stop_strays%20%2B%20agentbox%2Fgui_state.py%23gui_strays::Race%20and%20check-then-act%20on%20security-control%20state%3A%20GUI%20burst%20opened%20by%20decide%2F_snapshot%20or%20call_tool%20while%20a%20human%20takeover%20lease%20is%20held: candidate",
  "unit": "A%20GUI%20burst%20opened%20while%20a%20human%20takeover%20lease%20is%20held%3A%20%28a%29%20POST%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2Fapprove%20for%20an%20approved%20click%2Ftype%2Fkey%2C%20which%20is%20reachable%20once%20the%20snapshot%20quota%20turns%20GUI%20input%20into%20REQUIRE_APPROVAL%20or%20a%20policy%20gates%20GUI%20tools%2C%20and%20%28b%29%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%7D%20whose%20pre-input%20docker%20commit%20races%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover.%20The%20burst%20is%20then%20closed%20by%20close_idle%2C%20which%20any%20agent%20tool%20call%20triggers%2C%20or%20by%20the%20next%20burst%20after%20handback.::Agent%20GUI-burst%20enforcement%20%28stray%20kill%2C%20gui_kept%2Fgui_changes%20attribution%29%20versus%20the%20human%20desktop%20session%20during%20a%20takeover%3A%20takeover%20closes%20the%20burst%20under%20gui_lock%20before%20installing%20the%20lease%20%28service.py%3A571-589%2C%20close%20at%20582%29%2C%20but%20_snapshot%20%28service.py%3A261-277%29%20closes%20and%20opens%20a%20burst%20without%20gui_lock%20or%20a%20lease%20check%2C%20reached%20from%20decide%20%28service.py%3A440%29%20and%20from%20call_tool%20after%20a%20needs_snapshot%20lease%20check%20%28gui_bursts.py%3A55%29%20that%20precedes%20a%20multi-second%20commit%3B%20an%20opened%20burst%20may%20survive%20the%20lease%20so%20close_idle%20%28gui_bursts.py%3A154%29%20or%20the%20next%20burst%20kills%20processes%20the%20human%20started%20or%20charges%20human%20edits%20to%20the%20agent.::agentbox%2Fservice.py%23decide%2F_snapshot%2Fcall_tool%2Ftakeover%2F_handback_locked%20%2B%20agentbox%2Fgui_bursts.py%23needs_snapshot%2Fopen%2Fclose_idle%2F_stop_strays%20%2B%20agentbox%2Fgui_state.py%23gui_strays::Race%20and%20check-then-act%20on%20security-control%20state%3A%20GUI%20burst%20opened%20by%20decide%2F_snapshot%20or%20call_tool%20while%20a%20human%20takeover%20lease%20is%20held"
 },
 {
  "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
  "state": "ledger unit Every%20HTTP%20request%20before%20routing%20and%20authentication%3A%20_BodyLimit%20ASGI%20middleware%20%28Content-Length%20and%20streamed%20bodies%2C%20upload%20path%20selection%29%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%20multipart%20form%20%2B%20the%20%2Fui%20upload%20form%20%2B%20deploy%2FCaddyfile%20request_body::Pre-authentication%20and%20per-request%20body%20caps%20%28F1%20fix%2C%20PR%20%2316%29%3A%20JSON%2Fform%20bodies%20capped%20at%20AGENTBOX_MAX_BODY%2C%20uploads%20at%20AGENTBOX_MAX_UPLOAD_BODY%20selected%20by%20method%20and%20path%20regex%2C%20multipart%20parsed%20only%20after%20screen_human.%20Invariant%3A%20an%20unauthenticated%20or%20agent%20client%20cannot%20make%20the%20server%20buffer%2C%20parse%20or%20spool%20more%20than%20the%20cap%20%28or%20hang%20a%20worker%29%20before%20auth%2C%20through%20any%20HTTP%20framing%20%28chunked%2C%20missing%20or%20duplicate%20Content-Length%2C%20path%20variants%2C%20HEAD%2Fother%20methods%2C%20root_path%29.::agentbox%2Fapi.py%23_BodyLimit%2F_UPLOAD_PATH%2Fput_files%2Fbuild%20%2B%20agentbox%2Fweb.py%23upload%20form%20%2B%20agentbox%2Fconfig.py%23max_body_bytes%2Fmax_upload_body_bytes%20%2B%20deploy%2FCaddyfile::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance: candidate",
  "unit": "Every%20HTTP%20request%20before%20routing%20and%20authentication%3A%20_BodyLimit%20ASGI%20middleware%20%28Content-Length%20and%20streamed%20bodies%2C%20upload%20path%20selection%29%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%20multipart%20form%20%2B%20the%20%2Fui%20upload%20form%20%2B%20deploy%2FCaddyfile%20request_body::Pre-authentication%20and%20per-request%20body%20caps%20%28F1%20fix%2C%20PR%20%2316%29%3A%20JSON%2Fform%20bodies%20capped%20at%20AGENTBOX_MAX_BODY%2C%20uploads%20at%20AGENTBOX_MAX_UPLOAD_BODY%20selected%20by%20method%20and%20path%20regex%2C%20multipart%20parsed%20only%20after%20screen_human.%20Invariant%3A%20an%20unauthenticated%20or%20agent%20client%20cannot%20make%20the%20server%20buffer%2C%20parse%20or%20spool%20more%20than%20the%20cap%20%28or%20hang%20a%20worker%29%20before%20auth%2C%20through%20any%20HTTP%20framing%20%28chunked%2C%20missing%20or%20duplicate%20Content-Length%2C%20path%20variants%2C%20HEAD%2Fother%20methods%2C%20root_path%29.::agentbox%2Fapi.py%23_BodyLimit%2F_UPLOAD_PATH%2Fput_files%2Fbuild%20%2B%20agentbox%2Fweb.py%23upload%20form%20%2B%20agentbox%2Fconfig.py%23max_body_bytes%2Fmax_upload_body_bytes%20%2B%20deploy%2FCaddyfile::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance"
 },
 {
  "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
  "state": "ledger unit Every%20agent-reachable%20write%20to%20the%20shared%20control-plane%20SQLite%20file%20and%20host%20disk%20while%20AgentBox.disk_low%28%29%20is%20true%20or%20near%20the%20threshold%20%28tool%20calls%2C%20approval%20creation%2Fexpiry%2C%20GUI%20burst%20records%2C%20desktop%20and%20file%20routes%29%2C%20plus%20finished-approval%20row%20compaction::Disk-pressure%20guard%20and%20approval%20compaction%20%28PR%20%2320%29%3A%20call_tool%20refuses%20agent%20calls%20with%20507%20when%20free%20space%20on%20db_path.parent%20is%20below%20AGENTBOX_MIN_FREE%2C%20api.py%20skips%20the%20agent%20approval_forbidden%20row%2C%20_finish%20rewrites%20finished%20rows%27%20args%2Fpreview%20to%20the%20bounded%20audit%20shape%2C%20decide%20maps%20claim%20sqlite3.Error%20to%20503%20and%20expire_stale%20stops%20on%20sqlite3.Error.%20Invariant%3A%20an%20agent%20cannot%20keep%20growing%20the%20database%20or%20host%20disk%20past%20the%20guard%20through%20another%20route%2C%20and%20the%20human%20can%20still%20decide%2C%20delete%20and%20verify%20while%20low%3B%20compaction%20keeps%20what%20the%20approval%20card%20and%20audit%20need.::agentbox%2Fservice.py%23call_tool%2Fdisk_low%2F_finish%2Fdecide%2Fexpire_stale%2Flog_best_effort%20%2B%20agentbox%2Fapprovals.py%23finish%20%2B%20agentbox%2Fapi.py%23call_tool%20route%20%2B%20agentbox%2Fgui_bursts.py%23_finish%20%2B%20agentbox%2Fconfig.py%23min_free_bytes::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps: candidate",
  "unit": "Every%20agent-reachable%20write%20to%20the%20shared%20control-plane%20SQLite%20file%20and%20host%20disk%20while%20AgentBox.disk_low%28%29%20is%20true%20or%20near%20the%20threshold%20%28tool%20calls%2C%20approval%20creation%2Fexpiry%2C%20GUI%20burst%20records%2C%20desktop%20and%20file%20routes%29%2C%20plus%20finished-approval%20row%20compaction::Disk-pressure%20guard%20and%20approval%20compaction%20%28PR%20%2320%29%3A%20call_tool%20refuses%20agent%20calls%20with%20507%20when%20free%20space%20on%20db_path.parent%20is%20below%20AGENTBOX_MIN_FREE%2C%20api.py%20skips%20the%20agent%20approval_forbidden%20row%2C%20_finish%20rewrites%20finished%20rows%27%20args%2Fpreview%20to%20the%20bounded%20audit%20shape%2C%20decide%20maps%20claim%20sqlite3.Error%20to%20503%20and%20expire_stale%20stops%20on%20sqlite3.Error.%20Invariant%3A%20an%20agent%20cannot%20keep%20growing%20the%20database%20or%20host%20disk%20past%20the%20guard%20through%20another%20route%2C%20and%20the%20human%20can%20still%20decide%2C%20delete%20and%20verify%20while%20low%3B%20compaction%20keeps%20what%20the%20approval%20card%20and%20audit%20need.::agentbox%2Fservice.py%23call_tool%2Fdisk_low%2F_finish%2Fdecide%2Fexpire_stale%2Flog_best_effort%20%2B%20agentbox%2Fapprovals.py%23finish%20%2B%20agentbox%2Fapi.py%23call_tool%20route%20%2B%20agentbox%2Fgui_bursts.py%23_finish%20%2B%20agentbox%2Fconfig.py%23min_free_bytes::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps"
 },
 {
  "fingerprint": "agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop",
  "state": "ledger unit agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20upgrade%20before%20ws.accept%28%29::agentbox%2Fapi.py%23desktop_ws%20async%20handler%3A%20synchronous%20SQLite%20%28session%2C%20lease%29%20and%20Docker%20SDK%20calls%20on%20the%20event%20loop%20before%20accept%20%2B%20agentbox%2Fdesktop_ws.py%23relay%20setup::agentbox%2Fapi.py%20%2B%20agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation: candidate",
  "unit": "agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20upgrade%20before%20ws.accept%28%29::agentbox%2Fapi.py%23desktop_ws%20async%20handler%3A%20synchronous%20SQLite%20%28session%2C%20lease%29%20and%20Docker%20SDK%20calls%20on%20the%20event%20loop%20before%20accept%20%2B%20agentbox%2Fdesktop_ws.py%23relay%20setup::agentbox%2Fapi.py%20%2B%20agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation"
 },
 {
  "fingerprint": "agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt",
  "state": "ledger unit agentbox%2Fcli.py%23agentbox%20prune%20--before%20--archive%20%5B--dry-run%5D%20%2B%20agentbox%20verify%20--archive%20%28host%20CLI%2C%20direct%20SQLite%29%20and%20every%20later%20AuditLog.verify%28%29%2Fappend%20over%20a%20pruned%20database::Audit-log%20tamper%20evidence%20across%20pruning%3A%20retention.prune%20drops%20and%20recreates%20the%20audit_no_delete%20trigger%20inside%20BEGIN%20IMMEDIATE%2C%20records%20an%20audit_anchor%20%28last%20id%2Fhash%2C%20archive%20sha256%29%20and%20an%20audit_pruned%20row%3B%20verify%28%29%20starts%20at%20the%20latest%20anchor%20and%20verify_archives%28%29%20chains%20GENESIS%20-%3E%20archives%20-%3E%20live%20table.%20Invariant%3A%20a%20deletion%20or%20edit%20of%20audit%20history%20that%20the%20prune%20command%20did%20not%20perform%20is%20still%20detected%2C%20prune%20never%20removes%20pending%2Fapproved%20approvals%20or%20rows%20at%2Fafter%20the%20cutoff%2C%20and%20a%20failed%20prune%20leaves%20the%20database%20and%20archive%20consistent.::agentbox%2Fretention.py%20%2B%20agentbox%2Faudit.py%23SCHEMA%2Faudit_anchor%2Flatest_anchor%2Fcheck_chain%2Fread_archive%2Finsert_record%2Fappend%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fcli.py%23cmd_prune%2Fcmd_verify::ATTACK-CLASSES.md%23Cryptography%20and%20secrets: candidate",
  "unit": "agentbox%2Fcli.py%23agentbox%20prune%20--before%20--archive%20%5B--dry-run%5D%20%2B%20agentbox%20verify%20--archive%20%28host%20CLI%2C%20direct%20SQLite%29%20and%20every%20later%20AuditLog.verify%28%29%2Fappend%20over%20a%20pruned%20database::Audit-log%20tamper%20evidence%20across%20pruning%3A%20retention.prune%20drops%20and%20recreates%20the%20audit_no_delete%20trigger%20inside%20BEGIN%20IMMEDIATE%2C%20records%20an%20audit_anchor%20%28last%20id%2Fhash%2C%20archive%20sha256%29%20and%20an%20audit_pruned%20row%3B%20verify%28%29%20starts%20at%20the%20latest%20anchor%20and%20verify_archives%28%29%20chains%20GENESIS%20-%3E%20archives%20-%3E%20live%20table.%20Invariant%3A%20a%20deletion%20or%20edit%20of%20audit%20history%20that%20the%20prune%20command%20did%20not%20perform%20is%20still%20detected%2C%20prune%20never%20removes%20pending%2Fapproved%20approvals%20or%20rows%20at%2Fafter%20the%20cutoff%2C%20and%20a%20failed%20prune%20leaves%20the%20database%20and%20archive%20consistent.::agentbox%2Fretention.py%20%2B%20agentbox%2Faudit.py%23SCHEMA%2Faudit_anchor%2Flatest_anchor%2Fcheck_chain%2Fread_archive%2Finsert_record%2Fappend%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fcli.py%23cmd_prune%2Fcmd_verify::ATTACK-CLASSES.md%23Cryptography%20and%20secrets"
 }
]
```

# Hunter-reported `uncovered` boundaries

```json
[
 {
  "agent": "h-approvals",
  "uncovered": {
   "surface": "POST /sandboxes/{sid}/tools/exec with a long command: Policy.decide (command_names/_words/_raw_hits/simple_programs shlex passes) and preview_command, run on the tool_pool thread before any approval exists",
   "boundary": "Agent -> control-plane availability: CPU-bound pure-Python policy and preview parsing of an up-to-8 MiB command holds the GIL, which the event loop and human request threads share. Measured locally: Policy.decide took 4.96 s for a 128 KiB 'x;' command and grows at least linearly, so about 5 minutes for a full 8 MiB body, with 4 concurrent per sandbox.",
   "subsystem": "agentbox/policy.py#decide/_words/command_names/_raw_hits + agentbox/preview.py#_split_segments + agentbox/service.py#call_tool",
   "attack_class": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "starting_paths": [
    "agentbox/policy.py",
    "agentbox/preview.py",
    "agentbox/service.py",
    "agentbox/api.py"
   ],
   "reason": "No assigned unit owns command-length CPU cost in the policy gate. It needs its own bounded measurement of GIL starvation of the human API and a check of whether a per-command length cap belongs before policy.decide."
  }
 },
 {
  "agent": "h-ws",
  "uncovered": {
   "surface": "GET /ui/audit (polled every 3 s by templates/sandbox.html), GET /ui/verify, GET /audit/verify",
   "boundary": "AuditLog.recent runs an unindexed COUNT(*) WHERE sandbox_id, and AuditLog.verify does fetchall() of the entire audit table, both under AuditLog._lock (audit.py:311-316,338-340). The table grows with agent tool calls until disk_low. While these hold the lock, every agent tool call and every human log_human (fail-closed 503) waits, and verify loads the whole table into memory.",
   "subsystem": "agentbox/audit.py + agentbox/web.py + agentbox/api.py",
   "attack_class": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "starting_paths": [
    "agentbox/audit.py",
    "agentbox/web.py",
    "agentbox/api.py",
    "agentbox/templates/sandbox.html"
   ],
   "reason": "Agent-grown table size turns routine human audit views into long holds of a global lock and O(n) memory use. Measured 0.034 s (recent) and 0.84 s (verify) per 100k rows. This sits outside the WS unit and the peer disk-guard and retention units."
  }
 }
]
```

# Prior-ledger gap summary

- run-5 is a focused follow-up, not a full re-audit. Its ledger holds only the three units
  deferred in run-4 and four units for code changed by the run-4 fixes (PRs #16-#22). Every
  other run-4 unit was covered at 9805d91 and its code is unchanged or covered by these units;
  proposing them again needs a concrete changed-code reason.
- run-4 confirmed F1-F8 were fixed; regressions or bypasses of those fixes belong to the
  changed-code units. run-4 needs_validation N1 (same_origin scheme) and N3 (container output
  reader cap) stay open and are not re-hunted here.
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

Budget note: Budget cap 30 (owner-set). Spent so far: 6 hunters (Opus), 2 contract retries, 5 Phase 3 verifiers, and this critic = 14. Still reserved: about 5 Phase 5 record verifiers, 1 final-clean critic. Roughly 9 invocations remain for accepted new units (each needs an Opus hunter plus its Phase 3/5 verifiers), so propose at most 2-3 units, highest value first.

Return exactly one JSON object and nothing else:
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
