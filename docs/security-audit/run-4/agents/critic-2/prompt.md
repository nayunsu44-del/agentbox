You are `critic-2`, the distinct final-clean coverage critic; the post-wave critic has already run and its accepted work is recorded in the ledger, in run-4 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at `9805d91`. Your only writable directory is `/home/user/agentbox/docs/security-audit/run-4/agents/critic-2/scratch/`, and you need not write anything.

# architecture.md (verbatim)

# agentbox architecture summary (run-4)

Source ref: `9805d91` (`main`, after refactor PRs #11-#14). Profile `standard`, whole repo, budget 50. Built from recon-1a..1d (`agents/recon-*/result.md`). Line numbers below were re-checked by the parent; recon-1b and recon-1c cite some `api.py`, `web.py` and `preview.py` lines that do not exist in this tree, so treat their numbers as approximate.

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

Read it at /home/user/agentbox/docs/security-audit/run-4/coverage-ledger.json (32 units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

# Current candidate fingerprints and states

```json
[
 {
  "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
  "state": "final record: confirmed",
  "title": "Unauthenticated request bodies are fully read, JSON-decoded and multipart-spooled before the principal dependency rejects the request"
 },
 {
  "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
  "state": "final record: needs_validation",
  "title": "same_origin compares only the Origin netloc with Host, so an http:// page on the same host passes the CSRF origin check of a TLS deployment and can clear the session cookie"
 },
 {
  "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
  "state": "final record: needs_validation",
  "title": "Agent-grown audit and approval rows in the shared control-plane SQLite file have no aggregate bound or retention, so an agent can fill the host disk and neither recovery path keeps the audit chain"
 },
 {
  "fingerprint": "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap",
  "state": "final record: needs_validation",
  "title": "list_dir, outbox_list, preview glob expansion and screenshot buffer unbounded container output in the shared control-plane process"
 },
 {
  "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
  "state": "final record: needs_validation",
  "title": "GUI burst stray kill spares a uid-1001 process in a burst-start session whose pid the client-declared _NET_WM_PID window list names"
 },
 {
  "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
  "state": "final record: confirmed",
  "title": "Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent)"
 },
 {
  "fingerprint": "agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight",
  "state": "final record: confirmed",
  "title": "Unauthenticated GET /static/novnc/* runs docker create plus a full /usr/share/novnc tar extraction on every request while home/novnc/core/rfb.js is absent, with no single-flight"
 },
 {
  "fingerprint": "agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback",
  "state": "final record: confirmed",
  "title": "A GUI input queued on gui_lock across a human handback executes with no open burst, so its changes get no snapshot and no gui_changes row"
 },
 {
  "fingerprint": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
  "state": "final record: confirmed",
  "title": "Agent tool input still reaches the append-only audit log uncapped through approval previews and tool error strings"
 },
 {
  "fingerprint": "agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token",
  "state": "final record: confirmed",
  "title": "A restore racing a delete resurrects the deleted sandbox row and re-authorizes the agent token the delete revoked"
 },
 {
  "fingerprint": "agentbox/service.py:snapshot-quota:toctou-between-quota-gate-and-pre-exec-snapshot",
  "state": "final record: confirmed",
  "title": "Snapshot quota is decided from one container probe, but the docker commit is triggered by a second probe that the quota does not check"
 },
 {
  "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
  "state": "final record: needs_validation",
  "title": "The shared control-character filter misses U+061C - the only Unicode Bidi_Control code point it omits - plus the Cf/Zl/Zp invisibles, and the approval card renders them raw beside the argv that will execute"
 },
 {
  "fingerprint": "agentbox/web.py:unauthenticated-login-failure-audit-growth",
  "state": "final record: confirmed",
  "title": "Unauthenticated failed POST /login writes one permanent hash-chained audit row per attempt, with no rate limit, aggregation or retention"
 },
 {
  "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
  "state": "ledger unit Host-disk%20and%20SQLite%20pressure%20caused%20by%20agent%20actions%20%28audit%20rows%2C%20approval%20rows%2C%20captures%20PNGs%2C%20docker%20commit%20snapshots%2C%20sources%20dirs%29%20and%20by%20human%20read%20paths%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20%2Fui%2Fverify%2C%20%2Faudit%2Fverify%2C%20cmd_verify%2C%20GET%20%2Fapprovals%29::Agent-grown%20data%20-%3E%20one%20process-wide%20audit%20lock%20and%20one%20SQLite%20file%20shared%20by%20four%20connections%20%28AuditLog%2C%20ApprovalStore%2C%20SandboxManager%2C%20DesktopControl%29.%20AuditLog.verify%28%29%20and%20list%28%29%20run%20fetchall%20of%20the%20whole%20table%20under%20the%20same%20lock%20that%20every%20append%20needs%20%28agentbox%2Faudit.py%3A196-215%2C%20152-187%29.%20_safe_log%20swallows%20AuditWriteError%20after%20execution%20%28agentbox%2Fservice.py%3A362-369%29%2C%20while%20_close_gui_burst%20has%20already%20popped%20the%20burst%20before%20logging%20gui_changes%20or%20gui_processes_stopped.%20ApprovalStore%20claim%2C%20finish%20and%20create%20raise%20raw%20sqlite3%20errors%20%28approvals.py%3A49-92%29%2C%20not%20AuditWriteError.::agentbox%2Faudit.py%23append%20%2B%20list%20%2B%20verify%3B%20agentbox%2Fservice.py%23_safe_log%20%2B%20_close_gui_burst%20%2B%20decide%20%2B%20expire_stale%3B%20agentbox%2Fapprovals.py%23create%2Fclaim%2Ffinish%3B%20agentbox%2Fapi.py%23list_audit%2Fverify%3B%20agentbox%2Fweb.py%23verify_frag%2Faudit_frag::Failure%20and%20recovery%20under%20resource%20exhaustion%3A%20read-side%20lock%20hold%20time%20and%20memory%20on%20the%20shared%20audit%20lock%3B%20fail-closed%20%28503%29%20versus%20fail-open%20%28silently%20dropped%20post-hoc%20records%2C%20approvals%20stuck%20in%20approved%29%20behaviour%20at%20disk-full%20or%20lock%20contention: candidate",
  "unit": "Host-disk%20and%20SQLite%20pressure%20caused%20by%20agent%20actions%20%28audit%20rows%2C%20approval%20rows%2C%20captures%20PNGs%2C%20docker%20commit%20snapshots%2C%20sources%20dirs%29%20and%20by%20human%20read%20paths%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20%2Fui%2Fverify%2C%20%2Faudit%2Fverify%2C%20cmd_verify%2C%20GET%20%2Fapprovals%29::Agent-grown%20data%20-%3E%20one%20process-wide%20audit%20lock%20and%20one%20SQLite%20file%20shared%20by%20four%20connections%20%28AuditLog%2C%20ApprovalStore%2C%20SandboxManager%2C%20DesktopControl%29.%20AuditLog.verify%28%29%20and%20list%28%29%20run%20fetchall%20of%20the%20whole%20table%20under%20the%20same%20lock%20that%20every%20append%20needs%20%28agentbox%2Faudit.py%3A196-215%2C%20152-187%29.%20_safe_log%20swallows%20AuditWriteError%20after%20execution%20%28agentbox%2Fservice.py%3A362-369%29%2C%20while%20_close_gui_burst%20has%20already%20popped%20the%20burst%20before%20logging%20gui_changes%20or%20gui_processes_stopped.%20ApprovalStore%20claim%2C%20finish%20and%20create%20raise%20raw%20sqlite3%20errors%20%28approvals.py%3A49-92%29%2C%20not%20AuditWriteError.::agentbox%2Faudit.py%23append%20%2B%20list%20%2B%20verify%3B%20agentbox%2Fservice.py%23_safe_log%20%2B%20_close_gui_burst%20%2B%20decide%20%2B%20expire_stale%3B%20agentbox%2Fapprovals.py%23create%2Fclaim%2Ffinish%3B%20agentbox%2Fapi.py%23list_audit%2Fverify%3B%20agentbox%2Fweb.py%23verify_frag%2Faudit_frag::Failure%20and%20recovery%20under%20resource%20exhaustion%3A%20read-side%20lock%20hold%20time%20and%20memory%20on%20the%20shared%20audit%20lock%3B%20fail-closed%20%28503%29%20versus%20fail-open%20%28silently%20dropped%20post-hoc%20records%2C%20approvals%20stuck%20in%20approved%29%20behaviour%20at%20disk-full%20or%20lock%20contention"
 },
 {
  "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
  "state": "ledger unit Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29: candidate",
  "unit": "Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29"
 },
 {
  "fingerprint": "agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight",
  "state": "ledger unit Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29: candidate",
  "unit": "Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29"
 },
 {
  "fingerprint": "agentbox/web.py:unauthenticated-login-failure-audit-growth",
  "state": "ledger unit Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29: candidate",
  "unit": "Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29"
 },
 {
  "fingerprint": "agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token",
  "state": "ledger unit agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshots%7Crestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes%2F%7Bsid%7D%2Fsnapshot%7Crestore%7Cdelete::agentbox%2Fservice.py%23AgentBox.pause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%20ordering%20%28audit%2C%20end_desktop%2C%20bursts%2C%20captures%2C%20timers%29%20%2B%20api%2Fweb%20guard::agentbox%2Fservice.py%23lifecycle%20methods%20%28refactor%20PR%201%29::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use: candidate",
  "unit": "agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshots%7Crestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes%2F%7Bsid%7D%2Fsnapshot%7Crestore%7Cdelete::agentbox%2Fservice.py%23AgentBox.pause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%20ordering%20%28audit%2C%20end_desktop%2C%20bursts%2C%20captures%2C%20timers%29%20%2B%20api%2Fweb%20guard::agentbox%2Fservice.py%23lifecycle%20methods%20%28refactor%20PR%201%29::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use"
 },
 {
  "fingerprint": "agentbox/service.py:snapshot-quota:toctou-between-quota-gate-and-pre-exec-snapshot",
  "state": "ledger unit agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bwrite_file%2Cdelete_file%2CGUI%7D%20%2B%20snapshot%20routes::agentbox%2Fservice.py%23snapshot%20quota%20%2B%20_snap_locks%20%2B%20GUI%20burst%20snapshots::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox.py%23snapshot::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps: candidate",
  "unit": "agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bwrite_file%2Cdelete_file%2CGUI%7D%20%2B%20snapshot%20routes::agentbox%2Fservice.py%23snapshot%20quota%20%2B%20_snap_locks%20%2B%20GUI%20burst%20snapshots::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox.py%23snapshot::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps"
 },
 {
  "fingerprint": "agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback",
  "state": "ledger unit agentbox%2Fgui_bursts.py%23GuiBursts%20state%20shared%20by%20tool-pool%20threads%20%28call_tool%2C%20decide%29%20and%20human%20threads%20%28expire_stale%20polls%2C%20takeover%2C%20handback%2C%20end_desktop%2C%20lifecycle%20methods%29::agentbox%2Fgui_bursts.py%23GuiBursts%20open%2Fclose%2Fclose_idle%2Fend%2Freset_timers%20ordering%20%2B%20per-sandbox%20burst%20locks%20%2B%20_busy_lock::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_snapshot%2F_run_tool%2Ftakeover%2F_handback_locked%2Fend_desktop%2Fdecide::Race%20and%20check-then-act%20on%20security-control%20state%3A%20burst%20open%20versus%20idle-close%20ordering%2C%20double%20close%20or%20open%2C%20approved-path%20parity%20with%20call_tool%2C%20control-plane%20restart%20dropping%20bursts.%20Mitigation%20is%20only%20partial%20%28the%20accepted%20N-1%20GUI%20bypass%29.: candidate",
  "unit": "agentbox%2Fgui_bursts.py%23GuiBursts%20state%20shared%20by%20tool-pool%20threads%20%28call_tool%2C%20decide%29%20and%20human%20threads%20%28expire_stale%20polls%2C%20takeover%2C%20handback%2C%20end_desktop%2C%20lifecycle%20methods%29::agentbox%2Fgui_bursts.py%23GuiBursts%20open%2Fclose%2Fclose_idle%2Fend%2Freset_timers%20ordering%20%2B%20per-sandbox%20burst%20locks%20%2B%20_busy_lock::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_snapshot%2F_run_tool%2Ftakeover%2F_handback_locked%2Fend_desktop%2Fdecide::Race%20and%20check-then-act%20on%20security-control%20state%3A%20burst%20open%20versus%20idle-close%20ordering%2C%20double%20close%20or%20open%2C%20approved-path%20parity%20with%20call_tool%2C%20control-plane%20restart%20dropping%20bursts.%20Mitigation%20is%20only%20partial%20%28the%20accepted%20N-1%20GUI%20bypass%29."
 },
 {
  "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
  "state": "ledger unit agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF: candidate",
  "unit": "agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF"
 },
 {
  "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
  "state": "ledger unit approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls::agentbox%2Fpreview.py%23preview%20%2B%20split_segments%20%2B%20expand%2Fwalk%20callbacks%3A%20system-computed%20%27affected%27%20list::agentbox%2Fpreview.py%20%2B%20agentbox%2Fsandbox.py%23preview%20%2B%20agentbox%2Fservice.py%23_preview%2F_capture::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding: candidate",
  "unit": "approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls::agentbox%2Fpreview.py%23preview%20%2B%20split_segments%20%2B%20expand%2Fwalk%20callbacks%3A%20system-computed%20%27affected%27%20list::agentbox%2Fpreview.py%20%2B%20agentbox%2Fsandbox.py%23preview%20%2B%20agentbox%2Fservice.py%23_preview%2F_capture::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding"
 },
 {
  "fingerprint": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
  "state": "ledger unit container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality: candidate",
  "unit": "container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality"
 },
 {
  "fingerprint": "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap",
  "state": "ledger unit container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality: candidate",
  "unit": "container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality"
 },
 {
  "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
  "state": "ledger unit container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fgui_state.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fgui_state.py%20%2B%20agentbox%2Fsandbox_desktop.py%23desktop_processes%2Fkill_processes::ATTACK-CLASSES.md%23Business%20logic: candidate",
  "unit": "container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fgui_state.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fgui_state.py%20%2B%20agentbox%2Fsandbox_desktop.py%23desktop_processes%2Fkill_processes::ATTACK-CLASSES.md%23Business%20logic"
 },
 {
  "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
  "state": "ledger unit container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%2C%20approval%20cards%29::agentbox%2Fdisplay.py%23escape_controls%20%2B%20agentbox%2Fweb.py%23describe%2F_shown%2Ffinalize%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fcli.py%20%2B%20agentbox%2Ftemplates::AI-AND-LLM.md%23Insecure%20output%20rendering: candidate",
  "unit": "container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%2C%20approval%20cards%29::agentbox%2Fdisplay.py%23escape_controls%20%2B%20agentbox%2Fweb.py%23describe%2F_shown%2Ffinalize%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fcli.py%20%2B%20agentbox%2Ftemplates::AI-AND-LLM.md%23Insecure%20output%20rendering"
 }
]
```

# Hunter-reported `uncovered` boundaries

```json
[
 {
  "agent": "h-audit",
  "uncovered": {
   "surface": "Approval queue rows as an alternate, unmasked reader copy of tool args, retained after decide/expire/sandbox delete",
   "boundary": "agentbox/approvals.py storage and retention versus the masking policy enforced for the audit log; SQLite file retention across sandbox deletion",
   "subsystem": "agentbox/approvals.py + agentbox/service.py#drop_captures/delete_sandbox + agentbox/web.py#approvals_view",
   "attack_class": "DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline",
   "starting_paths": [
    "agentbox/approvals.py",
    "agentbox/service.py",
    "agentbox/web.py",
    "agentbox/api.py"
   ],
   "reason": "No assigned unit owns approval-table retention: the audit units own the hash chain and masking of audit rows, and the delete/lifecycle unit owns ordering and capture PNGs. It needs its own deterministic unit to decide whether the never-deleted raw-args row (including after the sandbox is gone) is intended audit history or an unmasked derived copy that outlives the workspace it describes."
  }
 },
 {
  "agent": "h-files",
  "uncovered": {
   "surface": "agentbox/api.py#POST /sandboxes and agentbox/web.py#POST /ui/sandboxes source_dir validation in compose mode",
   "boundary": "control-plane mount namespace versus host mount namespace: create() stats source_dir inside the agentbox container while the Docker daemon binds the same string in the host namespace",
   "subsystem": "agentbox/sandbox.py#create + deploy/docker-compose.yml",
   "attack_class": "CLOUD-AND-DEPLOYMENT.md#Secret exposure across workload boundaries",
   "starting_paths": [
    "agentbox/sandbox.py",
    "deploy/docker-compose.yml"
   ],
   "reason": "The is_dir()/overlaps() checks are only meaningful if the validated path denotes the same directory on the host. deploy/docker-compose.yml:19-28 mounts ${AGENTBOX_HOME_DIR} at an identical path and nothing else, so for any other source_dir the control plane validates a path inside its own image (for example /etc, /tmp or /root) and the daemon then copies the host's directory of that name into /workspace with a root-side cp -a under DAC_OVERRIDE, which can hand the agent host files the administrator never selected. Only the holder of the human token can supply source_dir, so this is not a privilege boundary crossing and is not a candidate here, but it is an unstated deployment precondition (host path equals control-plane path) that no assigned or peer-owned unit covers, and it needs its own unit with a rendered compose topology to settle."
  }
 },
 {
  "agent": "h-gui-race",
  "uncovered": {
   "surface": "decide->_snapshot->bursts.open during an active lease, then close_idle/_stop_strays killing the human newly launched GUI processes and attributing the human changes to the agent burst",
   "boundary": "agentbox/service.py#decide/_snapshot versus agentbox/gui_bursts.py#_stop_strays and the human desktop session",
   "subsystem": "agentbox/service.py + agentbox/gui_bursts.py",
   "attack_class": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Race conditions in shared state",
   "starting_paths": [
    "agentbox/service.py",
    "agentbox/gui_bursts.py"
   ],
   "reason": "No assigned unit owns the agent-burst-versus-human-session interaction during a takeover; it overlaps the stray-kill unit but is a distinct schedule."
  }
 },
 {
  "agent": "h-lifecycle",
  "uncovered": {
   "surface": "DELETE /sandboxes/{sid} retention of derived copies (snapshots table rows, snapshot images when removal fails, home/sources/{sid})",
   "boundary": "agentbox/sandbox.py#delete row/image cleanup + agentbox/sandbox.py#create empty-source dir",
   "subsystem": "agentbox/sandbox.py delete",
   "attack_class": "DATA-ISOLATION-AND-LIFECYCLE.md#Retention and queued-work overrun",
   "starting_paths": [
    "agentbox/sandbox.py"
   ],
   "reason": "The peer disk unit covers pressure on the host, not the lifecycle guarantee that a deleted sandbox's derived copies are gone; a dedicated unit should decide what delete must remove and whether a deleted sid may ever be restored."
  }
 },
 {
  "agent": "h-session",
  "uncovered": {
   "surface": "WebSocket /sandboxes/{sid}/desktop/ws -> agentbox/desktop_ws.py#relay (and any future async route that calls blocking sandbox helpers)",
   "boundary": "Blocking Docker SDK and SQLite work executed directly on the ASGI event loop before ws.accept: desktop_ws.py:20-21 -> sandbox_desktop.py:131-144 / sandbox.py:225-232 (_require_running -> containers.get) and service.log_human -> process-wide audit lock",
   "subsystem": "agentbox/desktop_ws.py + agentbox/sandbox_desktop.py + agentbox/sandbox.py",
   "attack_class": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "starting_paths": [
    "agentbox/desktop_ws.py",
    "agentbox/sandbox_desktop.py",
    "agentbox/api.py"
   ],
   "reason": "Any holder of a sandbox-scoped desktop link (the lowest-trust authenticated browser principal, handed out deliberately) can open repeated WS upgrades, and each one performs a synchronous Docker API call and an audit append on the single event loop, stalling every other HTTP/WS request including approval decisions. Sizing the stall needs the real daemon, and no listed unit owns blocking work inside async route handlers (h-pool owns the tool pools, h-audit owns the audit lock's read path), so this needs its own deterministic unit."
  }
 },
 {
  "agent": "h-wild",
  "uncovered": {
   "surface": "demo/injected_agent.py + demo/run_demo.sh + demo/policy.yaml (the documented prompt-injection demo harness)",
   "boundary": "demo#launcher environment propagation into the agent-side MCP process and the demo's deliberate default:allow policy operated with --auto approval",
   "subsystem": "demo",
   "attack_class": "ATTACK-CLASSES.md#Wildcard",
   "starting_paths": [
    "demo/injected_agent.py",
    "demo/run_demo.sh",
    "demo/policy.yaml"
   ],
   "reason": "No assigned or peer-owned unit lists demo/, yet it is the workflow the README tells an operator to run with an intentionally hijacked agent: it selects the environment handed to the low-trust side (injected_agent.py:37-42) and decides how approvals are answered (run_demo.sh:66-85). Whether that harness can leak AGENTBOX_HUMAN_TOKEN or normalise auto-approval is a deterministic question that should be owned by its own unit rather than a wildcard note."
  }
 }
]
```

# Prior-ledger gap summary

- run-3 confirmed records were all fixed afterwards and the refactor (PRs #11-#14) moved
  the code, so every one of them is a revalidation unit in this ledger, not an exclusion.
- run-3 needs_validation records v01 (same_origin scheme), v09 (burst open), v10 (gui_lock
  under a stuck X), v14 (framing), v15 (gui_strays window ownership) are current work.
- Three critic-3 units deferred in run-3 (GUI-burst state races, disk/SQLite pressure,
  pre-auth work) were folded into this ledger as units.
- Two run-3 rejected claims (runc alias, backgrounded-children pid exhaustion) suppress only
  those exact claims; reporting them again needs changed evidence.

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

Budget note: This is the final agent invocation of the run (50 of 50). No hunter can be assigned after you: any missing_units or reassign_ids you return are recorded as deferred with your reason and disclosed in the report, so return only source-backed gaps that are not already in the ledger (two critic-1 units are already deferred there). Return stop: true if you find no such gap.

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
