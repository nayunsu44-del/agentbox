You are hunter `h-audit` in run-4 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

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

# Assigned coverage units

[
 {
  "coverage_id": "Host-disk%20and%20SQLite%20pressure%20caused%20by%20agent%20actions%20%28audit%20rows%2C%20approval%20rows%2C%20captures%20PNGs%2C%20docker%20commit%20snapshots%2C%20sources%20dirs%29%20and%20by%20human%20read%20paths%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20%2Fui%2Fverify%2C%20%2Faudit%2Fverify%2C%20cmd_verify%2C%20GET%20%2Fapprovals%29::Agent-grown%20data%20-%3E%20one%20process-wide%20audit%20lock%20and%20one%20SQLite%20file%20shared%20by%20four%20connections%20%28AuditLog%2C%20ApprovalStore%2C%20SandboxManager%2C%20DesktopControl%29.%20AuditLog.verify%28%29%20and%20list%28%29%20run%20fetchall%20of%20the%20whole%20table%20under%20the%20same%20lock%20that%20every%20append%20needs%20%28agentbox%2Faudit.py%3A196-215%2C%20152-187%29.%20_safe_log%20swallows%20AuditWriteError%20after%20execution%20%28agentbox%2Fservice.py%3A362-369%29%2C%20while%20_close_gui_burst%20has%20already%20popped%20the%20burst%20before%20logging%20gui_changes%20or%20gui_processes_stopped.%20ApprovalStore%20claim%2C%20finish%20and%20create%20raise%20raw%20sqlite3%20errors%20%28approvals.py%3A49-92%29%2C%20not%20AuditWriteError.::agentbox%2Faudit.py%23append%20%2B%20list%20%2B%20verify%3B%20agentbox%2Fservice.py%23_safe_log%20%2B%20_close_gui_burst%20%2B%20decide%20%2B%20expire_stale%3B%20agentbox%2Fapprovals.py%23create%2Fclaim%2Ffinish%3B%20agentbox%2Fapi.py%23list_audit%2Fverify%3B%20agentbox%2Fweb.py%23verify_frag%2Faudit_frag::Failure%20and%20recovery%20under%20resource%20exhaustion%3A%20read-side%20lock%20hold%20time%20and%20memory%20on%20the%20shared%20audit%20lock%3B%20fail-closed%20%28503%29%20versus%20fail-open%20%28silently%20dropped%20post-hoc%20records%2C%20approvals%20stuck%20in%20approved%29%20behaviour%20at%20disk-full%20or%20lock%20contention",
  "surface": "Host-disk and SQLite pressure caused by agent actions (audit rows, approval rows, captures PNGs, docker commit snapshots, sources dirs) and by human read paths (GET /audit, /ui/audit, /ui/verify, /audit/verify, cmd_verify, GET /approvals)",
  "boundary": "Agent-grown data -> one process-wide audit lock and one SQLite file shared by four connections (AuditLog, ApprovalStore, SandboxManager, DesktopControl). AuditLog.verify() and list() run fetchall of the whole table under the same lock that every append needs (agentbox/audit.py:196-215, 152-187). _safe_log swallows AuditWriteError after execution (agentbox/service.py:362-369), while _close_gui_burst has already popped the burst before logging gui_changes or gui_processes_stopped. ApprovalStore claim, finish and create raise raw sqlite3 errors (approvals.py:49-92), not AuditWriteError.",
  "subsystem": "agentbox/audit.py#append + list + verify; agentbox/service.py#_safe_log + _close_gui_burst + decide + expire_stale; agentbox/approvals.py#create/claim/finish; agentbox/api.py#list_audit/verify; agentbox/web.py#verify_frag/audit_frag",
  "attack_class": "Failure and recovery under resource exhaustion: read-side lock hold time and memory on the shared audit lock; fail-closed (503) versus fail-open (silently dropped post-hoc records, approvals stuck in approved) behaviour at disk-full or lock contention",
  "starting_paths": [
   "agentbox/api.py",
   "agentbox/approvals.py",
   "agentbox/audit.py",
   "agentbox/cli.py",
   "agentbox/gui_bursts.py",
   "agentbox/service.py",
   "agentbox/web.py"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unsafe recovery and capacity rollback",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules"
  ],
  "excluded_blocks": [
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Computational amplification attack classes",
    "reason": "Superlinear parsing and decompression are not present; the amplification is row count and size, already owned by the audit-content and capture units."
   }
  ],
  "prior_status": "prior_deferred"
 },
 {
  "coverage_id": "agent-controlled%20audit%20content%20%28tool%20args%2C%20file%20names%2C%20process%20args%29%20and%20timeline%20readers%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20agentbox%20audit%29::agentbox%2Faudit.py%23hash%20chain%20%2B%20append-only%20triggers%20%2B%20list%20ordering%2Flimit::agentbox%2Faudit.py%20%2B%20agentbox%2Fweb.py%23audit%20%2B%20agentbox%2Fcli.py%23cmd_audit::ATTACK-CLASSES.md%23Business%20logic",
  "surface": "agent-controlled audit content (tool args, file names, process args) and timeline readers (GET /audit, /ui/audit, agentbox audit)",
  "boundary": "agentbox/audit.py#hash chain + append-only triggers + list ordering/limit",
  "subsystem": "agentbox/audit.py + agentbox/web.py#audit + agentbox/cli.py#cmd_audit",
  "attack_class": "ATTACK-CLASSES.md#Business logic",
  "starting_paths": [
   "agentbox/audit.py",
   "agentbox/web.py",
   "agentbox/cli.py",
   "agentbox/api.py"
  ],
  "ordinary_attack_class_block": "ATTACK-CLASSES.md#Business logic",
  "selected_companion_blocks": [
   "DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Universal moves",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Validation rules"
  ],
  "excluded_blocks": [
   {
    "block": "MEMORY-SAFETY-AND-BINARY.md#Core discipline",
    "reason": "No native code in scope; all control-plane code is Python."
   },
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "reason": "No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage)."
   },
   {
    "block": "PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline",
    "reason": "No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions."
   },
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "AI-AND-LLM.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLIENT-SIDE.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLOUD-AND-DEPLOYMENT.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   }
  ],
  "prior_status": "prior_confirmed_changed_source"
 },
 {
  "coverage_id": "every%20audit%20append%20%28tool%20args%2C%20results%2C%20errors%2C%20GUI%20records%29::agentbox%2Faudit.py%23mask_text%20%2B%20_mask::agentbox%2Faudit.py::ATTACK-CLASSES.md%23Cryptography%20and%20secrets",
  "surface": "every audit append (tool args, results, errors, GUI records)",
  "boundary": "agentbox/audit.py#mask_text + _mask",
  "subsystem": "agentbox/audit.py",
  "attack_class": "ATTACK-CLASSES.md#Cryptography and secrets",
  "starting_paths": [
   "agentbox/audit.py",
   "agentbox/service.py",
   "agentbox/gui_bursts.py"
  ],
  "ordinary_attack_class_block": "ATTACK-CLASSES.md#Cryptography and secrets",
  "selected_companion_blocks": [
   "DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Universal moves",
   "DATA-ISOLATION-AND-LIFECYCLE.md#Validation rules"
  ],
  "excluded_blocks": [
   {
    "block": "MEMORY-SAFETY-AND-BINARY.md#Core discipline",
    "reason": "No native code in scope; all control-plane code is Python."
   },
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "reason": "No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage)."
   },
   {
    "block": "PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline",
    "reason": "No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions."
   },
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "AI-AND-LLM.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLIENT-SIDE.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLOUD-AND-DEPLOYMENT.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   }
  ],
  "prior_status": "prior_covered_changed_source"
 }
]

## Prior-run records linked to these units (changed source: revalidate, do not assume)

All relevant source changed since run-3 (fixes and a behaviour-preserving refactor). For each prior confirmed record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can (candidate with the same fingerprint as confirmed, needs_validation, or record in your unit check why it no longer holds). A prior rejected claim may be re-reported only with changed evidence.

- `agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines` — run-3 confirmed medium: The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view
  Root cause (run-3 wording): AuditLog.list (audit.py:190-197) can only return the oldest `limit` rows after `after_id` (ORDER BY id ascending). Both human-facing consumers call it with limit=5000 and no after_id and then treat the result as the newest window: web.py audit_frag takes rows[-400:] and total=len(rows), and cli.py cmd_audit prints the whole list. Beyond 5000 rows the 'tail' is the tail of the oldest 5000, never the newest rows, and total is capped at 5000. Neither the UI nor the CLI has a paging control and the audit table is never pruned, so the freeze is permanent for that sandbox or system.

## Parent-provided reconnaissance leads

Recon leads (unverified): GET /audit with a negative limit may bypass min(limit, 5000) (SQLite LIMIT -1); mask_text runs on the truncated args head (secret split at the 16 KB boundary); dict keys are not masked; unauthenticated failed POST /login and agent approval_forbidden rows grow the audit log.
Settle each lead either way from current source; they are not findings.

# Selected attack-class blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost path, a missing effective bound, and impact on another user, shared service, safety function, or operator-owned spend. Self-limiting work in the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body/message/file caps, concurrency, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before calling a path unbounded.
- Do not run stress, saturation, or production tests. Use asymptotic analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State attacker cost, service work, persistence, scope, and recovery. One bounded input with superlinear or persistent shared effect is materially different from sustained volume.
- Use `confirmed` for source-visible bounds failures demonstrated safely. Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behavior is outside the repository.
```

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock -->
**Reachable fatal error or deadlock**
An untrusted input reaches `panic`, abort, fatal assertion, unhandled exception, process exit, lock cycle, or infinite loop in a shared process. Confirm supervisor scope and whether one worker or the whole service becomes unavailable. A restarted isolated worker may reduce impact but does not erase the defect.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unsafe recovery and capacity rollback -->
**Unsafe recovery and capacity rollback**
A restart, restore, fallback, or cleanup path rebuilds unbounded state, ignores current quotas, or restores the input that immediately repeats failure. Recovery correctness is part of availability.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers -->
**Analytics, logs, traces, and diagnostics as alternate readers**
Private content or credentials are emitted into systems with broader access, longer retention, or tenant mixing. Confirm the data class and realistic reader; field names, public identifiers, and operator-only content under intended policy are not enough.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves -->
## Universal moves (apply across the above)

- Build an input-to-resource table: earliest accepted size/cardinality, work before auth, downstream fan-out, persistence, shared pool, limit and cleanup owner, recovery.
- Compare aggregate limits with per-object limits. Ten thousand valid one-byte items may evade a per-message cap while exhausting tenant-wide or process-wide state.
- Validate only in an isolated fixture with strict CPU/memory/time limits and small growth points. Mock external and paid calls and stop once the missing bound or cancellation is observable.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name untrusted input, requester work, service amplification or retained resource, shared blast radius, and recovery. Missing limits without concrete shared impact are hardening.
2. Confirm no source-visible upstream, parser, queue, tenant, or framework bound prevents the path. Unknown deployed controls require `needs_validation`.
3. For superlinear behavior, establish the accepted complexity and bounded local growth. For leaks, show repeatable retention after cleanup should occur. For fatal paths, identify process/supervisor isolation.
4. Prioritize by low requester work, unauthenticated reachability, cross-tenant scope, persistence, and poor recovery; do not validate with availability impact.
5. Return `confirmed` only with safe local proof and meaningful shared effect. Return `needs_validation` with the exact upstream limit, topology, quota, or recovery observation an owner must check.

<!-- ATTACK-CLASSES.md#Business logic -->
**Business logic** (subagent_type: `general`)
Hunt logic errors by hand: standard scanners cannot find them, and they yield high-impact findings. For each major workflow:
- **State machine violations**: Can you skip steps? Go backwards? Reach an invalid state? What happens if you replay a completed flow? What about partial failure — if step 2 of 3 fails, is step 1 rolled back?
- **Race conditions with business impact**: Concurrent operations that produce invalid states (double-spend, double-approve, lost updates). Focus on operations that check-then-act non-atomically.
- **Numeric/quantity manipulation**: Negative values, zero values, overflow, precision loss, type coercion between string and number.
- **Access boundary violations**: Not "does the permission check exist" but "is it the right check for the business rule?" Can input to one operation bypass a restriction enforced on a different operation for the same effect?
- **Implicit trust assumptions**: Data from storage, config, other components, or plugins assumed safe because "we validated it on the way in." What if a different code path wrote it?
- **Time-based logic**: Expiry checks, scheduling, rate windows, clock skew. What happens at exact boundary moments? What about timezone differences between components?
- **Default and fallback behavior**: What is the security posture when config is missing? When a feature flag is off? When a dependency is unavailable? When the system is mid-migration?

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it for each read and write path.
- Trace derived copies. Sanitized primary data can become unsafe in search, cache, analytics, export, previews, logs, replicas, and backups with different ACL and retention rules.
- Deletion and revocation are lifecycle contracts. Check current, historical, cached, indexed, exported, restored, and queued copies within the product's stated boundary.
- Privacy or retention preference is not automatically a security vulnerability. Require an explicit data-access boundary or deletion/revocation guarantee and an unauthorized reader or later operation.
- Use `confirmed` for complete source-visible lineage and bounded dummy-tenant tests. Use `needs_validation` when external storage policy, retention, CDN behavior, replica lag, or backup access is unavailable.
```

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Universal moves -->
## Universal moves (apply across the above)

- Pick one protected record and draw primary write, query, cache, index, event, export, backup, deletion, and restore paths. Mark principal and tenant at every edge.
- Compare two dummy tenants through the same local service methods, then repeat after ACL change, deletion, account switch, and restore. Do not use real user data.
- Start at bypass clients, background jobs, migrations, global uniqueness, and cache keys. These paths commonly omit request-scoped identity that interactive endpoints carry.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name attacker or lower-trust principal, protected data/state, affected owner/tenant, alternate copy or operation, and unauthorized disclosure or mutation.
2. Cite both intended source-of-truth policy and the path that omits or disagrees with it. Confirm another layer does not enforce the same tenant/lifecycle condition.
3. Use local dummy tenants and non-sensitive fixtures to prove cross-scope access or stale lifecycle behavior. Stop at the minimum observable record or operation.
4. If external cache, object storage, replicas, analytics, backup, or retention policy is required, classify `needs_validation` and state the owner-observed check.
5. Return `confirmed` only with complete lineage and concrete boundary impact. Return `needs_validation` with the exact unresolved storage, ACL, invalidation, retention, or restore fact.

<!-- ATTACK-CLASSES.md#Cryptography and secrets -->
**Cryptography and secrets** (subagent_type: `general`)
- Weak randomness for security-critical values (tokens, keys, nonces)
- Hardcoded secrets, secrets in logs, error messages, URLs, or client-visible responses
- Broken key derivation, missing HMAC verification, nonce reuse
- Timing side-channels on secret comparison
- Misuse of crypto primitives (ECB mode, unauthenticated encryption, static IVs, etc.)
- What happens when crypto operations fail? Does the error path fall back to no-crypto?

# Excluded blocks

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Computational amplification attack classes`: Superlinear parsing and decompression are not present; the amplification is row count and size, already owned by the audit-content and capture units.
- `MEMORY-SAFETY-AND-BINARY.md#Core discipline`: No native code in scope; all control-plane code is Python.
- `SUPPLY-CHAIN-AND-RELEASE.md#Core discipline`: No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage).
- `PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline`: No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `AI-AND-LLM.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `WEB-PROTOCOL-AND-AUTH.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `CLIENT-SIDE.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `CLOUD-AND-DEPLOYMENT.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.

# Core hunting method (verbatim)

```text
## Defensive vulnerability-finding method

Your goal is to find source-grounded security invariant failures and the smallest fix,
not to expand harm beyond the boundary result. Stay within source review and bounded local execution.
Do not contact deployed endpoints, provider APIs, registries, identity systems,
message brokers, shared services, or other users. Use local dummy data only.

READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity,
authorization, normalization, state, derived copies, and the final sink. Read sibling,
legacy, batch, retry, cancellation, migration, and error paths that produce the same
effect. Compare sibling controls for equivalence, not only presence, and compare what
one component guarantees with what the next component assumes.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest affected dummy record, wrong return value, process-integrity
   effect, or locally observable shared-resource effect.
6. State a source-level change and regression case that enforce the invariant.

DEPTH BOUND: trace only paths that can reach your assigned boundary or whose
guarantees that boundary relies on. Stop a line of investigation as soon as the
invariant is settled either way, and record the result in your structured output —
a covered, candidate, or blocked disposition, or an `uncovered` entry — instead of
continuing to search.

TEST SAD PATHS AND DISAGREEMENTS. Check absent, empty, zero, negative, maximum,
over-limit, duplicate, mixed encoding, stale, revoked, reordered, concurrent,
partially migrated, failed dependency, and rollback state only where the interface
accepts them. Compare canonicalization and units at every parser or policy handoff.
For multi-step issues, treat each output as a prerequisite and do not assume a later
boundary. If any prerequisite is not established, record a blocker.

When a proposed high or critical candidate reveals a reusable root cause, search paths
owned by the assigned coverage IDs for lexical, structural, and logical variants.
Consolidate the same root cause, but establish each variant's conditions and impact
independently. Do not investigate peer-owned units. Return a variant with no current
coverage unit as `uncovered`.

USE THE NARROWEST LOCAL CHECK THAT SETTLES THE CLAIM. Target-controlled builds,
tests, processes, browsers, emulators, fuzzers, and fixture processing may run only
inside the parent-approved OS-enforced sandbox. It must disable external networking,
start from an empty allowlisted environment, expose target and tools read-only, permit
writes only to your scratch directory, and apply low CPU, memory, process, file-size,
disk, and wall-clock limits. Isolated loopback is allowed only for a local fixture.
If any control is unavailable, do not execute: return needs_validation with that exact
blocker. Prefer an existing unit test, minimal function harness, dummy-tenant service
call, small malformed fixture, deterministic race schedule, or locally rendered policy.
Do not install or fetch tools.

Record the exact input, command, limits, and minimum result. For the environment,
record only allowlisted variable names and safe non-secret values needed to reproduce
the check. Never capture the ambient environment, inherited variables, credentials,
authentication state, or unrelated host paths. The target-controlled process writes
only in scratch. After the sandbox and all its processes terminate, only trusted
parent-side code may promote predeclared scratch-relative files, following the
promotion procedure block included verbatim in this prompt. You and target code never
write retained artifacts. If promotion is unavailable or fails for decisive evidence,
return needs_validation with the exact promotion blocker.
Never stress availability, invoke a live target, use a real credential, publish an
artifact, or continue past the minimum observed effect.

A deployment, browser, provider, broker, OS, proxy, package, secret, or identity fact
outside source is not proof either way. If one such fact is decisive, return a
needs_validation record with the exact missing observation and safe owner-observed check.
```

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

# Core validation rules (verbatim)

```text
## Candidate gate

1. A candidate needs a complete repository-relative source trace and evidence for the
   claimed root cause, including the strongest source-visible control.
2. A proposed confirmed record needs a bounded local observed result, meaningful impact
   across a stated boundary, complete conditions, and no visible preventing layer.
3. Do not strengthen a crash into code execution, ordinary work into shared availability,
   or a same-principal action into privilege gain.
4. If a required fact is not source-visible or locally observable, use
   needs_validation. Name exact blockers; do not give it severity or speculative completion.
5. A missing best practice with no affected principal/resource is excluded or hardening,
   not a finding. A candidate disproved by source is not needs_validation.
6. Use the same source-derived fingerprint for the same root cause in every state.
   It must match `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` and must not include a line,
   wave, agent, severity, or verdict.
7. Return an empty candidate array when nothing survives these gates.
```

# Exclusions and peer-owned units

Carried same-source prior confirmed exclusions: none (no unit is same-source).

Peer-owned coverage IDs (do not investigate these; report a different boundary you notice under `uncovered`):
- `GUI-burst%20writes%20outside%20%2Fworkspace%20by%20uid%201001%20%28%2Fhome%2Fdesktop%2C%20%2Ftmp%2C%20%2Fdev%2Fshm%2C%20%2Frun%2Fuser%2C%20XDG%20dirs%29%20that%20persist%20through%20snapshot%2C%20restore%20or%20restart::images%2Fdesktop%2Fagentbox-desktop-start%23%2Fhome%2Fdesktop%20reset%20at%20start%20%2B%20agentbox%2Fgui_state.py%23workspace%20manifest%20scope::images%2Fdesktop%20%2B%20agentbox%2Fsandbox.py%23restore%2Fstart%20%2B%20agentbox%2Fgui_bursts.py::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries` (owner h-container)
- `Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29` (owner h-preauth)
- `agentbox%2Fagent.py%23LLM%20loop%20%2B%20agentbox%2Fmcp_server.py%20tools::agentbox%2Fagent.py%23prompt-injection%20to%20tool%20action%20and%20operator%20terminal%20output%20%28approval%20is%20the%20only%20control%29::agentbox%2Fagent.py%20%2B%20agentbox%2Fmcp_server.py%20%2B%20agentbox%2Fcli.py%23cmd_agent::AI-AND-LLM.md%23Indirect%20injection%20through%20retrieved%20or%20ingested%20content` (owner h-wild)
- `agentbox%2Fapi.py%23GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%20%2B%20takeover%2Fhandback%20%2B%20state%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fdesktop.py%23ticket%20redeem%20%2B%20session%20scope%20%2B%20session%20revocation%20on%20human-token%20rotation%20%2B%20lease::agentbox%2Fdesktop.py%20%2B%20agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Session%20fixation%20and%20invalidation` (owner h-session)
- `agentbox%2Fapi.py%23POST%20%2Fapprovals%2F%7Baid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2F%7Bdecision%7D%20%2B%20agentbox%2Fcli.py%23cmd_approve::agentbox%2Fservice.py%23decide%20executes%20the%20agent%27s%20original%20args%20after%20human%20approval::agentbox%2Fservice.py%20%2B%20agentbox%2Fapprovals.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding` (owner h-policy)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%20source_dir%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes::agentbox%2Fsandbox.py%23create%20source_dir%20overlap%20check%20%28filesystem%20identity%29%20%2B%20NonRecursive%20bind::agentbox%2Fsandbox.py%23create::ATTACK-CLASSES.md%23Feature%20abuse%20and%20data%20leakage` (owner h-files)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover%20%2B%20handback%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%28end_desktop%29::agentbox%2Fservice.py%23desktop.gui_lock%20held%20across%20timed%20_x%20GUI%20execs%20%2B%20takeover%2Fhandback%2030%20s%20bound%20%2B%20takeover-pending%20gate::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox_desktop.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-gui-race)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshots%7Crestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes%2F%7Bsid%7D%2Fsnapshot%7Crestore%7Cdelete::agentbox%2Fservice.py%23AgentBox.pause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%20ordering%20%28audit%2C%20end_desktop%2C%20bursts%2C%20captures%2C%20timers%29%20%2B%20api%2Fweb%20guard::agentbox%2Fservice.py%23lifecycle%20methods%20%28refactor%20PR%201%29::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use` (owner h-lifecycle)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%2Cscreenshot%7D::agentbox%2Fgui_bursts.py%23GUI%20burst%20snapshot%20%2B%20fail-closed%20baseline%20%2B%20gui_changes%20%2B%20stray%20kill%20%28N-1%20partial%20mitigation%29::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_run_tool::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries` (owner h-gui-burst)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%20%2B%20every%20expire_stale%20caller::agentbox%2Fapi.py%23tool_pool%20%2B%20agentbox%2Fservice.py%23call_tool%20tool_concurrency%20%2B%20agentbox%2Fgui_bursts.py%23burst%20close%20pool::agentbox%2Fservice.py%20%2B%20agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fapi.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-pool)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%20-%3E%20REQUIRE_APPROVAL%20on%20desktop%20templates::agentbox%2Fservice.py%23_call_tool%20approval%20creation%3A%20per-sandbox%20pending%20cap%20%2B%20capture%20PNG%20lifecycle%20%28drop_captures%20on%20decide%2Fexpire%2Fdelete%29::agentbox%2Fservice.py%20%2B%20agentbox%2Fapprovals.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps` (owner h-queue)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bwrite_file%2Cdelete_file%2CGUI%7D%20%2B%20snapshot%20routes::agentbox%2Fservice.py%23snapshot%20quota%20%2B%20_snap_locks%20%2B%20GUI%20burst%20snapshots::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox.py%23snapshot::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps` (owner h-pool)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2Fexec::agentbox%2Fpolicy.py%23Policy.decide%20read-only-exec%20allowlist::agentbox%2Fpolicy.py%20%2B%20agentbox%2Fsandbox.py%23exec::ATTACK-CLASSES.md%23Injection` (owner h-policy)
- `agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20-%3E%20agentbox%2Fdesktop_ws.py%23relay::agentbox%2Fapi.py%23cookie%20session%20%2B%20same_origin%20%2B%20lease%20on%20WebSocket%20%2B%20agentbox%2Fdesktop_ws.py%23session%20re-check::agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fapi.py::CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use` (owner h-session)
- `agentbox%2Fapi.py%23all%20JSON%20and%20browser%20routes::agentbox%2Fapi.py%23principal%20%2B%20human_only%20%2B%20screen_human%20%2B%20desktop_human::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::ATTACK-CLASSES.md%23Access%20control` (owner h-preauth)
- `agentbox%2Fapi.py%23tools%20read_file%2Fwrite_file%2Fdelete_file%2Flist_dir%20%2B%20POST%20files%20%2B%20GET%20outbox::agentbox%2Fsandbox.py%23safe_path%20%2B%20_workspace_path%20%2B%20clean_name%20%2B%20FIFO%20guard::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Resource%20and%20file%20handling` (owner h-files)
- `agentbox%2Fcli.py%23cmd_serve%20%2B%20agentbox%2Fapi.py%23create_app%20factory%20%2B%20deploy%2F%2A::agentbox%2Fcli.py%23bind_problem%20%2B%20runtime_problem%20%2B%20sandbox.py%20runtime%20selection::agentbox%2Fcli.py%20%2B%20deploy::CLOUD-AND-DEPLOYMENT.md%23Security-control%20precedence%20drift` (owner h-lifecycle)
- `agentbox%2Fgui_bursts.py%23GuiBursts%20state%20shared%20by%20tool-pool%20threads%20%28call_tool%2C%20decide%29%20and%20human%20threads%20%28expire_stale%20polls%2C%20takeover%2C%20handback%2C%20end_desktop%2C%20lifecycle%20methods%29::agentbox%2Fgui_bursts.py%23GuiBursts%20open%2Fclose%2Fclose_idle%2Fend%2Freset_timers%20ordering%20%2B%20per-sandbox%20burst%20locks%20%2B%20_busy_lock::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_snapshot%2F_run_tool%2Ftakeover%2F_handback_locked%2Fend_desktop%2Fdecide::Race%20and%20check-then-act%20on%20security-control%20state%3A%20burst%20open%20versus%20idle-close%20ordering%2C%20double%20close%20or%20open%2C%20approved-path%20parity%20with%20call_tool%2C%20control-plane%20restart%20dropping%20bursts.%20Mitigation%20is%20only%20partial%20%28the%20accepted%20N-1%20GUI%20bypass%29.` (owner h-gui-race)
- `agentbox%2Fweb.py%23%2Fui%20pages%20%2B%20agentbox%2Fdesktop.py%23page%20rendered%20in%20a%20frame::agentbox%2Fapi.py%23X-Frame-Options%20%2B%20CSP%20frame-ancestors%20%27self%27%20on%20cookie-authenticated%20pages%20%2B%20SameSite%3DStrict%20%2B%20same_origin::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fdesktop.py::CLIENT-SIDE.md%23Clickjacking` (owner h-webui)
- `agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF` (owner h-webui)
- `approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls::agentbox%2Fpreview.py%23preview%20%2B%20split_segments%20%2B%20expand%2Fwalk%20callbacks%3A%20system-computed%20%27affected%27%20list::agentbox%2Fpreview.py%20%2B%20agentbox%2Fsandbox.py%23preview%20%2B%20agentbox%2Fservice.py%23_preview%2F_capture::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding` (owner h-policy)
- `code%20running%20inside%20the%20sandbox%20container%20%28uid%201000%20agent%2C%20uid%201001%20desktop%29::agentbox%2Fsandbox.py%23container%20hardening%20flags%20%2B%20root-run%20docker%20execs%20%28sandbox.py%2C%20sandbox_desktop.py%29::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_desktop.py%20%2B%20images%2Fdesktop::CLOUD-AND-DEPLOYMENT.md%23Host%20or%20control-plane%20capability%20exposure` (owner h-container)
- `container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality` (owner h-queue)
- `container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fgui_state.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fgui_state.py%20%2B%20agentbox%2Fsandbox_desktop.py%23desktop_processes%2Fkill_processes::ATTACK-CLASSES.md%23Business%20logic` (owner h-gui-burst)
- `container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%2C%20approval%20cards%29::agentbox%2Fdisplay.py%23escape_controls%20%2B%20agentbox%2Fweb.py%23describe%2F_shown%2Ffinalize%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fcli.py%20%2B%20agentbox%2Ftemplates::AI-AND-LLM.md%23Insecure%20output%20rendering` (owner h-webui)
- `whole-repo%23basic%20exposures::whole-repo%23obvious%20controls%20%28secrets%2C%20debug%2C%20cookies%2C%20CORS%2C%20redirects%2C%20errors%29::whole-repo::ATTACK-CLASSES.md%23Obvious%20things` (owner h-preauth)
- `whole-repo%23undocumented%2Fedge%20surfaces::whole-repo%23feature%20interactions%20not%20covered%20by%20other%20units::whole-repo::ATTACK-CLASSES.md%23Wildcard` (owner h-wild)

# Your paths, sandbox and result contract

- Agent ID: `h-audit`. Audited source (read-only): `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` (git worktree of main at 9805d91). Read it with Read/Grep/Glob or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-audit/scratch/`. Retained artifacts: `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-audit/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-audit <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target). Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte are importable). This host is Windows, so the wrapper is a Python script and every sandbox call starts with `python`: write `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-audit/scratch/h.py`, then run `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-audit /usr/bin/python3 /scratch/h.py`; inside PowerShell capture output with `| Out-File -Encoding utf8 <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-audit/scratch/h.out` or have the script write its own file. Unit tests (cwd must be /target; the tests open repo-relative paths and pytest cannot write there, so pass --capture=sys): `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-audit /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"` (93 pass in ~27 s; the 120 s wall clock leaves room only for a subset, so prefer one file or -k).
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/h-audit/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
- Time box: aim to finish within roughly 50 tool calls. Stop each line of investigation as soon as the invariant is settled.
- Your final message must be ONLY the JSON object (no prose, no code fence).

## Structured hunter result

Return exactly one JSON object, with no surrounding prose:

```json
{
  "units": [
    {
      "coverage_id": "one assigned ID",
      "disposition": "covered|candidate|blocked",
      "reviewed_paths": ["repo/relative/path"],
      "checks": [
        {
          "agent_id": "canonical owner of this check",
          "reviewed_paths": ["repo/relative/path owned by this check"],
          "invariant": "specific control checked for this unit",
          "method": "source|local",
          "result": "what source or the bounded check established",
          "artifact": "agents/<agent-id>/artifacts/file for local, null for source"
        }
      ],
      "candidate_fingerprints": [],
      "unresolved": []
    }
  ],
  "candidates": [],
  "hardening": ["concrete non-finding note"],
  "uncovered": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "reason": "why this needs its own deterministic coverage unit"
    }
  ]
}
```

Each `candidates` entry is schema-shaped except that it uses `proposed_verdict` in place of `verdict`:

- `proposed_verdict: "confirmed"`: include every field required by the `confirmed` branch of `report-schema.json` other than `verdict`: `fingerprint`, title, description, `root_cause`, `intended_behavior`, ordered `trace`, `evidence`, `conditions`, target-neutral `execution`, `remediation`, `severity`, and `confidence`. The execution instructions describe only the bounded local check already performed. `payloads` holds the minimum test input, fixture, or native invocation. `observed_result` records actual local output. Overall severity must not exceed observed impact.
- `proposed_verdict: "needs_validation"`: include every field required by that schema branch other than `verdict`: `fingerprint`, title, description, `claimed_root_cause`, ordered `trace`, `evidence`, nonempty `blockers`, and `validation_plan` with at least one applicable `local` or `deployment` step. Do not invent an inapplicable context. Do not include severity, execution, remediation, reason, or a confirmed `root_cause`. `deployment` is an owner-observed check, not a request to probe a live target.

Every assigned coverage ID appears exactly once in `units`. A `covered` unit needs an owner, nonempty `reviewed_paths` and `checks`, no unresolved fact, and no candidate. A `candidate` unit has the same owned evidence and is the only state that carries linked fingerprints. A `blocked` unit is an owned partial review with nonempty paths, checks, and unresolved facts but no fingerprint. All source paths are repository-relative, never absolute or traversal paths. A trace with several entries begins at `entrypoint`, ends at `sink`, and labels intermediate steps `propagation`. Every check has its own canonical lowercase `agent_id` and nonempty `reviewed_paths`; the unit-level list is exactly the union of those owned paths. A `source` check uses `artifact: null`. A `local` check uses one successfully parent-promoted regular file beneath `agents/<check.agent_id>/artifacts/`; this permits a verifier to add independently owned evidence without taking ownership from the hunter. Never link scratch, an output-root file, or another check owner's artifact.

## report-schema.json `confirmed` branch (verbatim)

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

## report-schema.json `needs_validation` branch (verbatim)

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
