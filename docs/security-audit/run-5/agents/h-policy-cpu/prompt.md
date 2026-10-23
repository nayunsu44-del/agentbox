You are hunter `h-policy-cpu` in run-5 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

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

# Assigned coverage units

[
 {
  "coverage_id": "POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2Fexec%20%28and%20any%20tool%20whose%20argument%20text%20reaches%20Policy.decide%20and%20preview_command%29%20with%20a%20long%20or%20adversarially%20shaped%20command%2C%20run%20on%20the%20tool_pool%20thread%20before%20any%20approval%20exists%2C%20plus%20the%20approval-card%20render%20of%20the%20same%20text::Agent%20to%20control-plane%20availability%3A%20pure-Python%20policy%20and%20preview%20parsing%20%28Policy.decide%2C%20_split_segments%2C%20shlex%20passes%2C%20_raw_hits%2C%20preview%20glob%2Fwalk%29%20of%20an%20agent%20command%20up%20to%20the%208%20MiB%20body%20cap%2C%20with%20no%20per-command%20length%20cap%2C%20holds%20the%20GIL%20shared%20with%20the%20event%20loop%20and%20human%20threads%20%28hunter%20measurement%3A%204.96%20s%20for%20a%20128%20KiB%20command%2C%204%20concurrent%20per%20sandbox%29.%20Invariant%3A%20no%20agent-supplied%20argument%20makes%20evaluation%20cost%20more%20than%20a%20small%20bounded%20amount%20of%20CPU%2C%20memory%20or%20container%20exec%20time%20before%20rejection%20or%20queueing%2C%20and%20the%20human%20API%20stays%20responsive.::agentbox%2Fpolicy.py%23decide%2F_words%2Fcommand_names%2F_raw_hits%2Fsimple_programs%2Fhas_bash_comment%20%2B%20agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%20%28container-side%20glob%20and%20find%2C%20no%20timeout%29%20%2B%20agentbox%2Fservice.py%23call_tool%2F_call_tool%2F_logged_args%20%2B%20agentbox%2Fapi.py%23tool%20route::Resource%20exhaustion%3A%20algorithmic%20complexity%20and%20worker%20starvation",
  "surface": "POST /sandboxes/{sid}/tools/exec (and any tool whose argument text reaches Policy.decide and preview_command) with a long or adversarially shaped command, run on the tool_pool thread before any approval exists, plus the approval-card render of the same text",
  "boundary": "Agent to control-plane availability: pure-Python policy and preview parsing (Policy.decide, _split_segments, shlex passes, _raw_hits, preview glob/walk) of an agent command up to the 8 MiB body cap, with no per-command length cap, holds the GIL shared with the event loop and human threads (hunter measurement: 4.96 s for a 128 KiB command, 4 concurrent per sandbox). Invariant: no agent-supplied argument makes evaluation cost more than a small bounded amount of CPU, memory or container exec time before rejection or queueing, and the human API stays responsive.",
  "subsystem": "agentbox/policy.py#decide/_words/command_names/_raw_hits/simple_programs/has_bash_comment + agentbox/preview.py#preview_command/_split_segments + agentbox/sandbox.py#_expand/_walk (container-side glob and find, no timeout) + agentbox/service.py#call_tool/_call_tool/_logged_args + agentbox/api.py#tool route",
  "attack_class": "Resource exhaustion: algorithmic complexity and worker starvation",
  "starting_paths": [
   "agentbox/policy.py",
   "agentbox/preview.py",
   "agentbox/service.py",
   "agentbox/sandbox.py",
   "agentbox/api.py",
   "agentbox/default_policy.yaml"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation"
  ],
  "excluded_blocks": [
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality",
    "reason": "Container-output reader caps are run-4 N3 (needs_validation, not re-hunted); this unit is about CPU spent on agent-supplied input, not container output."
   }
  ],
  "prior_status": "new"
 }
]

## Prior-run records linked to these units (changed source: revalidate, do not assume)

Since run-4 (audited at 9805d91) every run-4 confirmed record and the N2/N4/N5 needs_validation records were fixed (PRs #16-#22); the source you read is the fixed tree. For each prior confirmed record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can (candidate with the same fingerprint as confirmed, needs_validation, or record in your unit check why it no longer holds). A prior rejected claim may be re-reported only with changed evidence.

- none

## Parent notes

- This unit came from the post-wave critic, based on h-approvals' measurement (Policy.decide 4.96 s for a 128 KiB 'x;' command). Full critic boundary: Agent to control-plane availability: pure-Python, CPU-bound policy and preview parsing of an attacker-sized command (up to the 8 MiB AGENTBOX_MAX_BODY; no per-command or per-argument length cap exists, grep finds only max_body_bytes) holds the GIL shared with the event loop and every human request thread. The h-approvals hunter measured Policy.decide at 4.96 s for a 128 KiB 'x;' command, growing at least linearly, and up to 4 such calls run concurrently per sandbox on the 32-thread tool_pool, across sandboxes. Invariant: no agent-supplied command or argument can make policy evaluation, _split_segments, simple_programs/shlex passes, _raw_hits or the preview glob/walk expansion cost more than a small bounded amount of CPU, memory or container-side exec time before the call is rejected or queued, and the human API stays responsive while it runs.
- Measure in the sandbox (bounded sizes only, e.g. 32/64/128/256 KiB) which function dominates and whether growth is linear or superlinear, and whether another thread (a stand-in for the event loop) is starved while it runs. Do not try full 8 MiB inputs in the 120 s sandbox; extrapolate. Check where in the call path a length cap would sit (before policy.decide) and what the agent token can reach.

- Contract: each unit's reviewed_paths must be exactly the union of its checks' reviewed_paths (two wave-1 results were bounced for this).
- Budget is tight (owner cap 30): settle the invariant with source plus at most a few sandboxed harnesses, and aim to finish within about 30 tool calls.

# Selected attack-class blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation -->
**Superlinear parsing, matching, or evaluation**
Small accepted input drives catastrophic regex backtracking, nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort/hash behavior. Derive accepted depth/cardinality and complexity, then demonstrate a bounded growth curve locally.

# Excluded blocks

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality`: Container-output reader caps are run-4 N3 (needs_validation, not re-hunted); this unit is about CPU spent on agent-supplied input, not container output.

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
- `A%20GUI%20burst%20opened%20while%20a%20human%20takeover%20lease%20is%20held%3A%20%28a%29%20POST%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2Fapprove%20for%20an%20approved%20click%2Ftype%2Fkey%2C%20which%20is%20reachable%20once%20the%20snapshot%20quota%20turns%20GUI%20input%20into%20REQUIRE_APPROVAL%20or%20a%20policy%20gates%20GUI%20tools%2C%20and%20%28b%29%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%7D%20whose%20pre-input%20docker%20commit%20races%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover.%20The%20burst%20is%20then%20closed%20by%20close_idle%2C%20which%20any%20agent%20tool%20call%20triggers%2C%20or%20by%20the%20next%20burst%20after%20handback.::Agent%20GUI-burst%20enforcement%20%28stray%20kill%2C%20gui_kept%2Fgui_changes%20attribution%29%20versus%20the%20human%20desktop%20session%20during%20a%20takeover%3A%20takeover%20closes%20the%20burst%20under%20gui_lock%20before%20installing%20the%20lease%20%28service.py%3A571-589%2C%20close%20at%20582%29%2C%20but%20_snapshot%20%28service.py%3A261-277%29%20closes%20and%20opens%20a%20burst%20without%20gui_lock%20or%20a%20lease%20check%2C%20reached%20from%20decide%20%28service.py%3A440%29%20and%20from%20call_tool%20after%20a%20needs_snapshot%20lease%20check%20%28gui_bursts.py%3A55%29%20that%20precedes%20a%20multi-second%20commit%3B%20an%20opened%20burst%20may%20survive%20the%20lease%20so%20close_idle%20%28gui_bursts.py%3A154%29%20or%20the%20next%20burst%20kills%20processes%20the%20human%20started%20or%20charges%20human%20edits%20to%20the%20agent.::agentbox%2Fservice.py%23decide%2F_snapshot%2Fcall_tool%2Ftakeover%2F_handback_locked%20%2B%20agentbox%2Fgui_bursts.py%23needs_snapshot%2Fopen%2Fclose_idle%2F_stop_strays%20%2B%20agentbox%2Fgui_state.py%23gui_strays::Race%20and%20check-then-act%20on%20security-control%20state%3A%20GUI%20burst%20opened%20by%20decide%2F_snapshot%20or%20call_tool%20while%20a%20human%20takeover%20lease%20is%20held` (owner h-gui-lease)
- `AuditLog._lock%20as%20a%20global%20contention%20point%20reachable%20by%20agent-grown%20table%20size%20and%20by%20unauthenticated%20traffic%3A%20GET%20%2Fui%2Faudit%20%28polled%20every%203%20s%20by%20templates%2Fsandbox.html%29%2C%20GET%20%2Fui%2Fverify%2C%20GET%20%2Faudit%2Fverify%2C%20AuditLog.recent%20%28unindexed%20COUNT%28%2A%29%20WHERE%20sandbox_id%29%2C%20AuditLog.verify%20%28fetchall%20of%20the%20whole%20table%2C%20audit.py%3A336-350%29%2C%20AuditLog.list%2C%20versus%20every%20AuditLog.append%2Finsert_record%20from%20agent%20tool%20calls%20and%20every%20fail-closed%20log_human%3B%20plus%20the%20unauthenticated%20POST%20%2Flogin%20failure%20throttle%20%28web.py%3A93-114%29%20and%20extract_novnc%20single-flight%20%28sandbox_desktop.py%3A174%29::Agent%20and%20unauthenticated%20clients%20to%20human%20availability%20and%20audit%20evidence%3A%20AuditLog.recent%2Fverify%20scan%20the%20agent-grown%20table%20under%20the%20same%20_lock%20append%20needs%20%28fail-closed%20log_human%20returns%20503%20while%20it%20is%20held%29%2C%20verify%20loads%20the%20whole%20table%2C%20the%20F8%20login%20throttle%20shares%20one%20global%20window%2C%20and%20F5%20extract_novnc%20holds%20a%20global%20lock%20across%20docker%20create.%20Invariant%3A%20no%20agent%20or%20unauthenticated%20sequence%20holds%20these%20locks%20long%20enough%20to%20refuse%20human%20actions%2C%20exhaust%20memory%2C%20or%20hide%20credential-guessing%20evidence.::agentbox%2Faudit.py%23recent%2Fverify%2Flist%2Fappend%2Finsert_record%2F_lock%20%2B%20agentbox%2Fweb.py%23note_login_failure%2Faudit%20and%20verify%20routes%20%2B%20agentbox%2Fapi.py%23%2Faudit%2Fverify%20%2B%20agentbox%2Fsandbox_desktop.py%23extract_novnc%2F_NOVNC_LOCK%20%2B%20agentbox%2Ftemplates%2Fsandbox.html%20%283%20s%20poll%29::Resource%20exhaustion%3A%20lock%20contention%20and%20pre-authentication%20work%20imbalance` (owner None)
- `Every%20HTTP%20request%20before%20routing%20and%20authentication%3A%20_BodyLimit%20ASGI%20middleware%20%28Content-Length%20and%20streamed%20bodies%2C%20upload%20path%20selection%29%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%20multipart%20form%20%2B%20the%20%2Fui%20upload%20form%20%2B%20deploy%2FCaddyfile%20request_body::Pre-authentication%20and%20per-request%20body%20caps%20%28F1%20fix%2C%20PR%20%2316%29%3A%20JSON%2Fform%20bodies%20capped%20at%20AGENTBOX_MAX_BODY%2C%20uploads%20at%20AGENTBOX_MAX_UPLOAD_BODY%20selected%20by%20method%20and%20path%20regex%2C%20multipart%20parsed%20only%20after%20screen_human.%20Invariant%3A%20an%20unauthenticated%20or%20agent%20client%20cannot%20make%20the%20server%20buffer%2C%20parse%20or%20spool%20more%20than%20the%20cap%20%28or%20hang%20a%20worker%29%20before%20auth%2C%20through%20any%20HTTP%20framing%20%28chunked%2C%20missing%20or%20duplicate%20Content-Length%2C%20path%20variants%2C%20HEAD%2Fother%20methods%2C%20root_path%29.::agentbox%2Fapi.py%23_BodyLimit%2F_UPLOAD_PATH%2Fput_files%2Fbuild%20%2B%20agentbox%2Fweb.py%23upload%20form%20%2B%20agentbox%2Fconfig.py%23max_body_bytes%2Fmax_upload_body_bytes%20%2B%20deploy%2FCaddyfile::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance` (owner h-bodylimit)
- `Every%20agent-reachable%20write%20to%20the%20shared%20control-plane%20SQLite%20file%20and%20host%20disk%20while%20AgentBox.disk_low%28%29%20is%20true%20or%20near%20the%20threshold%20%28tool%20calls%2C%20approval%20creation%2Fexpiry%2C%20GUI%20burst%20records%2C%20desktop%20and%20file%20routes%29%2C%20plus%20finished-approval%20row%20compaction::Disk-pressure%20guard%20and%20approval%20compaction%20%28PR%20%2320%29%3A%20call_tool%20refuses%20agent%20calls%20with%20507%20when%20free%20space%20on%20db_path.parent%20is%20below%20AGENTBOX_MIN_FREE%2C%20api.py%20skips%20the%20agent%20approval_forbidden%20row%2C%20_finish%20rewrites%20finished%20rows%27%20args%2Fpreview%20to%20the%20bounded%20audit%20shape%2C%20decide%20maps%20claim%20sqlite3.Error%20to%20503%20and%20expire_stale%20stops%20on%20sqlite3.Error.%20Invariant%3A%20an%20agent%20cannot%20keep%20growing%20the%20database%20or%20host%20disk%20past%20the%20guard%20through%20another%20route%2C%20and%20the%20human%20can%20still%20decide%2C%20delete%20and%20verify%20while%20low%3B%20compaction%20keeps%20what%20the%20approval%20card%20and%20audit%20need.::agentbox%2Fservice.py%23call_tool%2Fdisk_low%2F_finish%2Fdecide%2Fexpire_stale%2Flog_best_effort%20%2B%20agentbox%2Fapprovals.py%23finish%20%2B%20agentbox%2Fapi.py%23call_tool%20route%20%2B%20agentbox%2Fgui_bursts.py%23_finish%20%2B%20agentbox%2Fconfig.py%23min_free_bytes::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps` (owner h-approvals)
- `GUI%20burst%20stray-process%20decision%20at%20burst%20close%3A%20desktop_processes%20%28root%20ps%20%2B%20XRes%20window%20owners%20from%20a%20python3%20-I%20ctypes%20script%20run%20as%20the%20desktop%20user%20via%20docker%20exec%29%2C%20gui_strays%2Fgui_kept%2C%20and%20the%20per-sandbox%20kept%20set%20carried%20into%20the%20next%20burst%20baseline::Window%20ownership%20used%20to%20spare%20uid-1001%20processes%20from%20the%20stray%20kill%20now%20comes%20from%20the%20X%20server%20%28XResQueryClientIds%20client%20pid%20via%20SO_PEERCRED%29%20instead%20of%20the%20client-declared%20_NET_WM_PID%3B%20kept%20pids%20are%20excluded%20from%20the%20next%20baseline%20so%20they%20are%20re-judged.%20Invariant%3A%20a%20process%20the%20agent%20started%20during%20a%20burst%20cannot%20make%20itself%20or%20another%20process%20look%20window-owning%20or%20baseline%2C%20and%20any%20failure%20of%20the%20owner%20query%20fails%20toward%20stopping%20more%20processes.::agentbox%2Fsandbox_desktop.py%23_WINDOW_OWNERS%2Fdesktop_processes%20%2B%20agentbox%2Fgui_state.py%23_new_processes%2Fgui_strays%2Fgui_kept%20%2B%20agentbox%2Fgui_bursts.py%23open%2F_stop_strays%2F_kept::ATTACK-CLASSES.md%23Business%20logic` (owner h-xres)
- `Human%20lifecycle%20routes%20%28POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshot%7Crestore%2C%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%2C%20and%20the%20%2Fui%20equivalents%29%20racing%20the%20agent%20and%20human%20paths%20that%20do%20NOT%20take%20AgentBox._lifecycle%3A%20call_tool%2F_call_tool%2F_run_tool%20exec%20and%20file%20tools%2C%20_snapshot%20%28auto%20snapshot%20before%20destructive%20actions%29%2C%20decide%20%28approved%20run%29%2C%20import_file%2Fexport_file%2Fupload%2C%20takeover%2Fhandback%2C%20GUI%20bursts%20open%2Fclose%2C%20expire_stale%20and%20extract%2Fcapture%20paths::Agent%20and%20human%20actions%20versus%20sandbox%20lifecycle%20state%20after%20the%20F6%20fix%20%28PR%20%2318%29%3A%20_lifecycle%20%28service.py%3A500-505%29%20serialises%20only%20pause%2Fresume%2Fsnapshot%2Frestore%2Fdelete%2C%20while%20call_tool%2C%20decide%2C%20_snapshot%2C%20import_file%2C%20takeover%20and%20GUI%20bursts%20never%20take%20it.%20Invariant%3A%20after%20restore%20or%20delete%20returns%2C%20no%20agent%20or%20approved%20action%20writes%20to%2C%20snapshots%20or%20records%20results%20for%20the%20old%20container%20or%20a%20deleted%20sandbox%3B%20no%20snapshot%20row%20or%20image%20is%20orphaned%20or%20bound%20to%20the%20wrong%20container_id%3B%20and%20a%20lifecycle%20call%20cannot%20be%20starved%20or%20deadlocked%20by%20tool%20calls%2C%20takeover%20or%20burst%20close%20holding%20_snap_locks%2C%20gui_lock%20or%20concurrency%20slots%20%28and%20_life_locks%20does%20not%20grow%20without%20bound%29.::agentbox%2Fservice.py%23_lifecycle%2Fpause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%2F_snapshot%2Fdecide%2Fcall_tool%2F_busy%2F_snap_locks%2Fimport_file%20%2B%20agentbox%2Fsandbox.py%23restore%2Fdelete%2Fsnapshot%2Fpause%2Fresume%20%28status%20guards%2C%20container_id%20binding%2C%20snapshot%20rows%20and%20images%29%20%2B%20agentbox%2Fgui_bursts.py%23end%2Freset_timers%2Fclose%20under%20restore::Race%20and%20check-then-act%20on%20security-control%20state%20%28lifecycle%20and%20TOCTOU%20on%20container%20identity%29` (owner h-lifecycle)
- `agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20upgrade%20before%20ws.accept%28%29::agentbox%2Fapi.py%23desktop_ws%20async%20handler%3A%20synchronous%20SQLite%20%28session%2C%20lease%29%20and%20Docker%20SDK%20calls%20on%20the%20event%20loop%20before%20accept%20%2B%20agentbox%2Fdesktop_ws.py%23relay%20setup::agentbox%2Fapi.py%20%2B%20agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-ws)
- `agentbox%2Fcli.py%23agentbox%20prune%20--before%20--archive%20%5B--dry-run%5D%20%2B%20agentbox%20verify%20--archive%20%28host%20CLI%2C%20direct%20SQLite%29%20and%20every%20later%20AuditLog.verify%28%29%2Fappend%20over%20a%20pruned%20database::Audit-log%20tamper%20evidence%20across%20pruning%3A%20retention.prune%20drops%20and%20recreates%20the%20audit_no_delete%20trigger%20inside%20BEGIN%20IMMEDIATE%2C%20records%20an%20audit_anchor%20%28last%20id%2Fhash%2C%20archive%20sha256%29%20and%20an%20audit_pruned%20row%3B%20verify%28%29%20starts%20at%20the%20latest%20anchor%20and%20verify_archives%28%29%20chains%20GENESIS%20-%3E%20archives%20-%3E%20live%20table.%20Invariant%3A%20a%20deletion%20or%20edit%20of%20audit%20history%20that%20the%20prune%20command%20did%20not%20perform%20is%20still%20detected%2C%20prune%20never%20removes%20pending%2Fapproved%20approvals%20or%20rows%20at%2Fafter%20the%20cutoff%2C%20and%20a%20failed%20prune%20leaves%20the%20database%20and%20archive%20consistent.::agentbox%2Fretention.py%20%2B%20agentbox%2Faudit.py%23SCHEMA%2Faudit_anchor%2Flatest_anchor%2Fcheck_chain%2Fread_archive%2Finsert_record%2Fappend%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fcli.py%23cmd_prune%2Fcmd_verify::ATTACK-CLASSES.md%23Cryptography%20and%20secrets` (owner h-retention)
- `approvals%20table%20rows%20%28args%2C%20preview%2C%20result%29%20written%20for%20every%20REQUIRE_APPROVAL%20tool%20call::agentbox%2Fapprovals.py%23create%20stores%20raw%20agent%20args%20and%20preview%20for%20pending%20rows%20without%20audit%20masking%20or%20a%20size%20cap%20%28finish%20compacts%20them%20since%20PR%20%2320%29%2C%20rows%20outlive%20sandbox%20deletion%2C%20and%20only%20the%20host%20prune%20command%20removes%20finished%20rows::agentbox%2Fapprovals.py%20%2B%20agentbox%2Fservice.py%23_call_tool%2Fdecide%2Fdelete_sandbox%20%2B%20agentbox%2Fapi.py%23GET%20%2Fapprovals::DATA-ISOLATION-AND-LIFECYCLE.md%23Retention%20and%20queued-work%20overrun` (owner h-approvals)

# Your paths, sandbox and result contract

- Agent ID: `h-policy-cpu`. Audited source (read-only): `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` (git worktree of main at 346df29). Read it with Read/Grep/Glob or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `/home/user/agentbox/docs/security-audit/run-5/agents/h-policy-cpu/scratch/`. Retained artifacts: `/home/user/agentbox/docs/security-audit/run-5/agents/h-policy-cpu/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `/home/user/agentbox/docs/security-audit/run-5/tools/sbx h-policy-cpu <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable, 256 MiB loop mount), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target:/opt/userpy). Use `/usr/bin/python3.13` (host /usr mounted read-only; fastapi, docker SDK, jinja2, pyyaml, mcp importable). Write `/home/user/agentbox/docs/security-audit/run-5/agents/h-policy-cpu/scratch/h.py`, then run `/home/user/agentbox/docs/security-audit/run-5/tools/sbx h-policy-cpu /usr/bin/python3.13 /scratch/h.py > /home/user/agentbox/docs/security-audit/run-5/agents/h-policy-cpu/scratch/h.out 2>&1` (or have the script write its own file). Unit tests (cwd must be /target; pytest cannot write there, so pass --capture=sys): `/home/user/agentbox/docs/security-audit/run-5/tools/sbx h-policy-cpu /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_retention.py"`; the 120 s wall clock fits one file or a -k subset. Tests that need Docker skip or fail here; that is not evidence.
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/h-policy-cpu/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
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
