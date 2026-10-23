You are final record verifier `r-preview` in run-5 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound",
 "title": "Approval preview runs two untimed docker execs per rm operand, with no count or deadline, on a tool_pool thread before the approval exists",
 "description": "For an agent exec command that needs approval and contains an rm segment, preview_command calls expand(op) once per operand and, with -r, walk(m, limit) once per match. Each call is a synchronous docker exec_run in SandboxManager._expand/_walk with no container-side timeout. The display limit (200) truncates only the 'affected' list after every exec has run. Neither the API nor the service caps the operand count; the only bound is the 8 MiB body cap. One tool_pool thread is therefore held for a time proportional to the operand count (about 80 ms per exec, 2 execs per operand) before the 202 is returned. The pending-approval cap (service.py:326) is checked before the preview, so it does not throttle this. The parent-live run on the real Docker engine measured 399 exec_start events and 30.75 s to the 202 for a 200-operand command (about 1.6 KiB). Cost is linear: 50 operands took 8.05 s and 99 execs. Extrapolated, a 64 KiB command (32765 operands) holds the thread for about 87 minutes, and an 8 MiB command for days. This is a worker-occupancy and amplification problem. The live run saw no measurable delay of an allowed exec on a second sandbox (median 0.081-0.083 s against a 0.074-0.086 s baseline), so a Docker-daemon-wide slowdown is not established. The realistic impact is that a hostile agent pins its per-sandbox concurrency slots (4) and the same number of the shared 32 tool_pool threads for as long as it likes, from a single small request.",
 "root_cause": "preview_command loops over every rm operand and every glob match and calls the container callbacks with no call budget, total deadline, or early stop once 'limit' affected entries exist. _expand and _walk use plain c.exec_run without the _timed wrapper used by the manifest and read execs, so a single exec also has no container-side time bound. Neither call_tool nor _call_tool caps the operand count or the command length.",
 "intended_behavior": "Building the approval preview should cost a small bounded number of container execs and a bounded amount of time, then degrade to a note such as 'preview truncated, check the command text' and hand the approval to the human. A hostile command should not be able to hold a shared tool worker for an unbounded time before any approval exists.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "call_tool route (POST /sandboxes/{sid}/tools/{tool})",
   "description": "An agent token posts {\"args\":{\"command\":\"rm -r d d d ...\"}}, bounded only by the 8 MiB body cap. The route runs box.call_tool on the shared 32-thread tool_pool (api.py:160, 277-278). A client disconnect does not cancel the executor job."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 332,
   "scope": "AgentBox._call_tool",
   "description": "policy.decide (line 311) returns REQUIRE_APPROVAL (rm-curl-needs-approval, default_policy.yaml:12). After the pending cap check (line 326), self._preview (line 332, defined at 224-226) calls sandboxes.preview synchronously, before approvals.create. The per-sandbox concurrency limit in call_tool (lines 286-290) allows 4 such calls at once."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 586,
   "scope": "SandboxManager.preview",
   "description": "preview_command is called with lambdas bound to _expand and _walk on the live container."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 89,
   "scope": "preview_command",
   "description": "expand(op) runs for every operand (line 89). For every match with -r, walk(m, limit) runs (line 96). There is no budget, and the limit is applied only to the displayed list at lines 126-128."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 572,
   "scope": "SandboxManager._expand / _walk",
   "description": "Each call is c.exec_run(['sh','-c',...], user=AGENT_UID) with no _timed wrapper or timeout (_expand at 572, _walk at 577). That is one docker exec_create/start/inspect round trip per operand and per match, and the thread blocks until each returns."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/preview.py",
   "line": 96,
   "description": "walk(m, limit) runs once per match inside the per-operand loop. 'limit' bounds only each walk's output, not the number of walks."
  },
  {
   "file": "agentbox/preview.py",
   "line": 126,
   "description": "Truncation to 'limit' happens after all expand and walk execs have completed."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 376,
   "description": "The manifest exec uses _timed(_MANIFEST_TIMEOUT, ...), and the read execs at 449 and 553 use _timed(_READ_TIMEOUT, ...). _expand (572) and _walk (577) do not, so the preview execs have no timeout."
  },
  {
   "file": "agentbox/service.py",
   "line": 326,
   "description": "The pending-approval cap runs before the preview. The preview runs before approvals.create (line 337 onward), so the cap cannot throttle previews."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 27,
   "description": "touch and mkdir are in the allow-listed exec set, so an agent can also create many workspace entries without approval and send 'rm -r *' (one walk exec per entry)."
  },
  {
   "file": "agents/parent-live/artifacts/preview_exec.json",
   "line": 1,
   "description": "Real Docker engine, runc, ubuntu:24.04. 50 operands gave status 202 in 8.05 s with 99 exec_start events (81.28 ms per exec). 200 operands gave status 202 in 30.75 s with 399 exec_start events (77.08 ms per exec). A concurrent allowed 'ls' on a second sandbox had median 0.081-0.083 s and max 0.122 s, against a baseline of 0.074-0.086 s."
  },
  {
   "file": "agents/v-preview/scratch/count.py",
   "line": 1,
   "description": "Independent stub-callback check in the sandbox, run on the audited tree. 200 operands gave 200 expand and 200 walk calls, and 4000 operands gave 4000 and 4000, while the returned 'affected' list was truncated to 200."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "A valid agent token for the sandbox (the lowest-trust network principal in the threat model, assumed prompt-injected)."
  },
  {
   "kind": "data_state",
   "description": "The sandbox is running and has fewer than 20 pending approvals. The command must be classified REQUIRE_APPROVAL by the default policy, for example an rm segment with the operands repeated. The operand 'd' needs to exist (an allowed 'mkdir d' creates it) for walk to run per operand."
  },
  {
   "kind": "environmental_dependency",
   "description": "The impact on other principals depends on tool_pool saturation (32 threads, 4 per sandbox). One hostile sandbox pins at most 4 threads, so starving other sandboxes needs several hostile sandboxes. The human API runs on the Starlette threadpool, not tool_pool."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding its own sandbox's agent token and using the normal tool API.",
  "payloads": [
   "POST /sandboxes/{sid}/tools/exec {\"args\":{\"command\":\"mkdir d\"}} (allowed), then POST /sandboxes/{sid}/tools/exec {\"args\":{\"command\":\"rm -r d d d ... d\"}} with N repeated operands (N=200 was measured, about 1.6 KiB)",
   "Alternative: create many files with allowed 'touch', then send 'rm -r *'"
  ],
  "instructions": [
   "In a disposable loopback control plane (dummy tokens, default policy, one runc sandbox from ubuntu:24.04), have the agent run the allowed 'mkdir d'.",
   "Send the exec call with command 'rm -r ' followed by N copies of 'd'. Time the request until the 202 and count exec_start events with docker events.",
   "Repeat with N=50 and N=200 and compare. Do not run large inputs; extrapolate linearly."
  ],
  "observed_result": "Parent-live run on the real Docker engine: N=50 took 8.05 s to the 202 with 99 exec_start events, and N=200 took 30.75 s with 399 events, about 77-81 ms per exec and 2 execs per operand. The response time is linear in the operand count and the thread is held for the whole time. Another sandbox's allowed 'ls' showed no measurable delay in that run. Larger sizes (64 KiB, 8 MiB) were not run, and the durations quoted for them are linear extrapolations."
 },
 "remediation": {
  "strategy": "Bound the preview work in preview_command. Cap the total number of expand and walk calls (for example 20-50) and the operand count. Stop once 'limit' affected entries exist. Deduplicate repeated operands and matches. Add an overall deadline, and on exceeding any bound append a note that the preview is incomplete and hand the approval to the human. Also use the _timed wrapper (or exec_run with a timeout) for _expand and _walk. Optionally reject or truncate exec commands over a few KiB before policy and preview.",
  "code_changes": [
   {
    "file_name": "agentbox/preview.py",
    "fixed_code": "MAX_CALLS = 40\n# inside preview_command: calls = 0; deadline = time.monotonic() + 10\n# before each expand(op) / walk(m, limit):\n#   if calls >= MAX_CALLS or time.monotonic() > deadline or len(affected) >= limit:\n#       notes.append('operand/match count exceeds the preview budget; remaining items not checked')\n#       break\n#   calls += 1"
   },
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "# use c.exec_run(_timed(_READ_TIMEOUT, \"sh\", \"-c\", script, \"_\", pattern), user=AGENT_UID, demux=True) in _expand and _walk, treating exit 124/137 as a preview failure note"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Any agent token can trigger it with one small ordinary request (no tooling beyond rm and repeated operands), and the policy does not stop it. The intended threat model assumes a prompt-injected agent."
  },
  "impact": {
   "score": "low",
   "reason": "Observed: roughly 77-81 ms per exec, about 31 s of thread occupancy for 200 operands, growing linearly without a bound. The effect is pinning up to 4 of the 32 shared tool_pool threads per hostile sandbox, plus about 12 docker execs per second on the daemon per thread. The live run showed no measurable slowdown of another sandbox, and the human API does not use tool_pool. Starving other tenants needs several hostile sandboxes, and the host is not compromised."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The unbounded call count and missing timeout are directly visible in source, and were reproduced with stub callbacks. The real-engine run confirms linear scaling with 2 execs per operand and the held request time up to 200 operands. The 64 KiB and 8 MiB durations and the multi-sandbox saturation are extrapolated, not observed. The no-impact result for a second sandbox is from one small run."
 }
}
```

# Phase 5 procedure (verbatim)

```text
### Phase 5: Verify the final records with fresh eyes

Launch one fresh `research` verifier per final `confirmed` and `needs_validation` record, in parallel. This verifier checks the structured record, not the hunter write-up, and remains inside source/local boundaries.

In a `quick` run, Phase 3 and Phase 5 merge: the Phase 3 verifier also performs these record checks and returns the final schema-shaped record, so each candidate gets one fresh independent reviewer instead of two. Every other profile keeps the two passes separate. Never skip independent review of a `confirmed` record in any profile.

For `confirmed`, require it to check:

1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.

For `needs_validation`, require it to check:

1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.

Each verifier returns exactly one JSON object: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","reason":"...","record":{...}}`, with no surrounding prose. A replacement record must match its `confirmed`, `needs_validation`, or `rejected` schema branch. Treat a malformed or prose-wrapped Phase 5 result the same way as in Phase 3: discard it without repairing it and re-run with a fresh verifier when the budget permits.

Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict, including any promotion to `confirmed`, or materially changes the root cause, trace, execution input or observed result, demonstrated impact, or severity. Give that complete replacement to a new independent verifier that did not hunt, perform Phase 3 validation, or propose the Phase 5 replacement. The new verifier rechecks the current source and independently reproduces any decisive local result under the execution boundary, then returns `verified` or another replacement. Apply a material replacement only after this fresh verification. If another material replacement results, repeat with a fresh verifier. If budget or independence is unavailable, remove the disputed record from `findings.json`, keep its ledger unit as an unresolved candidate, and set `run_status: "incomplete"` with an exact `incomplete_reason`. Non-material wording or repository-line corrections may be applied directly when they do not change meaning or evidence.

After every applied replacement, rerun both validators and update linked ledger decisions. If a final verifier identifies a separate root cause, assign a new fingerprint and send it through independent candidate validation before inclusion. Set `run_status: "complete"` only when every ledger candidate has an independent final disposition and every retained record passes Phase 5.

Do not verify only `confirmed` records. A misleading `needs_validation` handoff wastes owner time and can preserve a false premise.
```

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
| 

# Relevant companion blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation -->
**Superlinear parsing, matching, or evaluation**
Small accepted input drives catastrophic regex backtracking, nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort/hash behavior. Derive accepted depth/cardinality and complexity, then demonstrate a bounded growth curve locally.

# Execution boundary and paths

- Agent ID `r-preview`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/r-preview/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx r-preview <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3.13`.
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx r-preview /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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

# Parent note

The Phase 3 verifier cited its scratch harness `agents/v-preview/scratch/count.py`; scratch is not retained, so the parent promoted it to `agents/v-preview/artifacts/count.py`. Check the evidence path against the promoted copy.
