You are candidate verifier `v03` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
 "title": "Agent-grown audit and approval rows in the shared control-plane SQLite file have no aggregate bound or retention, so an agent can fill the host disk and the only recovery breaks the audit chain",
 "description": "Every agent tool call appends two audit rows (tool_request, policy_decision) and risky calls add an approval_requested row plus an approvals-table row; args are capped per record but nothing bounds the tables, and no code path deletes audit rows. A prompt-injected agent that loops allowed tool calls with 80 KB arguments adds about 30 KB per call to data/agentbox.db on the host volume, permanently. When the volume fills, AuditLog.append raises AuditWriteError, which service.py converts to 503 for tool calls, human lifecycle, approvals and handbacks, so the whole control plane stops rather than only the offending sandbox. The only way to reclaim space (deleting old audit rows or the file) permanently trips the id/prev_hash checks, so capacity recovery and audit integrity cannot both be kept.",
 "claimed_root_cause": "The audit table is append-only by design (audit.py:35-38) and the per-record arg cap (service.py:37-38, 181-194) is the only bound on agent-driven growth; there is no aggregate quota, retention window, pruning command or size check, and approvals rows holding the full unmasked args are likewise never deleted. The shared SQLite file used by all four components (api.py:86-94, config.py:85-86) therefore has host disk as its only limit, and audit.py:229-236 rejects any prefix deletion, so the recovery path and the integrity contract are mutually exclusive.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "An agent token calls a tool with agent-controlled body.args; api.py has no request-body cap for tool args (only the upload route at api.py:278-283 is capped)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 295,
   "scope": "_call_tool",
   "description": "tool_request is appended with _logged_args(args) and policy_decision is appended right after; both happen before any snapshot or execution."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 189,
   "scope": "_logged_args",
   "description": "Only the single record is bounded: blobs over 64 KiB are replaced by a 16 KiB head plus size and sha256, measured at 30,076 bytes per two-row call."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 324,
   "scope": "_call_tool approval creation",
   "description": "REQUIRE_APPROVAL stores the full raw args and preview in the approvals table (approvals.py:49-59); PENDING_APPROVALS_MAX=20 limits concurrency only, and expired or decided rows are never removed."
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 179,
   "scope": "AuditLog.append",
   "description": "The row is inserted into the same SQLite file; the append-only triggers at audit.py:35-38 make it permanent and there is no retention job in the repository."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 592,
   "scope": "log_human",
   "description": "At disk-full every append raises AuditWriteError, which becomes 503 for human lifecycle, import/export and tool calls, so the blast radius is all sandboxes rather than the agent's own process."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 230,
   "scope": "AuditLog.verify",
   "description": "Reclaiming space by deleting the oldest rows makes the first surviving row fail the expected_id or prev_hash check, so /audit/verify reports a broken chain permanently after any capacity recovery."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 35,
   "description": "Append-only triggers abort every UPDATE and DELETE; the local fixture reproduced both rejections."
  },
  {
   "file": "agentbox/audit.py",
   "line": 229,
   "description": "verify() requires ids to start at 1 and each prev_hash to chain, so prefix deletion is indistinguishable from tampering."
  },
  {
   "file": "agentbox/service.py",
   "line": 37,
   "description": "LOGGED_ARGS_MAX/LOGGED_ARGS_HEAD are the only size controls and they are per record, not per table or per sandbox."
  },
  {
   "file": "agentbox/service.py",
   "line": 182,
   "description": "The author comment states the log cannot be deleted and that an agent growing it with large args cannot be undone."
  },
  {
   "file": "agentbox/service.py",
   "line": 106,
   "description": "drop_captures removes only capture PNGs; approval rows, their full args and preview survive sandbox deletion."
  },
  {
   "file": "agentbox/config.py",
   "line": 44,
   "description": "snapshot_quota exists specifically so an agent cannot fill host disk with docker commits without a human, showing the intended invariant that agent actions are host-disk bounded."
  },
  {
   "file": "agentbox/approvals.py",
   "line": 49,
   "description": "create() stores the full raw args JSON with no cap; the fixture measured 416,120 bytes for 400 KB args and no deletion path exists."
  },
  {
   "file": "agentbox/api.py",
   "line": 86,
   "description": "AuditLog, SandboxManager, ApprovalStore and DesktopControl share one file, settings.db_path (config.py:85-86, default ./data/agentbox.db)."
  },
  {
   "file": "agentbox/web.py",
   "line": 206,
   "description": "Each 2-second UI poll materialises every historical approval row with full args and preview, so retained rows also cost control-plane memory and DB read time."
  }
 ],
 "blockers": [
  "Free space on the host volume holding data/agentbox.db and the deployment's expected lifetime are outside the repository; no size quota or disk check exists in code (config.py:85-86).",
  "Whether operators prune or rotate the SQLite file out of band is a deployment fact; the product cannot do it without permanently failing /audit/verify, so the acceptable trade-off is an owner decision."
 ],
 "validation_plan": {
  "local": "Already performed and retained as agents/h-audit/artifacts/h.out: 80 records in a scratch DB measured 30,076 bytes per max-size tool call and 9,476 bytes per 'ls' call, DELETE/UPDATE rejected by the triggers, and 5 approval rows of 400 KB args measured 416,120 bytes each.",
  "deployment": "Owner-observed on a disposable deployment: record free space on the data/agentbox.db volume, run 1,000 allowed exec calls from one agent token with 80 KB commands, then compare the DB size delta with the free-space budget and confirm whether any operator retention or rotation exists for that file."
 },
 "x_proposed_by": "h-audit"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Host-disk%20and%20SQLite%20pressure%20caused%20by%20agent%20actions%20%28audit%20rows%2C%20approval%20rows%2C%20captures%20PNGs%2C%20docker%20commit%20snapshots%2C%20sources%20dirs%29%20and%20by%20human%20read%20paths%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20%2Fui%2Fverify%2C%20%2Faudit%2Fverify%2C%20cmd_verify%2C%20GET%20%2Fapprovals%29::Agent-grown%20data%20-%3E%20one%20process-wide%20audit%20lock%20and%20one%20SQLite%20file%20shared%20by%20four%20connections%20%28AuditLog%2C%20ApprovalStore%2C%20SandboxManager%2C%20DesktopControl%29.%20AuditLog.verify%28%29%20and%20list%28%29%20run%20fetchall%20of%20the%20whole%20table%20under%20the%20same%20lock%20that%20every%20append%20needs%20%28agentbox%2Faudit.py%3A196-215%2C%20152-187%29.%20_safe_log%20swallows%20AuditWriteError%20after%20execution%20%28agentbox%2Fservice.py%3A362-369%29%2C%20while%20_close_gui_burst%20has%20already%20popped%20the%20burst%20before%20logging%20gui_changes%20or%20gui_processes_stopped.%20ApprovalStore%20claim%2C%20finish%20and%20create%20raise%20raw%20sqlite3%20errors%20%28approvals.py%3A49-92%29%2C%20not%20AuditWriteError.::agentbox%2Faudit.py%23append%20%2B%20list%20%2B%20verify%3B%20agentbox%2Fservice.py%23_safe_log%20%2B%20_close_gui_burst%20%2B%20decide%20%2B%20expire_stale%3B%20agentbox%2Fapprovals.py%23create%2Fclaim%2Ffinish%3B%20agentbox%2Fapi.py%23list_audit%2Fverify%3B%20agentbox%2Fweb.py%23verify_frag%2Faudit_frag::Failure%20and%20recovery%20under%20resource%20exhaustion%3A%20read-side%20lock%20hold%20time%20and%20memory%20on%20the%20shared%20audit%20lock%3B%20fail-closed%20%28503%29%20versus%20fail-open%20%28silently%20dropped%20post-hoc%20records%2C%20approvals%20stuck%20in%20approved%29%20behaviour%20at%20disk-full%20or%20lock%20contention",
  "surface": "Host-disk and SQLite pressure caused by agent actions (audit rows, approval rows, captures PNGs, docker commit snapshots, sources dirs) and by human read paths (GET /audit, /ui/audit, /ui/verify, /audit/verify, cmd_verify, GET /approvals)",
  "boundary": "Agent-grown data -> one process-wide audit lock and one SQLite file shared by four connections (AuditLog, ApprovalStore, SandboxManager, DesktopControl). AuditLog.verify() and list() run fetchall of the whole table under the same lock that every append needs (agentbox/audit.py:196-215, 152-187). _safe_log swallows AuditWriteError after execution (agentbox/service.py:362-369), while _close_gui_burst has already popped the burst before logging gui_changes or gui_processes_stopped. ApprovalStore claim, finish and create raise raw sqlite3 errors (approvals.py:49-92), not AuditWriteError.",
  "local_checks": [
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/service.py"
    ],
    "invariant": "Agent-grown audit rows have an aggregate bound or retention, so one prompt-injected agent cannot grow the shared SQLite file without limit; a per-record cap on args is not an effective bound.",
    "method": "local",
    "result": "AuditLog fixture: 40 tool-call record pairs written with the largest args the audit path accepts (exec command of 80,000 bytes -> args_head exactly 16,384 bytes) added 30,076 bytes per call; the same pairs with {command: ls} added 9,476 bytes per call; growth is linear and no code path ever removes rows. DELETE FROM audit and UPDATE audit are both rejected by the append-only triggers ('audit log is append-only'). grep shows no retention, VACUUM, size or count quota for the audit table anywhere in agentbox/. service.py:182-183 states the authors' own premise that this log cannot be deleted and that an agent growing it is irreversible.",
    "artifact": "agents/h-audit/artifacts/h.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/approvals.py",
     "agentbox/service.py"
    ],
    "invariant": "Approval rows (which hold the full, unmasked agent args) are size-bounded and are removed on decision, expiry and sandbox deletion.",
    "method": "local",
    "result": "ApprovalStore on the same DB file stored 400,000-byte exec args as 416,120 bytes per row (5 rows). No DELETE FROM approvals exists anywhere in agentbox/ (the only prunes are ui_tickets/ui_sessions/takeover_leases in desktop.py), and the delete path only unlinks capture PNGs (service.py:106-109, 471-475). Rows therefore survive approve/deny/expire and sandbox deletion. web.py:206-211 loads every historical row with full args/preview JSON every 2 s per open UI page and keeps the last 5, so retained rows also amplify read work.",
    "artifact": "agents/h-audit/artifacts/h.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/audit.py"
    ],
    "invariant": "Human audit read paths clamp their cost on the shared audit lock (limit is an upper bound, not a hint).",
    "method": "local",
    "result": "api.py:269 applies min(limit, 5000), which does not clamp negatives: list(limit=-1) returned all 160 rows of the fixture (SQLite LIMIT -1 means no limit), so a single GET /audit?limit=-1 would decode the whole table into memory while holding AuditLog._lock. Reachable only with the human bearer token (api.py:115-129), so this is an operator self-cost rather than a cross-principal attack.",
    "artifact": "agents/h-audit/artifacts/h.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/web.py",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "Read-side lock hold on the single audit lock is O(window), so monitoring reads cannot stall every agent append as the table grows.",
    "method": "source",
    "result": "recent() performs COUNT(*) plus the sandbox-filtered ORDER BY id DESC LIMIT 400 inside 'with self._lock' (audit.py:212-217); verify() does fetchall of the whole table inside the same lock (audit.py:225-228); the SCHEMA creates no index besides the INTEGER PRIMARY KEY (audit.py:23-34), so the sandbox filter and status scan are full scans. audit.py:158-186 shows append needs that same lock. templates/sandbox.html:19 re-issues /ui/audit every 3 s and web.py:265-269 serves it, so each open sandbox page holds the append lock for a full-table COUNT(*) every 3 s; growth caused by the agent therefore lengthens a lock hold that blocks the agent's own fail-closed appends."
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/api.py",
     "agentbox/gui_bursts.py"
    ],
    "invariant": "Audit-write failure is fail-closed before execution and cannot silently discard the only record of an action (GUI burst changes and stray kills) after it ran.",
    "method": "local",
    "result": "Harness on the real AgentBox.log_best_effort with an audit stub that raises: AuditWriteError is swallowed after exactly one append attempt and no record is written; a RuntimeError from append is not swallowed and escapes. gui_bursts.py:107-111 deletes self._gui_burst[sid] before _finish() calls self._log (gui_bursts.py:130-135, 90-92), so a swallowed failure leaves no gui_changes/gui_processes_stopped row and no retry state. Fail-closed holds for the next call (service.py:295-306, 590-594 raise 503), and handback/takeover/export refuse to proceed without a record (service.py:536-541, 497-500).",
    "artifact": "agents/h-audit/artifacts/h3.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/service.py"
    ],
    "invariant": "Rejected agent requests cannot add uncapped rows to the audit log.",
    "method": "source",
    "result": "api.py:252-259 appends an approval_forbidden row for every agent attempt to POST /approvals/{aid} and swallows only append errors, so this is one more agent-driven row source with no rate or count bound; it feeds the same unbounded table as tool calls."
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/approvals.py",
     "agentbox/service.py"
    ],
    "invariant": "Approval state cannot remain in a non-terminal state after a partial failure (claim-then-execute is recoverable).",
    "method": "source",
    "result": "decide() claims the row to 'approved' (approvals.py:82-89) before snapshot and execution (service.py:395-418). Every exception path calls finish(FAILED), but a control-plane crash or OOM between claim and finish leaves the row 'approved' forever: expire_stale only scans PENDING (service.py:375-388), so nothing ever revisits it and the agent's GET /approvals/{aid} reports an approval that never executed. No privilege effect; recovery gap only."
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-3 wording)

```json
- none
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

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

# Relevant companion blocks (verbatim)

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

- Agent ID `v03`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v03/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v03 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v03 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
