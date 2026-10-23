You are candidate verifier `v-lifecycle` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:SandboxManager.snapshot:delete-race-orphaned-snapshot-image",
 "title": "Agent pre-write snapshot that is still committing when the human deletes the sandbox leaves an untracked snapshot image and a snapshot record for the deleted sandbox",
 "description": "delete_sandbox holds only the per-sandbox _lifecycle lock. The agent's automatic snapshot before a destructive tool (call_tool -> _call_tool -> _snapshot, holding only _snap_locks), the approved-run snapshot in decide, and the import_file snapshot never take that lock. SandboxManager.snapshot checks the deleted status once in _container, then runs a multi-second docker commit, then inserts the snapshot row without checking status again. If the human's DELETE runs during the commit, delete removes the container, marks the sandbox deleted and removes the snapshot images it can list, then returns. The commit then finishes: a snapshot row is inserted for the deleted sandbox, the system writes a 'snapshot' audit row after 'sandbox_delete', and the committed image (the agent's whole writable layer, which the agent can make large with many write_file calls) stays on the host Docker disk. Nothing removes it unless someone issues DELETE again for the already-deleted id, and the UI hides deleted sandboxes. A sandboxed schedule with real agentbox code and a fake Docker client reproduced this end to end. The one fact not established here is whether real dockerd lets an in-flight commit finish while 'docker rm -f' removes the container.",
 "claimed_root_cause": "Snapshot creation is check-then-act on the sandbox status (sandbox.py:351 _container check, :355 commit, :358-362 unconditional INSERT) and is not serialised with delete_sandbox (service.py:538-543 under _lifecycle only). SandboxManager.delete (sandbox.py:320-332) cleans up only the snapshot rows that exist when it runs list_snapshots, so a commit that completes after that point is never cleaned up.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "POST /sandboxes/{sid}/tools/{tool} (agent token)",
   "description": "Agent calls write_file on an existing path (allowed by default policy, which snapshots on overwrite) or another SNAPSHOT_TOOLS tool; runs on tool_pool via box.call_tool."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 292,
   "scope": "AgentBox.call_tool",
   "description": "Takes the per-sandbox _snap_locks lock (not _lifecycle) and enters _call_tool."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 367,
   "scope": "AgentBox._call_tool",
   "description": "The allow path with _needs_snapshot true calls _snapshot before running the tool (decide at service.py:467 and import_file at :555 reach the same call)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 351,
   "scope": "SandboxManager.snapshot",
   "description": "_container checks status != deleted once and returns the container handle."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 355,
   "scope": "SandboxManager.snapshot",
   "description": "A multi-second docker commit runs. Meanwhile the human DELETE runs delete_sandbox -> SandboxManager.delete: removes the container (:323), sets status deleted (:326), and removes the images of the snapshot rows that exist so far (:328-332)."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 359,
   "scope": "SandboxManager.snapshot",
   "description": "After the commit returns, the snapshot row is inserted for the deleted sandbox with no status re-check. Its image is never removed, and _snapshot (service.py:269) appends a 'snapshot' audit record after the delete."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 500,
   "description": "_lifecycle is the only per-sandbox serialisation for delete; call_tool, decide and import_file never acquire it."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 328,
   "description": "delete removes only the images of snapshot rows that exist when list_snapshots runs."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 358,
   "description": "The snapshot INSERT runs after the commit with no deleted-status check, unlike restore's conditional UPDATE at sandbox.py:401-406."
  },
  {
   "file": "agentbox/service.py",
   "line": 269,
   "description": "_snapshot writes the 'snapshot' audit row for the sandbox regardless of its current status."
  }
 ],
 "blockers": [
  "Real Docker 29.9.1 behaviour is not observable in the sandbox (no Docker socket). The local check assumed that a 'docker commit' already in progress (pause=True) completes and keeps its image when the same container is force-removed concurrently (container rm -f during commit). If dockerd instead fails the commit, or blocks the remove until the commit ends and the remove still lands before the INSERT, the orphan does not occur in practice.",
  "Local harness output (agents/h-lifecycle/artifacts/h.out) uses a fake Docker client. It shows the agentbox-side logic only."
 ],
 "validation_plan": {
  "local": "Parent-live, disposable loopback setup with a dummy human token: run 'agentbox serve' with the cli template and default policy, then create a sandbox. With the agent token, write /workspace/a.txt, then write many new 8 MiB files with write_file (about 1-2 GiB total, no snapshots) so that the commit takes several seconds. Start POST /sandboxes/{sid}/tools/write_file {path:/workspace/a.txt, content:'x'} with the agent token. About 0.5 s later, while 'docker ps' shows the container paused by the commit, send DELETE /sandboxes/{sid} with the human token and wait for both to return. Observe the result in three places: (1) 'docker images agentbox-snap --filter label=agentbox.sandbox=<sid>' lists an image after DELETE returned 204; (2) sqlite 'SELECT * FROM snapshots WHERE sandbox_id=<sid>' has a row while sandboxes.status='deleted'; (3) GET /audit shows a system 'snapshot' event after human 'sandbox_delete'. Repeat with delays of 0.1, 0.5 and 2 s. Then clean up by sending DELETE again (which removes the orphan) and running 'docker image rm'."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Human%20lifecycle%20routes%20%28POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshot%7Crestore%2C%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%2C%20and%20the%20%2Fui%20equivalents%29%20racing%20the%20agent%20and%20human%20paths%20that%20do%20NOT%20take%20AgentBox._lifecycle%3A%20call_tool%2F_call_tool%2F_run_tool%20exec%20and%20file%20tools%2C%20_snapshot%20%28auto%20snapshot%20before%20destructive%20actions%29%2C%20decide%20%28approved%20run%29%2C%20import_file%2Fexport_file%2Fupload%2C%20takeover%2Fhandback%2C%20GUI%20bursts%20open%2Fclose%2C%20expire_stale%20and%20extract%2Fcapture%20paths::Agent%20and%20human%20actions%20versus%20sandbox%20lifecycle%20state%20after%20the%20F6%20fix%20%28PR%20%2318%29%3A%20_lifecycle%20%28service.py%3A500-505%29%20serialises%20only%20pause%2Fresume%2Fsnapshot%2Frestore%2Fdelete%2C%20while%20call_tool%2C%20decide%2C%20_snapshot%2C%20import_file%2C%20takeover%20and%20GUI%20bursts%20never%20take%20it.%20Invariant%3A%20after%20restore%20or%20delete%20returns%2C%20no%20agent%20or%20approved%20action%20writes%20to%2C%20snapshots%20or%20records%20results%20for%20the%20old%20container%20or%20a%20deleted%20sandbox%3B%20no%20snapshot%20row%20or%20image%20is%20orphaned%20or%20bound%20to%20the%20wrong%20container_id%3B%20and%20a%20lifecycle%20call%20cannot%20be%20starved%20or%20deadlocked%20by%20tool%20calls%2C%20takeover%20or%20burst%20close%20holding%20_snap_locks%2C%20gui_lock%20or%20concurrency%20slots%20%28and%20_life_locks%20does%20not%20grow%20without%20bound%29.::agentbox%2Fservice.py%23_lifecycle%2Fpause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%2F_snapshot%2Fdecide%2Fcall_tool%2F_busy%2F_snap_locks%2Fimport_file%20%2B%20agentbox%2Fsandbox.py%23restore%2Fdelete%2Fsnapshot%2Fpause%2Fresume%20%28status%20guards%2C%20container_id%20binding%2C%20snapshot%20rows%20and%20images%29%20%2B%20agentbox%2Fgui_bursts.py%23end%2Freset_timers%2Fclose%20under%20restore::Race%20and%20check-then-act%20on%20security-control%20state%20%28lifecycle%20and%20TOCTOU%20on%20container%20identity%29",
  "surface": "Human lifecycle routes (POST /sandboxes/{sid}/pause|resume|snapshot|restore, DELETE /sandboxes/{sid}, and the /ui equivalents) racing the agent and human paths that do NOT take AgentBox._lifecycle: call_tool/_call_tool/_run_tool exec and file tools, _snapshot (auto snapshot before destructive actions), decide (approved run), import_file/export_file/upload, takeover/handback, GUI bursts open/close, expire_stale and extract/capture paths",
  "boundary": "Agent and human actions versus sandbox lifecycle state after the F6 fix (PR #18): _lifecycle (service.py:500-505) serialises only pause/resume/snapshot/restore/delete, while call_tool, decide, _snapshot, import_file, takeover and GUI bursts never take it. Invariant: after restore or delete returns, no agent or approved action writes to, snapshots or records results for the old container or a deleted sandbox; no snapshot row or image is orphaned or bound to the wrong container_id; and a lifecycle call cannot be starved or deadlocked by tool calls, takeover or burst close holding _snap_locks, gui_lock or concurrency slots (and _life_locks does not grow without bound).",
  "local_checks": [
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "After DELETE /sandboxes/{sid} returns, no agent pre-destructive snapshot is recorded for the deleted sandbox and no snapshot image is left behind (delete_sandbox vs call_tool -> _snapshot, which holds only _snap_locks, not _lifecycle).",
    "method": "local",
    "result": "Deterministic schedule with real AgentBox/AuditLog/ApprovalStore/SandboxManager code (sqlite in scratch) and a fake Docker client whose commit blocks until released: agent call_tool(write/delete_file) entered SandboxManager.snapshot (status check via _container at sandbox.py:351 passed, commit at :355 in progress); human delete_sandbox ran and returned (status=deleted, snapshot_rows=[], images=[]). When the commit then completed, sandbox.py:358-362 inserted snapshot row snap_6a3f7373 for the deleted sandbox, the image agentbox-snap:sb_1-snap_6a3f7373 remained in the (fake) daemon, and the audit log shows system 'snapshot' (id 4) after human 'sandbox_delete' (id 3), then tool_error 'deleted sandbox'. A second DELETE on the deleted id removes the orphan (sandboxes.delete has no deleted-status guard), but nothing triggers it. Whether real dockerd lets an in-flight commit finish while 'rm -f' removes the container is not established locally -> needs_validation.",
    "artifact": "agents/h-lifecycle/artifacts/h.out"
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/sandbox.py",
     "agentbox/approvals.py"
    ],
    "invariant": "After restore returns, no agent/approved/human-import action writes to or snapshots the old container, and snapshot rows are attributed correctly.",
    "method": "source",
    "result": "No container identity is carried from check to use: _snapshot (service.py:261-276), _run_tool (service.py:129-161) and sandbox tool methods re-resolve container_id from the DB per call (_container sandbox.py:225-232, _require_running :343-347). An in-flight exec/write that already resolved the old container hits it before removal (harmless, state discarded) or fails with a docker NotFound/APIError; one resolved after restore's UPDATE (sandbox.py:401-403) runs on the restored container, which the agent may do anyway with its still-valid token. Snapshot rows carry only sandbox_id (sandbox.py:63-69), so a commit of the old container completing across restore is correctly attributed to sid and is listable/removable by later delete. Variant gap (hardening, not a boundary result): the pre-destructive snapshot taken for an in-flight write/decide/import_file may be of the old container rather than the restored state being overwritten; the overwritten content still exists in the restore-source snapshot. Pending approvals survive restore (restore_sandbox service.py:528-536 does not expire them) and execute on the restored container with a preview/capture computed on the old one; the agent can already change files between preview and approval, so restore adds no agent advantage.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/gui_bursts.py",
     "tests/test_m2_unit.py"
    ],
    "invariant": "GUI bursts are never bound to a container other than the one the covered GUI input runs on, across restore.",
    "method": "source",
    "result": "GuiBursts.open (gui_bursts.py:73-87) takes no burst lock and is not fenced by _lifecycle. Schedule: agent GUI input is inside _snapshot's commit (service.py:264) when restore_sandbox runs end_desktop -> bursts.end (finds no burst; _snapshot closed it at :263); open then reads the old container_id and baseline from the old container before restore removes it (sandbox.py:395); restore installs the new container and reset_timers; the input's _run_tool (service.py:141-150) passes covers() (gui_bursts.py:68-71 checks only sid in _gui_burst, not container_id) and clicks on the restored container. That single input is covered by a burst whose close reports gui_burst_close_failed 'container replaced' (gui_bursts.py:132-136; intended per tests/test_m2_unit.py:247-257) with no stray kill or gui_changes, and the next burst's baseline includes what it started. Reach of one input on a freshly reset desktop is minimal and the window is narrow (open must finish between end_desktop and the docker remove), so recorded as hardening, not a candidate. Restore that closes a burst opened earlier is fail-closed (end closes it; covers() then refuses).",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/gui_bursts.py",
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "A lifecycle call cannot be deadlocked or starved by tool calls, takeover or burst close holding _snap_locks, gui_lock, burst locks or concurrency slots, and _life_locks does not grow without bound from a lower-trust principal.",
    "method": "source",
    "result": "Lock order inside _lifecycle (service.py:499-504): life -> audit lock (log_human) -> burst lock (end -> close, gui_bursts.py:117-128) -> gui_lock via handback's _gui_locked with a 30 s timeout whose ServiceError end_desktop swallows (service.py:647-655). No tool, decide, takeover or burst path ever takes _life_locks, and lifecycle never takes _snap_locks or _busy, so no cycle exists. The agent can delay a lifecycle call only by a burst close in progress (bounded by _timed X and manifest execs, sandbox.py:376 30 s) or by holding gui_lock (bounded by GUI_LOCK_WAIT=30); new closes need new bursts, which need quota-limited snapshots. All lifecycle routes are human_only/browser_human (api.py:248-269, web.py:270-287), so _life_locks keys (created before any existence check, service.py:502) come only from the human principal; _snap_locks/_busy keys are created per authenticated call, and an agent is fixed to its own sid. Growth is human-driven only: hardening.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "Every SandboxManager method that snapshots, resumes, pauses or execs refuses a deleted sandbox.",
    "method": "source",
    "result": "restore checks deleted explicitly (sandbox.py:389) and re-checks with a conditional UPDATE (:401-406). snapshot, pause, resume, workspace_manifest go through _container (sandbox.py:225-228, deleted -> SandboxError); exec/list_dir/read/write/delete/upload/is_dir/outbox and desktop tools go through _require_running/_desktop -> _container (sandbox.py:343-347, sandbox_desktop.py:64-67). delete has no guard, which keeps it idempotent. The guards are check-then-act: a status check passed before a concurrent delete does not stop the in-flight docker call, so the commit race in check 1 is the remaining gap.",
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

- `agents/parent-live/artifacts/delete_commit.json`
- `agents/parent-live/artifacts/delete_commit_late.json`

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

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state -->
**Restore reintroduces invalid state**
Backup, undo, undelete, or replica recovery restores data, credentials, memberships, or permissions that current policy no longer allows. Re-authorize restored state and reapply lifecycle changes made after the snapshot.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use -->
**Stale authorization and derived copy use**
Membership removal, ACL update, consent withdrawal, secret revocation, or role downgrade does not invalidate sessions, caches, subscriptions, jobs, or materialized data that continue to authorize future operations.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

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

- Agent ID `v-lifecycle`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-lifecycle/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-lifecycle <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-lifecycle /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
