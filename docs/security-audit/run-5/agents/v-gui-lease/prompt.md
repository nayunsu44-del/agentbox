You are candidate verifier `v-gui-lease` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease",
 "title": "GUI burst opened during a human takeover lets the control plane kill the human's processes and charge human edits to the agent",
 "description": "AgentBox._snapshot closes and opens an agent GUI burst without gui_lock and without checking the takeover lease. An approved GUI action decided while a lease is held (decide), or an agent click/type/key whose pre-input docker commit overlaps POST /desktop/takeover (call_tool), installs a new burst whose baseline is taken mid-takeover. _run_tool then raises HumanControl, but the burst stays open. When close_idle runs (triggered by any agent tool call or GET /approvals/{aid}) or the next agent burst closes it after handback, _stop_strays SIGKILLs, as the desktop user, every uid-1001 process the human started after that baseline in a new session (terminal shells and jobs started from them), and _finish records the human's /workspace edits as agent gui_changes. The takeover's own close at service.py:582 is meant to keep human activity out of agent bursts, and this path bypasses it. A prompt-injected agent can pick the moment of the kill, and with the default policy path (b) needs only that the takeover overlaps a commit.",
 "claimed_root_cause": "Burst open/close in _snapshot (service.py:261-276) is not serialized with takeover (gui_lock) and is not conditioned on the lease. Only needs_snapshot (gui_bursts.py:61) checks the lease, before a multi-second commit, and decide does not check it at all. The HumanControl paths in call_tool (service.py:373-381) and decide (service.py:477-480) do not discard the burst they just opened, so a baseline taken during the lease is later used for stray kill and change attribution.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 273,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "Agent token calls click/type/key; also POST /approvals/{aid} (api.py:308) and POST /ui/approvals/{aid}/approve (web.py:242) reach decide."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 61,
   "scope": "GuiBursts.needs_snapshot",
   "description": "Lease/takeover_pending checked here only, before the commit; no lease yet, so it returns True."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 367,
   "scope": "AgentBox._call_tool",
   "description": "Allow path calls _snapshot without gui_lock (decide does the same at service.py:467 with no lease check at all)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 582,
   "scope": "AgentBox.takeover",
   "description": "Human takeover gets gui_lock (free), closes the burst (none yet, the old one was closed at 263), then installs the lease at 584."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 268,
   "scope": "AgentBox._snapshot",
   "description": "After the commit returns, bursts.open records a baseline of processes/manifest taken during the lease."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 143,
   "scope": "AgentBox._run_tool",
   "description": "_check_control raises HumanControl; call_tool returns 423 / decide marks the approval failed; the burst is left in _gui_burst."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 161,
   "scope": "GuiBursts.close_idle",
   "description": "Run from any call_tool (service.py:285) or expire_stale (service.py:424, reached by GET /approvals/{aid}); submits close of the mid-lease burst while the lease is still held (or the next burst's close('next_burst') after handback)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_state.py",
   "line": 76,
   "scope": "_new_processes",
   "description": "Human-started uid-1001 processes in sessions absent from the mid-lease baseline are classified as strays."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox_desktop.py",
   "line": 94,
   "scope": "SandboxManager.kill_processes",
   "description": "kill -KILL of the human's processes as the desktop user; _finish (gui_bursts.py:147) logs the human's edits as agent gui_changes."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 261,
   "description": "_snapshot closes (263) and opens (268) the burst with no gui_lock and no lease check."
  },
  {
   "file": "agentbox/service.py",
   "line": 467,
   "description": "decide calls _snapshot unconditionally for an approved GUI input, even while desktop.lease(sid) is set."
  },
  {
   "file": "agentbox/service.py",
   "line": 373,
   "description": "HumanControl handling returns 423 without discarding the burst opened by _snapshot; decide (477-480) likewise."
  },
  {
   "file": "agentbox/service.py",
   "line": 582,
   "description": "takeover closes the burst so human changes stay out of agent bursts. This intent is bypassed when the open happens after this close."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 95,
   "description": "_stop_strays kills gui_strays computed against the burst baseline."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 87,
   "description": "Docstring: processes in sessions absent at burst start (terminal shells, setsid jobs) are stopped."
  },
  {
   "file": "agentbox/api.py",
   "line": 290,
   "description": "GET /approvals/{aid} (agent-callable) runs expire_stale -> close_idle, letting the agent choose when the kill happens."
  }
 ],
 "blockers": [
  "The sandboxed check used a fake Docker-facing SandboxManager (snapshot blocks on an event in place of docker commit, desktop_processes returns a fixed ps/window table). Still to be observed: real kill -KILL of human-started processes in the agentbox-desktop:0.1 container during a live lease, the real session layout of a terminal opened through noVNC, and the real docker commit duration that sets the race window for path (b)."
 ],
 "validation_plan": {
  "local": "Already run in tools/sbx: agents/h-gui-lease/artifacts/h.out from h.py (real AgentBox/GuiBursts/gui_state/DesktopControl/ApprovalStore, fake SandboxManager). Shows killed [201,202] and gui_changes added [human_notes.txt] for (a) decide-under-lease, (b) call_tool/takeover race with close during lease, and (b') close via next_burst after handback; control without race shows killed []. Regression: same schedules must give killed == [] and no 'sb' in box.bursts._gui_burst while the lease is held.",
  "deployment": "Parent-live, loopback, disposable desktop sandbox, dummy tokens. (a) Deterministic: policy file adds rule {id: gui-approval, tool: click, action: require_approval}; create desktop sandbox; human session POST /sandboxes/{sid}/desktop/takeover; agent token POST /sandboxes/{sid}/tools/click {x:1,y:1} -> 202 with approval_id; human POST /approvals/{aid} {decision: approve} -> status failed; audit shows human_takeover then a system 'snapshot' row for tool click. Do not keep the main UI tabs open (they poll /ui/notify). Then start a human-like job outside the exec exemption: docker exec -u desktop <c> setsid -f sleep 600 (reparented to PID 1, new session), or open a terminal through noVNC. Wait more than 60 s, then agent GET /approvals/{aid}; expect while the lease is still held an audit gui_processes_stopped row (reason idle) listing that pid and the pid gone from ps. (b) Race: leave the agent's GUI idle for more than 60 s, send agent click, and about 200 ms later (inside the docker commit) send POST /desktop/takeover; expect click 423 and audit order human_takeover -> snapshot(tool=click) -> tool_blocked(human_control), then repeat the setsid job + agent list_dir step and observe the kill. Variant: hand back instead, then agent click; expect gui_processes_stopped reason next_burst for the job started during the lease."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "A%20GUI%20burst%20opened%20while%20a%20human%20takeover%20lease%20is%20held%3A%20%28a%29%20POST%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2Fapprove%20for%20an%20approved%20click%2Ftype%2Fkey%2C%20which%20is%20reachable%20once%20the%20snapshot%20quota%20turns%20GUI%20input%20into%20REQUIRE_APPROVAL%20or%20a%20policy%20gates%20GUI%20tools%2C%20and%20%28b%29%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%7D%20whose%20pre-input%20docker%20commit%20races%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover.%20The%20burst%20is%20then%20closed%20by%20close_idle%2C%20which%20any%20agent%20tool%20call%20triggers%2C%20or%20by%20the%20next%20burst%20after%20handback.::Agent%20GUI-burst%20enforcement%20%28stray%20kill%2C%20gui_kept%2Fgui_changes%20attribution%29%20versus%20the%20human%20desktop%20session%20during%20a%20takeover%3A%20takeover%20closes%20the%20burst%20under%20gui_lock%20before%20installing%20the%20lease%20%28service.py%3A571-589%2C%20close%20at%20582%29%2C%20but%20_snapshot%20%28service.py%3A261-277%29%20closes%20and%20opens%20a%20burst%20without%20gui_lock%20or%20a%20lease%20check%2C%20reached%20from%20decide%20%28service.py%3A440%29%20and%20from%20call_tool%20after%20a%20needs_snapshot%20lease%20check%20%28gui_bursts.py%3A55%29%20that%20precedes%20a%20multi-second%20commit%3B%20an%20opened%20burst%20may%20survive%20the%20lease%20so%20close_idle%20%28gui_bursts.py%3A154%29%20or%20the%20next%20burst%20kills%20processes%20the%20human%20started%20or%20charges%20human%20edits%20to%20the%20agent.::agentbox%2Fservice.py%23decide%2F_snapshot%2Fcall_tool%2Ftakeover%2F_handback_locked%20%2B%20agentbox%2Fgui_bursts.py%23needs_snapshot%2Fopen%2Fclose_idle%2F_stop_strays%20%2B%20agentbox%2Fgui_state.py%23gui_strays::Race%20and%20check-then-act%20on%20security-control%20state%3A%20GUI%20burst%20opened%20by%20decide%2F_snapshot%20or%20call_tool%20while%20a%20human%20takeover%20lease%20is%20held",
  "surface": "A GUI burst opened while a human takeover lease is held: (a) POST /approvals/{aid} and POST /ui/approvals/{aid}/approve for an approved click/type/key, which is reachable once the snapshot quota turns GUI input into REQUIRE_APPROVAL or a policy gates GUI tools, and (b) POST /sandboxes/{sid}/tools/{click,type,key} whose pre-input docker commit races POST /sandboxes/{sid}/desktop/takeover. The burst is then closed by close_idle, which any agent tool call triggers, or by the next burst after handback.",
  "boundary": "Agent GUI-burst enforcement (stray kill, gui_kept/gui_changes attribution) versus the human desktop session during a takeover: takeover closes the burst under gui_lock before installing the lease (service.py:571-589, close at 582), but _snapshot (service.py:261-277) closes and opens a burst without gui_lock or a lease check, reached from decide (service.py:440) and from call_tool after a needs_snapshot lease check (gui_bursts.py:55) that precedes a multi-second commit; an opened burst may survive the lease so close_idle (gui_bursts.py:154) or the next burst kills processes the human started or charges human edits to the agent.",
  "local_checks": [
   {
    "agent_id": "h-gui-lease",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/gui_bursts.py",
     "agentbox/desktop.py",
     "agentbox/api.py",
     "agentbox/web.py",
     "agentbox/policy.py",
     "agentbox/default_policy.yaml"
    ],
    "invariant": "No agent GUI burst (baseline + later stray kill + gui_changes attribution) may be opened while a human takeover lease is held; takeover (service.py:571-589) closes the burst under gui_lock before desktop.take, so every later burst open must also be serialized against the lease.",
    "method": "source",
    "result": "Violated. _snapshot (service.py:261-276) runs bursts.close('next_burst') (263), docker commit (264) and bursts.open (268) with no gui_lock and no lease/_takeover_pending check. decide (service.py:440, _snapshot at 467) never checks the lease before _snapshot; call_tool checks the lease only inside bursts.needs_snapshot (gui_bursts.py:61) before the commit. _run_tool then takes gui_lock and _check_control raises HumanControl (service.py:142-143, 163-172), but nothing removes the burst that _snapshot just installed: call_tool returns 423 (service.py:373-381), decide marks the approval failed (service.py:477-480). The F2 covers() gate (gui_bursts.py:68-71, service.py:145) is reached only after _check_control and does not help. The F6 _lifecycle lock (service.py:500-504) is not taken by call_tool/decide/takeover. The burst stays in _gui_burst during the lease and is closed later by close_idle (gui_bursts.py:154-165, run from call_tool service.py:285 and expire_stale service.py:424, which the agent reaches via any tool call or GET /approvals/{aid} api.py:288-290) or by the next burst's close('next_burst') after handback.",
    "artifact": null
   },
   {
    "agent_id": "h-gui-lease",
    "reviewed_paths": [
     "agentbox/gui_bursts.py",
     "agentbox/gui_state.py",
     "agentbox/sandbox_desktop.py",
     "agentbox/templates/base.html",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "Stray kill and gui_kept/_kept handling must only judge processes the agent could have started during its own burst.",
    "method": "source",
    "result": "With a baseline taken mid-lease, _stop_strays (gui_bursts.py:89-110) passes to kill_processes (sandbox_desktop.py:92-95, kill -KILL as the desktop user) every uid-1001 process created after that baseline in a session absent from it (gui_state.py:53-79; the docstring at gui_state.py:86-88 states shells inside a terminal are in such sessions). Human-opened terminal shells and jobs started from them are therefore SIGKILLed; the human's windowed terminal itself lands in _kept (gui_bursts.py:99-101) and is only re-judged next burst (open excludes kept pids, gui_bursts.py:83-84), which adds no further harm. _finish (gui_bursts.py:144-152) logs the human's /workspace edits as gui_changes under the agent burst's snapshot_id. The N4 kept set does not change reachability. Default policy allows GUI tools (default_policy.yaml), so path (b) needs only default config; path (a) needs a GUI approval (policy rule or snapshot quota reached before the takeover; under a lease needs_snapshot returns False so the quota does not convert new GUI calls). The main UI polls /ui/notify every 3 s and /ui/approvals every 2 s (templates/base.html:45, sandbox.html:25), which runs close_idle and can close an idle-stamped burst early; a desktop-link-only session (desktop.py page polls /state only) does not.",
    "artifact": null
   },
   {
    "agent_id": "h-gui-lease",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/gui_bursts.py",
     "agentbox/gui_state.py",
     "agentbox/desktop.py",
     "agentbox/approvals.py",
     "tests/test_m2_unit.py"
    ],
    "invariant": "Deterministic schedule with the real AgentBox/GuiBursts/gui_state/DesktopControl/ApprovalStore and a fake Docker-facing SandboxManager (pattern of tests/test_m2_unit.py _GuiSandboxes): no human-started process is killed and no human edit is charged to the agent across a takeover.",
    "method": "local",
    "result": "Control (burst finished before takeover): killed []. (b) agent click blocks in fake snapshot(), human takeover succeeds (lease True), agent gets 423, burst still open with baseline [1,100,101]; human adds terminal 200 (windowed), bash 201 and job 202 in new session 201 and file human_notes.txt; agent list_dir (200) while lease still held -> killed [201,202], gui_processes_stopped reason idle, gui_processes_kept [200], gui_changes added [human_notes.txt] snapshot_id snap_1. (b') same race, no close during lease, handback, agent click -> killed [201,202] reason next_burst, gui_changes charged to snap_1. (a) policy rule click=require_approval, takeover, agent click -> 202 pending, human decide approve -> failed (HumanControl) after snapshot, burst left open with baseline [1,100,101]; expire_stale -> lease still held, killed [201,202]. Command: tools/sbx h-gui-lease /usr/bin/python3.13 /scratch/h.py (no network, uid 65534, 512 MiB, 64 pids, 120 s), rc=0.",
    "artifact": "agents/h-gui-lease/artifacts/h.out"
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

- `agents/parent-live/artifacts/gui_lease_a.json`

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

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

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

- Agent ID `v-gui-lease`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-gui-lease/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-gui-lease <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-gui-lease /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
