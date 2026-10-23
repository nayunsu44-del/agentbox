You are final record verifier `r-gui-lease` in run-5 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease",
 "title": "GUI burst opened during a human takeover lets the control plane kill the human's processes and charge human edits to the agent",
 "description": "AgentBox._snapshot closes and opens an agent GUI burst without taking gui_lock and without checking the takeover lease. If an approved GUI click/type/key is decided while a lease is held, or if an agent click/type/key whose pre-input docker commit overlaps POST /desktop/takeover, a new burst is installed with a baseline taken mid-takeover. _run_tool then raises HumanControl (call_tool returns 423, decide marks the approval failed) but nothing discards the burst. When close_idle runs, or the next agent burst closes it after handback, _stop_strays SIGKILLs as the desktop user every uid-1001 process the human started after that baseline in a session absent from it (terminal shells and jobs started from them). _finish also records the human's /workspace edits as agent gui_changes under the agent burst's snapshot_id. Takeover closes the burst at service.py:582 precisely so that human activity stays out of agent bursts, and this path bypasses that. The agent can choose when the kill happens, because any agent tool call or GET /approvals/{aid} runs close_idle. Path (a) is demonstrated against the real Docker engine and desktop image. Path (b) rests on source plus a local deterministic schedule: the race window is the docker commit duration, which was not timed live, and the agent cannot force a takeover into it. Impact is bounded: lost human background work (windowed apps are kept) and misattributed audit rows, not agent escalation.",
 "root_cause": "Burst open/close in _snapshot (service.py:261-276) is not serialized with takeover (gui_lock) and is not conditioned on the lease. GuiBursts.needs_snapshot (gui_bursts.py:61) checks the lease only before a multi-second commit, and decide (service.py:467) does not check it at all. The HumanControl handlers in call_tool (service.py:373-381) and decide (service.py:477-480) leave the burst that _snapshot just opened in _gui_burst. A baseline taken during the lease is later used for stray kill and change attribution.",
 "intended_behavior": "No agent GUI burst (baseline, later stray kill, gui_changes attribution) exists while a human takeover lease is held. Takeover closes the agent burst under gui_lock (service.py:582) so that human processes and edits are never judged against an agent baseline, and every later burst open is serialized against the lease.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 273,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "The agent token calls click/type/key (api.py:278 calls box.call_tool with actor=agent). A pending GUI approval is decided via POST /approvals/{aid} (api.py:308) or POST /ui/approvals/{aid}/{decision} (web.py:242), both reaching AgentBox.decide."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 61,
   "scope": "GuiBursts.needs_snapshot",
   "description": "The lease and takeover_pending check happens only here, before the docker commit. With no lease yet it returns True and the commit starts."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 367,
   "scope": "AgentBox._call_tool",
   "description": "The allow path calls _snapshot without gui_lock. decide calls _snapshot at service.py:467 with no lease check at all."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 582,
   "scope": "AgentBox.takeover",
   "description": "Takeover takes gui_lock, which is free because _snapshot does not hold it. It closes the burst (none open yet) and installs the lease at service.py:584."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 268,
   "scope": "AgentBox._snapshot",
   "description": "After the commit returns, bursts.open records a baseline of desktop-user pids and a /workspace manifest taken while the lease is held (gui_bursts.py:73-87)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 143,
   "scope": "AgentBox._run_tool",
   "description": "_check_control raises HumanControl. call_tool returns 423 (service.py:373-381) and decide marks the approval failed (service.py:477-480). The burst stays in _gui_burst and no input time is marked (mark_input is never reached), so it already counts as idle."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 154,
   "scope": "GuiBursts.close_idle",
   "description": "Run from any call_tool (service.py:285) or expire_stale (service.py:424, reached by GET /approvals/{aid}, api.py:288-290). It submits close() of the mid-lease burst while the lease is still held. Alternatively _snapshot's close('next_burst') (service.py:263) closes it after handback."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_state.py",
   "line": 53,
   "scope": "_new_processes",
   "description": "Human-started desktop-user processes in sessions absent from the mid-lease baseline are classified as strays (line 78). Windowed ones go to kept."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox_desktop.py",
   "line": 92,
   "scope": "SandboxManager.kill_processes",
   "description": "kill -KILL of the human's processes as the desktop user (via GuiBursts._stop_strays, gui_bursts.py:95). _finish (gui_bursts.py:147) logs the human's /workspace edits as agent gui_changes."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 263,
   "description": "_snapshot closes (263) and opens (268) the burst with no gui_lock and no lease or takeover_pending check."
  },
  {
   "file": "agentbox/service.py",
   "line": 467,
   "description": "decide calls _snapshot unconditionally for an approved GUI input, even while desktop.lease(sid) is set."
  },
  {
   "file": "agentbox/service.py",
   "line": 373,
   "description": "The HumanControl handler returns 423 without discarding the burst opened by _snapshot. decide (477-480) likewise only marks the approval failed."
  },
  {
   "file": "agentbox/service.py",
   "line": 582,
   "description": "takeover closes the burst so that human changes stay out of agent bursts. The open in _snapshot can happen after this close, so the intent is bypassed."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 95,
   "description": "_stop_strays computes gui_strays against the burst baseline and kills them."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 161,
   "description": "close_idle treats a burst with no recorded input time as idle (_gui_input_at.get(sid, 0.0)). A burst opened by a blocked input therefore closes on the next close_idle even though the lease is held."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 86,
   "description": "Docstring of gui_strays: processes in sessions absent at burst start (terminal shells, nohup/setsid jobs) are stopped."
  },
  {
   "file": "agentbox/api.py",
   "line": 288,
   "description": "GET /approvals/{aid} is callable by the agent token and runs expire_stale -> close_idle, so the agent chooses when the close happens."
  },
  {
   "file": "agents/parent-live/artifacts/gui_lease_a.json",
   "line": 1,
   "description": "Live run against the real Docker engine and agentbox-desktop:0.1: with click gated by policy, takeover, agent click returned 202, human approve returned status failed (HumanControl) with burst_open true. A desktop-user setsid job (pid 400) started during the lease was then SIGKILLed at close_idle with the lease still held. Audit shows human_takeover, snapshot(click), tool_error, then gui_processes_stopped reason idle for 'sleep 600'. (The artifact's burst_baseline_size 0 is a script key mismatch, 'procs' versus the burst's 'pids', and does not affect the kill.)"
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Agent token for its own desktop sandbox (lowest-trust network principal). Path (a) also needs the human to take over and decide the approval."
  },
  {
   "kind": "system_configuration",
   "description": "Desktop-template sandbox with gui_snapshot_interval > 0 (default). Path (a) needs a GUI click/type/key to be gated by policy or by the snapshot quota so a pending approval exists. Path (b) works under the default policy, which allows GUI tools."
  },
  {
   "kind": "user_interaction",
   "description": "Path (a): a human takes over the desktop and approves, or is approved on their behalf from the UI, a pending GUI approval while the lease is held. Path (b): a human takeover starts inside the agent's docker commit."
  },
  {
   "kind": "timing_dependency",
   "description": "Path (b) needs the takeover to land inside the pre-input docker commit window. Path (a) is deterministic. The human must also start a non-windowed or new-session desktop-user process after the baseline, such as a terminal shell or a setsid/nohup job, before the burst closes."
  }
 ],
 "execution": {
  "attacker_perspective": "Prompt-injected agent holding the sandbox's agent token. It places or waits for a GUI click/type/key, which is sent so that it ends up as a pending approval or its docker commit overlaps a takeover, and later makes any tool call or GET /approvals/{aid} to trigger close_idle.",
  "payloads": [
   "POST /sandboxes/{sid}/tools/click {\"args\":{\"x\":1,\"y\":1}} with a policy rule {id: gui-approval, tool: click, action: require_approval}",
   "POST /approvals/{aid} {\"decision\":\"approve\"} by the human during the lease",
   "GET /approvals/{aid} with the agent token after the idle window",
   "docker exec -u desktop <container> setsid -f sleep 600 (stand-in for a human-opened terminal job)"
  ],
  "instructions": [
   "Create a desktop sandbox with a policy rule gating click behind approval.",
   "Human takes over: POST /sandboxes/{sid}/desktop/takeover.",
   "Agent sends click and receives 202 with an approval_id.",
   "Human approves during the lease. The approval ends status failed (HumanControl) after a snapshot row is logged, and the burst stays open with a baseline taken during the lease.",
   "Human starts a job in a new session, for example setsid sleep 600 as the desktop user or a terminal opened through noVNC.",
   "After the idle window, the agent calls any tool or GET /approvals/{aid}. While the lease is still held, the audit log gets gui_processes_stopped (reason idle) listing the human's pid, and the process is gone.",
   "Path (b): the same end state is reached when the agent's click commit overlaps a takeover (click returns 423, burst left open). Handing back and having the agent click again closes it with reason next_burst."
  ],
  "observed_result": "Real Docker plus agentbox-desktop:0.1 (parent-live, path a): the burst was opened during the lease. The human's setsid sleep 600 (pid 400) was killed by the idle close with the lease still held and the burst closed, and gui_processes_stopped was audited. Independent local rerun (fake Docker-facing SandboxManager, real AgentBox, GuiBursts, gui_state, DesktopControl and ApprovalStore) via tools/sbx: the control with no race killed []. Path (b) with close during the lease killed [201, 202]. Path (b) with the close via next_burst after handback killed [201, 202]. Path (a) decide-under-lease killed [201, 202] with the lease held. The windowed xfce4-terminal was kept, and the human's file was logged as agent gui_changes under snap_1."
 },
 "remediation": {
  "strategy": "Never let a burst exist while the human holds or is about to hold the screen. Serialize _snapshot's close, commit and open with the same gui_lock that takeover uses. Re-check lease(sid), is_stale and _takeover_pending after the commit and before bursts.open. If the lease or a pending takeover is present, skip opening, or discard the snapshot's burst. Also discard or close the burst without stray kill when HumanControl is raised in call_tool and decide. Make decide check the lease before snapshotting. As defense in depth, have _finish skip _stop_strays and gui_changes for a burst whose open time overlapped a lease, and reject close or kill while desktop.lease(sid) is set.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "# in _snapshot, after the commit and before bursts.open, with self.desktop.gui_lock(sid) held around close+open:\nif tool in GUI_INPUT:\n    with self.desktop.gui_lock(sid):\n        if self.desktop.lease(sid) or self._takeover_pending(sid):\n            self.bursts.reset_timers(sid)\n            raise HumanControl(self.desktop.lease(sid) or Lease(sid, self._takeover_pending(sid)))\n        self.bursts.mark_snapshot(sid)\n        opened = self.bursts.open(sid, snap['id'])\n# and in call_tool/decide HumanControl handlers: self.bursts.close_discard(sid)  # drop burst without stray kill"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Path (a) is deterministic once a GUI approval is pending and a human approves during their own takeover, a plausible UI flow. It needs a policy gate or snapshot quota on GUI tools, and the human has to start a new-session or non-windowed process in the window. Path (b) needs the takeover to land inside the commit window under the default policy, and the agent cannot force it. The agent does control when the kill fires."
  },
  "impact": {
   "score": "low",
   "reason": "The human's non-windowed desktop-user processes (terminal shells and jobs, setsid/nohup jobs) started after a mid-lease baseline are SIGKILLed, and the human's /workspace edits are logged as agent changes under an agent snapshot. This loses the human's background work and degrades audit attribution. It does not give the agent code execution, data access or approval bypass. Windowed apps are kept, and the snapshot is available for recovery."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Source shows no lock or lease check between needs_snapshot and bursts.open and no discard on HumanControl. Path (a) was observed end to end against the real Docker engine and desktop image (parent-live). I independently reran the local deterministic schedules (control killed [], races killed [201, 202]). Unobserved: the real docker commit duration for path (b) and a terminal opened through noVNC in place of the setsid stand-in. Neither changes the source-visible root cause."
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

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

# Execution boundary and paths

- Agent ID `r-gui-lease`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/r-gui-lease/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx r-gui-lease <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3.13`.
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx r-gui-lease /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
