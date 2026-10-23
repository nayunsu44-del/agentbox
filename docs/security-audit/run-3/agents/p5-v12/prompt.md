You are Phase 5 final-record verifier `p5-v12` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.

# Execution boundary (verbatim from the skill)

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
```

# Phase 5 checks for a `confirmed` record (verbatim from the skill)

```text
1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.
```

A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# Final record (from findings.json)

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause",
 "title": "GUI burst stray-kill and gui_changes logging are lost across sandbox restore and pause",
 "description": "GUI input bypasses the approval gate by design (N-1). The partial mitigation for that is a per-burst snapshot, a gui_changes audit record and killing the uid-1001 processes started during the burst (service.py:206-256). None of the GUI burst state (_gui_burst, _gui_input_at, _gui_snap_at) is reconciled with container lifecycle transitions. (1) Restore: api.py:192 and web.py:243 call end_desktop, which closes the old burst (service.py:531). It clears _gui_input_at only through handback when a human lease exists (service.py:494), and it never clears _gui_snap_at. After the restore, an agent GUI input that comes within gui_snapshot_idle (60 s) of its previous input and within gui_snapshot_interval (600 s) of the last GUI snapshot gets False from _gui_needs_snapshot (service.py:196). It therefore runs with no snapshot and no burst. A uid-1001 background process the agent starts in that gap is recorded in the next burst's baseline pid set (service.py:213), so gui_strays skips it (sandbox.py:216) and it is never killed. Workspace changes made in the gap are in the next burst's baseline manifest, so they never appear in gui_changes. (2) Pause: the pause route (api.py:166-170) does no burst handling. Once the burst's idle time passes while the sandbox is paused, the next caller of close_idle_gui_bursts closes it: the sandbox page polls /ui/audit every 3 s (templates/sandbox.html:19, web.py:261), and GET /audit, expire_stale and any call_tool also call it. _close_gui_burst pops the burst first (service.py:232). desktop_processes then raises through _desktop/_require_running for a paused sandbox (sandbox.py:688, 468-469) and the error is swallowed (service.py:221-222). The manifest exec against the paused container also fails and is swallowed (238-239). The strays are not killed and the changes are not logged. After resume they keep running and become part of the next burst's baseline. The same unreconciled state also causes an availability effect, reproduced only in the fake harness. Restore pops the burst in end_desktop before the container is replaced, and nothing invalidates a burst opened after that point. If an agent GUI input opens a burst between end_desktop and the container swap (a race window), the baseline holds the old container's pids. When that burst idles out, gui_strays treats every uid-1001 process of the new desktop session as a stray and kills it. Windowed processes are included, because base_sids is empty when the old pids are absent from the new container. This happens only when the new container's pids differ from the old ones. With identical pids nothing is killed.",
 "root_cause": "GUI burst bookkeeping in AgentBox is in-memory state keyed only by sandbox id. It has no tie to the container instance or its run state. end_desktop (service.py:529-537), which the restore routes call, closes the burst but leaves _gui_input_at (cleared only by handback at 494) and _gui_snap_at (set at 263, never cleared) in place. _gui_needs_snapshot (195-197) therefore suppresses a fresh burst after restore, and a burst opened after end_desktop survives the container swap. The pause and resume routes (api.py:166-176) do not touch burst state at all. _close_gui_burst (232) also discards the burst before its enforcement steps, and those steps return silently on failure (221-222, 238-239). An idle close while the sandbox is paused therefore drops the burst without killing strays or logging changes.",
 "intended_behavior": "Every container lifecycle change (restore, pause, resume, delete) resets the GUI burst timers, so the first GUI input afterwards takes a snapshot and opens a burst whose baseline belongs to the current container. A burst is discarded only after its strays have been stopped and its changes diffed and logged. A paused sandbox keeps its burst until it is running again, or the burst is closed before pausing. A burst whose container id no longer matches is closed without killing anything.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 205,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "Agent token (lowest-trust principal, own sandbox) calls GUI input tools click/type/key, which the default policy allows (no matching rule), through box.call_tool on tool_pool."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 109,
   "scope": "AgentBox._run_tool",
   "description": "Every GUI input sets _gui_input_at[sid] before the click runs, even if the click then fails, for example while the container is being replaced."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 192,
   "scope": "restore route",
   "description": "Human restore calls box.end_desktop(sid, 'sandbox_restored') and then sandboxes.restore, which replaces the container (web.py:243-244 does the same). Nothing else touches GUI burst state."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 531,
   "scope": "AgentBox.end_desktop",
   "description": "Closes the open burst before the swap. _gui_input_at is popped only via handback when a lease exists (494). _gui_snap_at is never cleared."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 196,
   "scope": "AgentBox._gui_needs_snapshot",
   "description": "Recent last_input (<=60 s) and last_snap (<=600 s) give False, so _call_tool (339) runs the first post-restore GUI inputs with no snapshot and no open burst."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 169,
   "scope": "pause route",
   "description": "Pause variant: the route only logs and calls sandboxes.pause; the open burst stays in _gui_burst."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 232,
   "scope": "AgentBox._close_gui_burst",
   "description": "An idle close during the pause (close_idle_gui_bursts at 254-256, called by the /ui/audit 3 s poll at web.py:261) pops the burst first. desktop_processes then raises through sandbox.py:688 -> _require_running 468-469 and the error is swallowed at 221-222. The manifest failure is swallowed at 238-239."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 213,
   "scope": "AgentBox._open_gui_burst",
   "description": "The next burst (after the idle or interval timer expires, or after resume) records all current pids as its baseline, including the gap or paused-burst stray, and records the current manifest, including the gap changes."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 216,
   "scope": "gui_strays",
   "description": "Baseline pids are skipped, so the stray uid-1001 process is never selected by _stop_gui_strays and keeps running. Its changes never appear in gui_changes."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 494,
   "description": "_gui_input_at is reset only on handback, which end_desktop calls only when a lease exists (532-536)."
  },
  {
   "file": "agentbox/service.py",
   "line": 263,
   "description": "_gui_snap_at is set on every GUI snapshot and has no pop anywhere in the package (grep)."
  },
  {
   "file": "agentbox/api.py",
   "line": 175,
   "description": "Resume route only logs and unpauses; no burst or timer handling."
  },
  {
   "file": "agentbox/service.py",
   "line": 255,
   "description": "close_idle_gui_bursts closes idle bursts regardless of sandbox status."
  },
  {
   "file": "agentbox/web.py",
   "line": 261,
   "description": "UI audit fragment calls close_idle_gui_bursts. sandbox.html:19 polls it every 3 s; api.py:258 GET /audit and expire_stale/call_tool also call it."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 468,
   "description": "_require_running raises SandboxError for a paused sandbox. desktop_processes reaches it via _desktop (680, 688)."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 498,
   "description": "workspace_manifest uses _container, not _require_running. For a paused sandbox the docker exec fails, so the post-burst diff is skipped at service.py:238-239."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 518,
   "description": "restore sets the new container_id and status running before _wait_display. A burst opened after end_desktop is not invalidated by the swap (stale-baseline consequence)."
  },
  {
   "file": "docs/security-audit/run-3/agents/v12/artifacts/v12_burst.out",
   "line": 46,
   "description": "Harness output. A_control kills stray 50 and logs gui_processes_stopped and gui_changes. B_restore: timers kept; t20 and t70 inputs took no snapshot and opened no burst; next baseline [1,10,11,12,60]; killed []; no gui_* events. The fix check (timers cleared) kills 60 and logs report.md. C_pause (line 157): burst dropped while paused; killed []; baseline [1,10,11,12,70]; stray alive. D (line 192): stale baseline kills the new desktop [14,15,16] when pids differ, and nothing when pids match."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Agent token for a desktop-template sandbox, driving GUI input tools (allowed by the default policy)."
  },
  {
   "kind": "user_interaction",
   "description": "Restore variant: a human restores while the agent's last GUI input is under 60 s old and its last GUI snapshot is under 600 s old, with no active human lease (a lease's handback clears _gui_input_at). Pause variant: a human pauses while a burst is open and keeps it paused past gui_snapshot_idle while some poller (open sandbox page, GET /audit, approvals list, or any agent's tool call) runs close_idle_gui_bursts."
  },
  {
   "kind": "system_configuration",
   "description": "gui_snapshot_interval > 0 (default 600) and gui_snapshot_idle at its default of 60."
  },
  {
   "kind": "timing_dependency",
   "description": "Restore gap length is bounded by the remaining idle and interval windows. The agent controls both by keeping inputs frequent. The stale-baseline desktop kill additionally needs a GUI input landing between end_desktop and the container swap, and new pids that differ from the old ones."
  }
 ],
 "execution": {
  "attacker_perspective": "Prompt-injected agent with its own sandbox's agent token, using click/type/key on a desktop sandbox (for example opening a terminal and starting a setsid background loop as uid 1001) around a human restore or pause.",
  "payloads": [
   "restore: click t=0 (snap_1, burst); human end_desktop + restore at t=10; click t=20; uid-1001 setsid loop pid 60 + report.md modified at t=25; click t=70; idle close t=150; click t=200; idle close t=300",
   "pause: click t=0 (burst); stray pid 70 + report.md modified at t=5; click t=10; pause t=20; close_idle_gui_bursts t=100 (UI audit poll); resume t=200; click t=210; idle close t=400",
   "stale baseline: click t=0; idle close t=1000; end_desktop t=1001; click t=1002 before the container swap; restore with new desktop pids (14,15,16) at t=1003; idle close t=1100"
  ],
  "instructions": [
   "In the sbx sandbox (no network, no Docker), run /usr/bin/python3.13 -I /scratch/v12_burst.py. It builds the real AgentBox with a real AuditLog, ApprovalStore, Policy.load(default_policy.yaml) and DesktopControl, and the real gui_strays. Only SandboxManager is faked: it records snapshots and kills; desktop_processes and click raise when paused, mirroring _require_running; workspace_manifest raises when paused, mirroring Docker refusing exec in a paused container. time.monotonic is patched to drive the timers.",
   "Drive the agent through box.call_tool(sid, 'click', ...) and the human restore through box.end_desktop followed by the fake restore, as api.py:192-193 does. Pause and resume flip the record status, as api.py:169/175 do. Call close_idle_gui_bursts as the UI poll does. Compare the snapshots, baselines, kills, surviving pids and audit snapshot/gui_processes_stopped/gui_changes events against the control run and against a run with the timers cleared after restore."
  ],
  "observed_result": "Control: snapshot snap_1, stray 50 killed, gui_processes_stopped [50] and gui_changes modified [report.md] logged. Restore: after end_desktop the burst is closed but _gui_input_at and _gui_snap_at are kept. The t20 and t70 inputs return 200 with no snapshot and no burst. The next burst (t200, snap_2) has baseline [1,10,11,12,60]. Killed []. Stray 60 still alive. No gui_processes_stopped or gui_changes event. With the timers cleared after restore (proposed fix), t20 opens snap_2, stray 60 is killed and report.md is logged. Pause: the idle close while paused drops the burst. Killed []. Stray 70 is alive after resume. Next baseline [1,10,11,12,70]; stray 70 is still alive after the next idle close; no gui_* events. Stale baseline: a burst opened after end_desktop on the old container, with baseline [1,10,11,12], kills every uid-1001 process of the new container [14,15,16], including the windowed panel. With identical new pids nothing is killed."
 },
 "remediation": {
  "strategy": "Tie GUI burst state to the container lifecycle. In end_desktop, and in the pause, resume and restore paths (API and web), close the burst and then clear _gui_input_at and _gui_snap_at, so the next GUI input always snapshots and opens a burst on the current container. Record the container_id in the burst and close a burst whose container_id no longer matches without killing anything. Skip paused sandboxes in close_idle_gui_bursts, or close the burst before pausing. In _close_gui_burst, remove the burst only after stray stop and the manifest diff succeed, and log a gui_burst_close_failed event otherwise. Add regression tests: GUI input soon after restore opens a new burst, a burst idling out while paused is kept or closed before pausing, and a burst opened before a container swap does not kill the new desktop.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "def _reset_gui_state(self, sid: str, reason: str) -> None:\n    self._close_gui_burst(sid, reason)\n    self._gui_input_at.pop(sid, None)\n    self._gui_snap_at.pop(sid, None)\n\ndef end_desktop(self, sid: str, reason: str) -> None:\n    self._reset_gui_state(sid, reason)\n    if self.desktop.lease(sid):\n        try:\n            self.handback(sid, None, reason)\n        except ServiceError:\n            pass\n    self.desktop.close_all(sid)\n    # callers: also call self._gui_input_at.pop / _gui_snap_at.pop again after sandboxes.restore returns\n\ndef _open_gui_burst(self, sid, snapshot_id):\n    ...\n    self._gui_burst[sid] = {..., \"container_id\": self.sandboxes.get(sid)[\"container_id\"]}\n\ndef close_idle_gui_bursts(self) -> None:\n    idle = self.sandboxes.settings.gui_snapshot_idle\n    now = time.monotonic()\n    for sid in list(self._gui_burst):\n        try:\n            if self.sandboxes.get(sid)[\"status\"] == \"paused\":\n                continue\n        except Exception:\n            pass\n        if now - self._gui_input_at.get(sid, 0.0) > idle:\n            self._close_gui_burst(sid, \"idle\")\n\ndef _close_gui_burst(self, sid, reason):\n    burst = self._gui_burst.get(sid)\n    if not burst:\n        return\n    if self.sandboxes.get(sid)[\"container_id\"] != burst[\"container_id\"]:\n        self._gui_burst.pop(sid, None)  # stale baseline: never kill against it\n        return\n    ok = self._stop_gui_strays(sid, burst, reason)  # return False on failure\n    ...  # pop only after strays stopped and manifest diff logged; otherwise log gui_burst_close_failed\n"
   },
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "@app.post(\"/sandboxes/{sid}/pause\")\ndef pause(sid: str, p: Principal = Depends(human_only)):\n    box.log_human(\"sandbox_pause\", sid, {})\n    box.end_gui_burst(sid, \"sandbox_paused\")  # close burst (kill strays, log changes) and clear timers\n    guard(lambda: box.sandboxes.pause(sid))\n    return box.sandboxes.get(sid)\n# resume: clear timers after unpause; same changes in web.py"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Pausing or restoring a sandbox while the agent is active on the GUI is the natural human reaction to suspicious activity. The pause variant only needs the pause to outlast gui_snapshot_idle (60 s) while the sandbox page is open, or while any other caller runs close_idle_gui_bursts. For the restore variant, the agent keeps the timers recent just by issuing frequent inputs. It needs no active human lease at restore."
  },
  "impact": {
   "score": "medium",
   "reason": "It defeats the only compensating controls on the GUI approval bypass (N-1). An agent-started uid-1001 background process survives indefinitely, and its /workspace changes are missing from gui_changes, so the audit trail the human relies on after a restore or pause is incomplete. The restore variant also skips the post-restore GUI restore point. No privilege beyond the sandbox and no network (network_mode none). A same-root-cause stale baseline can also kill the new desktop session, but only through a race and pid divergence, and it was shown only in the harness."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "The restore variant is pure control-plane state logic in service.py and was reproduced with the real AgentBox, AuditLog, Policy, DesktopControl and gui_strays. Clearing the timers (the proposed fix) restores the kill and the logging. The pause variant's decisive step is the source-visible _require_running status check. The harness fakes SandboxManager and does not exercise live Docker pids, the real xfce process tree, or the stale-baseline race timing. Those affect only the related desktop-kill consequence, not the confirmed stray-survival and missing-log result."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Architecture facts

# agentbox architecture summary (run-3)

Source ref: `0e4b958` on `ccr-e10bee8e-6wt669` (PR #5 head; `agentbox/` identical after merge to `main`). Profile `standard`, whole repo.

## 1. Product, principals, protected resources

agentbox is a self-hosted control plane (FastAPI + SQLite) that gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. A desktop mode adds Xvfb/Xfce/noVNC so a human can watch or take over the screen.

- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full API.
- **Web UI cookie session**, scope `*` (token login form or one-time `*` ticket): full UI (`web.py:208-242`, `desktop.py`).
- **Desktop-link session**, scope = one sandbox id (redeemed per-sandbox ticket): only that sandbox's desktop page/state/takeover/handback/WS (`api.py:134-140,298-336`, `desktop.py:147-152`).
- **Agent token** `agt_…` per sandbox (hash stored): tool calls on its own sandbox, read own sandbox/approval/desktop state (`api.py:160-230,315`). Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (tool execs), uid 1001 `desktop` (X session, GUI tools, x11vnc; member of the agent group, `/workspace` group-writable). Container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listings, file names) is attacker-controlled input to the control plane.
- **MCP stdio server / agent.py LLM loop**: hold an agent token; inherit trust from the local launcher.

Protected resources: the human token and approval authority; host filesystem and Docker daemon (control plane holds `docker.sock` = host root); other sandboxes; integrity of `/workspace` restore points (AP-2 snapshots before destructive actions); audit-log integrity and secret masking; control-plane availability (shared thread pool, memory, host disk via `docker commit`).

## 2. Comparable baseline

No source-grounded comparable product. Components: MCP (FastMCP stdio), VNC/RFB via x11vnc+noVNC, gVisor/Kata runtimes. A runc sandbox shares the host kernel; the code refuses runc only when the control plane is exposed (`cli.py:79-115`).

## 3. Stack, deployment, offline limits

Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: local `agentbox serve` (127.0.0.1), direct TLS, `--behind-tls-proxy` (compose + Caddy, `forwarded_allow_ips="*"` by default), `--insecure`, and the bare `uvicorn agentbox.api:create_app --factory` path that skips serve-time checks. Container flags: `network_mode=none`, `/source` read-only bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits; no userns, default seccomp (`sandbox.py:367-388`). Host: Docker 29.9.1, runtimes `runc` and `io.containerd.runc.v2` only (no gVisor/Kata), cgroup v1, images `agentbox-desktop:0.1`, `buildpack-deps:noble-curl`. Pure-function harnesses and the three unit test modules fit the parent's `sbx` sandbox; anything that builds the app needs the Docker daemon (parent-live checks).

## 4. Entry surfaces and important paths

- JSON API `POST /sandboxes/{sid}/tools/{tool}` → `service.call_tool` (per-sandbox concurrency 4, 429) → audit → `policy.decide` → allow / approval queue → `sandbox.exec|read_file|write_file|delete_file|list_dir|gui_*` (`docker exec` as uid 1000/1001), dedicated 32-thread `tool_pool` (`api.py:81`). Exec output streamed and capped (`_Head`, 64 KB).
- Approvals `POST /approvals/{aid}` (human only) → atomic claim → pre-snapshot → run with the agent's original args; terminal approver `cli.py` renders args through `_safe()`.
- Snapshots: `docker commit` before write/delete overwrite and per GUI burst; quota 50 → approval (`service.py:199-204`); per-sandbox `_snap_locks`.
- GUI bursts (`service.py:186-260`): snapshot + manifest + baseline pids at burst start; at close, kill new uid-1001 processes classified by `gui_strays` from root `ps` output and `xdotool` window pids (`sandbox.py:174-225,686-697`), diff `find -printf` manifest (8 MB cap) and log `gui_changes`. Closed on idle from `expire_stale`, `call_tool`, `GET /audit`, UI audit fragment, takeover, end_desktop.
- Files: `read_file` (`timeout` + `[ -f ]` FIFO guard), `outbox_list/read`, `POST /sandboxes/{sid}/files` upload, `source_dir` copy at create (refuses overlap with `settings.home`/DB dir).
- Desktop: tickets (60 s, one-time, hashed), sessions (12 h, hashed, `scope`), leases keyed by public session id `hs_`+32 bits, WS `/desktop/ws` (cookie + same_origin; control needs lease; re-check every 30 s, `session_ended` handback), logout `end_ui_session`.
- Audit: hash chain with append-only triggers, `mask_text` regex set (`audit.py`), UI/CLI timelines render container-controlled strings (`web.py describe`, Jinja autoescape; `cli._safe`).
- Serve: `bind_problem`, `runtime_problem` (literal `"runc"` only), `--allow-runc`/`AGENTBOX_ALLOW_RUNC`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc here) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot, `gui_changes`, stray kill (partial, N-1) |
| Agent → human authority | token kinds, `human_only`, scope checks, source_dir overlap check |
| Agent → control-plane availability | tool_pool, tool_concurrency, `_Head`, snapshot quota, read timeouts |
| Container output → control plane | parsers `_parse_ps`, `_parse_manifest`, `_parse_outbox`; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin` (missing Origin allowed) |
| Desktop-link session → rest of UI | `scope` column, `desktop_human` |
| Network → control plane | `bind_problem` TLS gate; proxy trust `*` |

## 6. Starting paths

`agentbox/service.py`, `sandbox.py`, `api.py`, `policy.py`, `desktop.py`, `audit.py`, `web.py`, `cli.py`, `config.py`, `approvals.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

run-1 (`7fc501f`, standard, source-only) ledger: 15 units; run-2 validated live. 9 confirmed records, all with changed source (fixed in PR #1–#5; N-1 GUI bypass only partially mitigated) → `prior_confirmed_changed_source` revalidation units, not excluded from hunting. One rejected claim (`desktop.py:redeem:sandbox-scoped-ticket-mints-unscoped-full-admin-session`): source changed (scope column), so the unit is current work. No same-source confirmed exclusions. Changed since `7fc501f`: 9 source files (+598/−67) — first priority.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent-driven work consumes the shared pool, memory, host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: browser UI with htmx and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 desktop helper killed/inspected by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release/signing path; CI only runs tests), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker/RPC beyond HTTP/WS/MCP stdio covered elsewhere).


# Execution paths

- Agent ID `p5-v12`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v12/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v12 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v12/artifacts/<file>`.

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


# report-schema.json branches (verbatim): confirmed, needs_validation, rejected

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


# Output

Return exactly one JSON object with no prose and no markdown fence, one of:
{"decision": "verified", "fingerprint": "<the record's fingerprint>"}
{"decision": "replace", "reason": "<what failed and why>", "record": {...}, "artifacts_to_promote": [...]}
A replacement record must match its `confirmed`, `needs_validation`, or `rejected` branch exactly (additionalProperties: false) and keep the same fingerprint unless you identified a genuinely different root cause. `artifacts_to_promote` is optional. Overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
