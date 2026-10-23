You are final record verifier `r08` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback",
 "title": "A GUI input queued on gui_lock across a human handback executes with no open burst, so its changes get no snapshot and no gui_changes row",
 "description": "AgentBox decides whether a GUI input needs a snapshot before it acquires gui_lock. While a human holds the desktop a takeover lease exists, so GuiBursts.needs_snapshot returns False and the input blocks on gui_lock instead of opening a burst. If the human hands the desktop back while that input is queued, the input runs with a lease check that now passes and no burst open: it writes as uid 1001, calls mark_input, and its fresh input timestamp makes needs_snapshot False for every later input until 60 s of input silence (gui_snapshot_idle) or 600 s after the last snapshot (gui_snapshot_interval). Those inputs produce no snapshot, no burst, and no gui_changes row; the only recovery point predates the human takeover, and the file effects of the inputs are never diffed or attributed.",
 "root_cause": "The burst decision is taken outside the lock that serializes execution: service.py:343 evaluates _needs_snapshot (gui_bursts.py:52-63, which returns False while a non-stale lease or pending takeover exists) before _run_tool acquires gui_lock at service.py:136, and the only re-check under the lock (_check_control, service.py:152-161) validates the stale-lease/lease/pending-takeover state, never burst presence. _handback_locked (service.py:528-543) releases the lease (542) and calls forget_input (543) while still holding gui_lock, so the queued input resumes into a state where its earlier premise is gone and nothing takes a snapshot; mark_input (service.py:139) then suppresses the next burst decision.",
 "intended_behavior": "Every GUI input that executes must be covered by an open burst bound to a snapshot taken before that input, and each burst must close into a gui_changes record (service.py:261-264 fails closed when a burst baseline cannot be opened; gui_bursts.py:157-162 re-timers lifecycle paths for exactly this reason). A burst decision taken before waiting on a lock must be re-validated after the lock is acquired.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool} -> AgentBox.call_tool",
   "description": "Agent token from principal; default_policy.yaml has default: allow and no rule for click/type/key, so GUI inputs are approval-free, are audited as tool_request, and take the ALLOW branch."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 343,
   "scope": "AgentBox._call_tool (ALLOW branch)",
   "description": "_needs_snapshot is evaluated before any lock; while a takeover lease is present _over_snapshot_quota is skipped too and GuiBursts.needs_snapshot returns False, so no snapshot is taken and no burst is opened."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 136,
   "scope": "AgentBox._run_tool (GUI branch)",
   "description": "gui_lock is acquired afterwards without a timeout, so an input that already decided 'no burst needed' can sit queued while the human's handback holds the same lock."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 152,
   "scope": "AgentBox._check_control",
   "description": "The only re-check after acquiring gui_lock handles a stale lease, a live lease and the pending-takeover marker; burst presence and the earlier needs_snapshot result are never re-validated."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 542,
   "scope": "AgentBox._handback_locked",
   "description": "While gui_lock is still held, the human handback releases the lease; the queued input then acquires the lock with no lease and no pending marker, so _check_control passes."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 543,
   "scope": "AgentBox._handback_locked",
   "description": "forget_input only drops the input timestamp; the handback opens no burst, so the resumed input's decision premise is gone but nothing forces a snapshot."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 139,
   "scope": "AgentBox._run_tool (GUI branch)",
   "description": "The resumed input executes the GUI action and calls bursts.mark_input although no burst is open."
  },
  {
   "kind": "sink",
   "file": "agentbox/gui_bursts.py",
   "line": 62,
   "scope": "GuiBursts.needs_snapshot",
   "description": "The fresh input timestamp makes the next decision False, so later inputs run burstless until gui_snapshot_idle of silence or gui_snapshot_interval since the last snapshot."
  },
  {
   "kind": "sink",
   "file": "agentbox/gui_bursts.py",
   "line": 113,
   "scope": "GuiBursts._finish",
   "description": "Only an open burst is ever diffed and logged as gui_changes; no burst exists for these inputs, so their /workspace changes are never recorded."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 343,
   "description": "Burst decision taken before the lock; with a lease present it is False."
  },
  {
   "file": "agentbox/service.py",
   "line": 136,
   "description": "gui_lock is acquired after that decision, with no timeout."
  },
  {
   "file": "agentbox/service.py",
   "line": 152,
   "description": "_check_control re-checks only stale lease, lease and pending takeover; no burst-presence condition."
  },
  {
   "file": "agentbox/service.py",
   "line": 542,
   "description": "The handback releases the lease inside the gui_lock-held section."
  },
  {
   "file": "agentbox/service.py",
   "line": 543,
   "description": "forget_input in the same section clears the timestamp but opens no burst."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 58,
   "description": "needs_snapshot returns False while a non-stale lease or pending takeover exists, assuming the input will get 423."
  },
  {
   "file": "agentbox/service.py",
   "line": 139,
   "description": "mark_input runs for an input that has no burst open."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 62,
   "description": "A fresh input timestamp suppresses the following burst decision."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 113,
   "description": "No burst, so no gui_changes row for the changes made by these inputs."
  },
  {
   "file": "agentbox/service.py",
   "line": 278,
   "description": "_snap_locks serializes SNAPSHOT_TOOLS, so at most one GUI input per sandbox is in _call_tool at a time; the window is the handback's lock-held section, not a queue of many inputs."
  },
  {
   "file": "agentbox/config.py",
   "line": 50,
   "description": "gui_snapshot_idle default 60 s: the burstless window ends after that much input silence."
  },
  {
   "file": "agentbox/config.py",
   "line": 51,
   "description": "gui_snapshot_interval default 600 s: upper bound with continuous input, because a snapshot older than that forces a new burst."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "A sandbox agent token (agt_...); GUI tools are default-allow (default_policy.yaml default: allow) and need no human approval."
  },
  {
   "kind": "timing_dependency",
   "description": "The single in-flight GUI input must take its burst decision while the takeover lease exists and then acquire gui_lock after the handback released the lease. A tight loop of click/type calls during the takeover (each 423) raises the hit rate; the window is the handback's lock-held section (audit write plus lease release), which SQLite/audit contention widens."
  },
  {
   "kind": "user_interaction",
   "description": "The human must hand the desktop back through handback, logout, or pause/restore/delete via end_desktop, because that path is the one that holds gui_lock across the lease release."
  },
  {
   "kind": "data_state",
   "description": "A snapshot taken within gui_snapshot_interval (default 600 s) exists, so after the burstless input the fresh mark_input timestamp keeps later inputs from opening a burst; the queued input itself needs only the lease."
  }
 ],
 "execution": {
  "attacker_perspective": "An agent that wants to change the desktop without a gui_changes row and without a fresh recovery point keeps issuing GUI inputs while a human holds the desktop, so one of them is queued on gui_lock when the human hands back, and then keeps clicking/typing immediately afterwards.",
  "payloads": [
   "POST /sandboxes/sb_x/tools/click {\"args\":{\"x\":1,\"y\":1}} (opens the first burst and snapshot)",
   "repeated POST /sandboxes/sb_x/tools/click {\"args\":{\"x\":2,\"y\":2}} while a takeover lease is held; all but the one landing in the handback window return 423",
   "POST /sandboxes/sb_x/tools/click and /tools/type immediately after the handback"
  ],
  "instructions": [
   "Bounded harness in the approved audit sandbox (sbx.py v08, no network, /target read-only): real AgentBox, GuiBursts and DesktopControl (sqlite :memory:); fake SandboxManager (click/type add a manifest entry), in-memory AuditLog with one hook, default-allow Policy, empty ApprovalStore.",
   "Seed one click so a snapshot (snap_1) and an open burst exist; call box.takeover(sid, 'hs_human') so the burst is closed and a lease is held.",
   "Install a hook on AuditLog.append('human_handback'): it starts the agent's click thread, waits until that thread has recorded its needs_snapshot decision (False, lease present, no burst), verifies it is blocked on gui_lock, then returns so box.handback(sid, 'hs_human') can release the lease and unlock.",
   "Join the agent thread, then issue three more clicks, and read snapshot count, bursts._gui_burst, audit gui_changes rows and needs_snapshot.",
   "Control run on a fresh box: seed click, three clicks while the burst is open, then takeover to close the burst, and compare the gui_changes diff."
  ],
  "observed_result": "The queued click executed with status 200 executed and needs_snapshot False taken while the lease was still present and no burst open; snapshots stayed 1 and gui_changes stayed at the single row the takeover wrote for the seed burst, while the click plus three following clicks (all 200) added 4 files (5 files total). All four burst decisions were False, so no new snapshot or burst appeared. The control run with the same four clicks inside an open burst logged gui_changes added=4 for snap_1 when the burst closed. The only artificial element is a pause inside the handback's audit append (a real SQLite write), which widens the natural window; the ordering it produces is one the code allows."
 },
 "remediation": {
  "strategy": "Decide the GUI burst requirement under the same lock that serializes GUI execution: after gui_lock is acquired in _run_tool, re-evaluate needs_snapshot and take the snapshot / open the burst there, and fail closed with reset_timers if no burst is open. Key the decision on burst presence rather than only on input timestamps, and make the handback path force the next input to open a new burst instead of only forgetting the timestamp. Regression test: hold gui_lock with an input queued, release the lease inside the lock, release the lock, and assert the input never calls mark_input or executes without an open burst.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "if tool in GUI_TOOLS:\n    with self.desktop.gui_lock(sid):\n        self._check_control(sid)\n        if tool in GUI_INPUT:\n            if self.bursts.needs_snapshot(sid):   # must be re-decided here, not at _call_tool:343\n                self._snapshot(sid, tool, f\"before {tool}\", {})\n            if not self.bursts.is_open(sid):\n                self.bursts.reset_timers(sid)   # next input re-decides and opens a burst\n                raise SandboxError(\"GUI 구간이 열려 있지 않아 GUI 입력을 실행하지 않음. 잠시 뒤 다시 호출할 것\")\n            self.bursts.mark_input(sid)"
   },
   {
    "file_name": "agentbox/gui_bursts.py",
    "fixed_code": "def is_open(self, sid: str) -> bool:\n    \"\"\"입력이 실행될 때 열린 구간이 있는가. 구간 없이 실행하면 바뀐 것이 기록되지 않는다.\"\"\"\n    with self._lock:\n        return sid in self._gui_burst"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "The agent must land its single in-flight GUI input in the handback's lock-held section: at ~5-10 ms per call in a tight loop and a few ms of audit write plus release, the collision is reachable within a session, and it needs no agent control over when the human hands back. Not certain per attempt, so not high."
  },
  "impact": {
   "score": "medium",
   "reason": "The inputs themselves are still audited as tool_request/tool_result (coordinates, typed text), but their /workspace effects get no gui_changes diff and no snapshot is taken, so the burst-level attribution and recovery point the N-1 mitigation relies on silently misses an attacker-chosen window; the last snapshot predates the human takeover."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Every trace line was re-checked in the 9805d91 tree and the minimum result was reproduced on the real AgentBox, GuiBursts and DesktopControl objects, with a control run showing the same inputs are recorded when a burst is open. The residual uncertainty is only how often the natural window is hit."
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

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Establish the realistic local or remote-content attacker: another app, another OS user, a sandboxed child, an untrusted document, or a remote origin. Self-harm within the same account and authority is not a boundary violation.
- Paths, process names, bundle/package IDs, and claimed sender fields are not peer authentication. Use OS peer credentials, code identity, capability handles, or protected channel state.
- The native bridge or helper must authorize each operation and final resource after parsing. A trusted UI or broker does not make attacker-influenceable arguments trusted.
- OS sandbox, signing, entitlements, permissions, keychain ACLs, exported-component policy, and prompt behavior are real controls when pinned and visible.
- Use `confirmed` for source evidence plus bounded local/emulator tests. Use `needs_validation` when signing, manifest merge, OS version, device policy, installer ACL, or packaging is required but not observable.
```

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU -->
**Local file ownership and TOCTOU**
The app checks a file/path then follows replacement, symlink, mount, or case/normalization changes during a privileged read/write. Use descriptor-relative operations and verify final ownership. Focus `MEMORY-SAFETY-AND-BINARY.md` on parsing after the file is opened.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock -->
**Reachable fatal error or deadlock**
An untrusted input reaches `panic`, abort, fatal assertion, unhandled exception, process exit, lock cycle, or infinite loop in a shared process. Confirm supervisor scope and whether one worker or the whole service becomes unavailable. A restarted isolated worker may reduce impact but does not erase the defect.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unsafe recovery and capacity rollback -->
**Unsafe recovery and capacity rollback**
A restart, restore, fallback, or cleanup path rebuilds unbounded state, ignores current quotas, or restores the input that immediately repeats failure. Recovery correctness is part of availability.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves -->
## Universal moves (apply across the above)

- Enumerate every process, app component, local endpoint, URI scheme, file association, webview origin, and helper. Record OS identity, runtime privilege, caller, and callable operation.
- Read final packaging inputs: merged manifest, entitlements, installer rules, native-messaging registration, protocol handlers, and ACL creation. Source declarations can be overwritten downstream.
- Validate with dummy profiles and non-sensitive local fixtures on an isolated machine/emulator. Do not interact with other users' apps, credentials, or production services.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the attacker starting capability, OS/app principal crossed, entry channel, accepted argument or state, and unauthorized operation or disclosure.
2. Confirm OS sandbox, peer credential, signing, entitlement, permission, user-consent, and installer controls that apply. Unknown packaging/runtime facts require `needs_validation`.
3. For webview bridges, cite both navigation/origin control and privileged native sink. For IPC, cite peer authentication and per-resource authorization. For helpers, verify final normalized destination.
4. Keep local tests bounded and use dummy content/accounts. Stop after proving the boundary result; do not extend proof into persistence or broader system modification.
5. Return `confirmed` only with a complete source and local evidence chain. Return `needs_validation` with the exact OS, manifest, signing, ACL, or device-lifecycle fact required.

# Execution boundary and paths

- Agent ID `r08`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r08/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r08 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r08 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
