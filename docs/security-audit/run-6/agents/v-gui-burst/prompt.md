You are candidate verifier `v-gui-burst` in run-6 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at commit `530b29e` (after fix PRs #24 and #25). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore",
 "title": "GuiBursts.covers omits container identity check, allowing agent GUI tools to execute on restored containers under stale baselines and escape stray kill",
 "description": "GuiBursts.covers (gui_bursts.py:68-71) checks only whether the sandbox ID exists in self._gui_burst without verifying that the burst's recorded container_id matches the sandbox's current container_id from sandboxes.get(sid). When an agent GUI input initiates a burst snapshot concurrently with an administrative restore_sandbox operation, restore_sandbox's end_desktop call runs before bursts.open creates the new burst entry. bursts.open records the pre-restore container C1, but sandboxes.restore then replaces the active container with C2. Because covers() checks only 'sid in self._gui_burst', the agent's GUI tool call executes on the restored container C2 under C1's baseline. When the burst subsequently closes, _finish detects the container mismatch, aborts change diffing, and logs gui_burst_close_failed without invoking _stop_strays, allowing any background processes spawned by the agent on C2 to persist unmonitored and join future burst baselines.",
 "root_cause": "GuiBursts.covers (gui_bursts.py:68-71) only evaluates 'self.sandboxes.settings.gui_snapshot_interval <= 0 or sid in self._gui_burst' without binding the burst to the current container identity (self.sandboxes.get(sid)['container_id']), and restore_sandbox (service.py:573-581) does not call bursts.end() after replacing the container in sandboxes.restore().",
 "intended_behavior": "GuiBursts.covers(sid) must verify that the recorded burst['container_id'] matches self.sandboxes.get(sid)['container_id']. If the container has changed, covers() must return False, causing _run_tool (service.py:148-152) to raise SandboxError and reject the execution. In addition, restore_sandbox() must call bursts.end(sid, 'sandbox_restored') after completing sandboxes.restore() to clear any bursts opened during the restore window.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 306,
   "scope": "AgentBox.call_tool",
   "description": "Agent dispatches a GUI input tool call (e.g. click, type, key) on a desktop sandbox while an administrative restore_sandbox operation is in flight or pending."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 267,
   "scope": "AgentBox._snapshot",
   "description": "_snapshot closes any existing burst (line 266) and begins committing the current container C1. Concurrently, restore_sandbox (service.py:574-577) runs end_desktop (which finds _gui_burst empty and does not clear the upcoming burst) and enters sandboxes.restore to replace C1 with C2."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 76,
   "scope": "GuiBursts.open",
   "description": "_snapshot completes the commit of C1 and invokes bursts.open(sid, snap['id']). bursts.open records container_id C1 into self._gui_burst[sid] before sandboxes.restore completes updating the active container to C2 in the database."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 148,
   "scope": "AgentBox._run_tool",
   "description": "_run_tool executes under gui_lock and checks self.bursts.covers(sid). Because covers() only checks 'sid in self._gui_burst' and does not compare burst['container_id'] to sandboxes.get(sid)['container_id'], it returns True despite the active container now being C2."
  },
  {
   "kind": "sink",
   "file": "agentbox/gui_bursts.py",
   "line": 136,
   "scope": "GuiBursts._finish",
   "description": "The GUI tool executes on C2, allowing the agent to launch rogue background processes. When the burst closes, _finish checks replaced = self.sandboxes.get(sid)['container_id'] != burst.get('container_id'). Because C2 != C1, replaced is True, so _finish logs gui_burst_close_failed and returns immediately without running _stop_strays or diff_manifest. The agent's background processes survive on C2 and silently join the baseline of the next burst."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/gui_bursts.py",
   "line": 71,
   "description": "GuiBursts.covers checks only 'self.sandboxes.settings.gui_snapshot_interval <= 0 or sid in self._gui_burst', omitting any validation that burst['container_id'] matches the current sandbox container."
  },
  {
   "file": "agentbox/service.py",
   "line": 148,
   "description": "_run_tool relies exclusively on self.bursts.covers(sid) under gui_lock to guard GUI inputs against running outside a valid burst."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 136,
   "description": "_finish skips _stop_strays and diff_manifest whenever replaced is True, leaving processes started on C2 alive when closed under C1's burst."
  },
  {
   "file": "agentbox/service.py",
   "line": 578,
   "description": "restore_sandbox calls bursts.reset_timers() after sandboxes.restore() but never calls bursts.end(), leaving any burst opened during restore active in self._gui_burst."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Agent token with authorization to call GUI input tool endpoints (click, type, key) on a sandbox with the desktop template."
  },
  {
   "kind": "timing_dependency",
   "description": "An agent GUI input tool call executing _snapshot races against restore_sandbox such that bursts.open runs after restore_sandbox's end_desktop call but before the active container update."
  }
 ],
 "execution": {
  "attacker_perspective": "An untrusted agent invokes GUI tool calls on its sandbox while the human administrator or control plane restores the sandbox from a snapshot.",
  "payloads": [
   "POST /sandboxes/sb1/tools/click with JSON body {/"x/": 5, /"y/": 5}"
  ],
  "instructions": [
   "Run the sandbox test script scratch/h.py using tools/sbx.py.",
   "Thread t1 calls box.call_tool('sb1', 'click', {'x': 5, 'y': 5}), entering _snapshot on container C1.",
   "Thread t2 calls box.restore_sandbox('sb1', 'snap_0'), executing end_desktop and entering sandboxes.restore.",
   "Thread t1 completes snapshot commit and invokes bursts.open, recording C1 in _gui_burst['sb1'].",
   "Thread t2 finishes restore, updating the database active container to C2.",
   "Thread t1 calls _run_tool, where bursts.covers('sb1') evaluates to True because it checks only 'sid in _gui_burst'.",
   "The click executes on container C2, spawning a background process (pid 999).",
   "Upon burst closure (idle or next tool), _finish detects container replacement (C2 != C1), logs gui_burst_close_failed, and returns without killing rogue processes.",
   "The subsequent burst baseline on C2 includes pid 999 as an authorized process."
  ],
  "observed_result": "Tool executed with status 200 on container C2 under a burst with container_id C1. bursts.covers('sb1') returned True. On burst closure, zero processes were killed, gui_burst_close_failed was logged with '컨테이너가 바뀌어 비교하지 않음 (복원)', and rogue process 999 successfully joined the baseline of the next burst on C2."
 },
 "remediation": {
  "strategy": "Modify GuiBursts.covers(sid) to verify that burst.get('container_id') == self.sandboxes.get(sid)['container_id']. If the container ID does not match, return False so _run_tool rejects the execution with SandboxError. In addition, call self.bursts.end(sid, 'sandbox_restored') in restore_sandbox() after sandboxes.restore() completes.",
  "code_changes": [
   {
    "file_name": "agentbox/gui_bursts.py",
    "fixed_code": "    def covers(self, sid: str) -> bool:/n        /"/"/"지금 GUI 입력을 실행해도 열린 구간이 그 변경을 받는지. gui_lock을 잡은 채로 부른다./n        스냅샷 판단은 잠금 전에 하므로, 잠금을 기다리는 사이 인수·반환으로 구간이 닫히면 여기서 걸러진다./"/"/"/n        if self.sandboxes.settings.gui_snapshot_interval <= 0:/n            return True/n        burst = self._gui_burst.get(sid)/n        if not burst:/n            return False/n        try:/n            return burst.get(/"container_id/") == self.sandboxes.get(sid)[/"container_id/"]/n        except Exception:/n            return False/n"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Occurs whenever an agent is issuing GUI tools during an administrative restore operation, which is standard procedure when recovering a compromised desktop sandbox."
  },
  "impact": {
   "score": "medium",
   "reason": "Defeats the GUI stray process kill policy and audit change recording on the restored container, allowing untrusted agent-spawned background processes to survive restore and enter future baselines without audit detection."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Source review confirmed the missing container comparison in covers(), and local deterministic sandboxed multi-threading reproduction verified both the exploit schedule and the fix."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Container%20identity%20binding%20of%20the%20F2%20GUI-input%20gate%3A%20GuiBursts.covers%20%28gui_bursts.py%3A68-71%29%20checks%20only%20%27sid%20in%20_gui_burst%27%2C%20called%20from%20_run_tool%20under%20gui_lock%20%28service.py%3A145%29%2C%20versus%20burst%5B%27container_id%27%5D%20set%20in%20open%28%29%20and%20the%20restore%2Fdelete%20path::Agent%20GUI%20input%20to%20the%20burst-based%20change%20recorder%20after%20restore%3A%20a%20burst%20opened%20on%20the%20pre-restore%20container%20can%20satisfy%20covers%28%29%20for%20an%20input%20that%20runs%20on%20the%20restored%20container%2C%20so%20no%20stray%20kill%20or%20gui_changes%20applies%20and%20the%20started%20processes%20join%20the%20next%20baseline.%20h-lifecycle%20recorded%20this%20as%20hardening%2C%20and%20its%20only%20candidate%20was%20rejected%20on%20a%20different%20claim.%20The%20PR%20%2317%20gate%20has%20no%20unit%20that%20reproduces%20or%20refutes%20this%20schedule.::agentbox%2Fgui_bursts.py%23covers%2Fopen%2Fend%2Freset_timers%20%2B%20agentbox%2Fservice.py%23_run_tool%2F_snapshot%2Frestore_sandbox::Race%20and%20check-then-act%20on%20security-control%20state%20%28container%20identity%20across%20restore%29",
  "surface": "Container identity binding of the F2 GUI-input gate: GuiBursts.covers (gui_bursts.py:68-71) checks only 'sid in _gui_burst', called from _run_tool under gui_lock (service.py:145), versus burst['container_id'] set in open() and the restore/delete path",
  "boundary": "Agent GUI input to the burst-based change recorder after restore: a burst opened on the pre-restore container can satisfy covers() for an input that runs on the restored container, so no stray kill or gui_changes applies and the started processes join the next baseline. h-lifecycle recorded this as hardening, and its only candidate was rejected on a different claim. The PR #17 gate has no unit that reproduces or refutes this schedule.",
  "local_checks": [
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_bursts.py",
     "agentbox/service.py"
    ],
    "invariant": "GuiBursts.covers(sid) must enforce that an open GUI burst belongs to the container currently running the sandbox before _run_tool executes any GUI input.",
    "method": "source",
    "result": "GuiBursts.covers (gui_bursts.py:68-71) checks only 'sid in self._gui_burst' and does not compare burst['container_id'] against the current container from self.sandboxes.get(sid)['container_id']. When _snapshot (service.py:265-284) races restore_sandbox (service.py:573-581), a burst opened with pre-restore container C1 satisfies covers() for an input executing on restored container C2.",
    "artifact": null
   },
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_bursts.py",
     "agentbox/sandbox.py",
     "agentbox/sandbox_desktop.py",
     "agentbox/service.py",
     "tests/test_m2_unit.py"
    ],
    "invariant": "A GUI burst opened across a container restore must not allow agent processes spawned on the restored container to escape stray kill or join subsequent burst baselines.",
    "method": "local",
    "result": "Deterministically reproduced in OS-enforced sandbox test harness (test 1 in h.out): an in-flight _snapshot on C1 completes bursts.open after end_desktop ran. The subsequent click executes on C2 because covers() returns True. When the burst closes, _finish aborts with 'gui_burst_close_failed: 컨테이너가 바뀌어 비교하지 않음 (복원)', leaving rogue process 999 unkilled to join the next burst baseline. Test 2 verified that checking burst['container_id'] == sandboxes.get(sid)['container_id'] in covers() rejects execution with SandboxError.",
    "artifact": "agents/h-gui-burst/artifacts/h.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint

```json
- none
```

# Parent-live evidence

- `agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/gui_burst_restore_live.out` (at `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/gui_burst_restore_live.out`)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-6)
Source ref: `530b29e` (`main`, after fix PRs #24 and #25). Profile `standard`, focused follow-up, budget 30 (all subagents `flash`). This file is the run-4/run-5 architecture plus a parent-written delta in section 0 covering every file changed since `346df29` (PRs #24 and #25: 13 non-test files in `agentbox/` and `deploy/`) and the run-5 delta from `9805d91` to `346df29`. No reconnaissance agent was spent in run-6: the parent inspected the full diff `346df29..530b29e`. **Line numbers in section 0.1 are exact at `530b29e`; section 0.2 has `346df29` numbers; sections 1-8 are `9805d91` numbers.**
## 0.1 Run-6 delta (changes in PRs #24 and #25, exact line numbers at `530b29e`)
- **Pre-read credential gate and anonymous body cap (`api.py`, `config.py`, `cli.py`, `deploy/`, PR #25 — run-5 N1 fix).**
  - `api.py:52-54`: `_UPLOAD_PATH = re.compile(r"/sandboxes/[^/]+/files")`, `_ANON_BODY_PATHS = {"/login"}`, `_ANON_BODY_MAX = 64 * 1024`.
  - `api.py:57-128` `_BodyLimit`: takes `authenticated` callback (`api.py:63-65`, wired at `api.py:185-201`). Rejects invalid/over-20-digit/over-cap `Content-Length` with 413 (`api.py:84-86`). Computes `has_body = (length is not None and int(length) > 0) or b"transfer-encoding" in headers` (`api.py:87`). If `has_body` and `scope["path"] in _ANON_BODY_PATHS`, lowers `cap = min(cap, _ANON_BODY_MAX)` (64 KiB) and rechecks `Content-Length` (`api.py:88-91`). Otherwise, if `has_body and self.authenticated and not await run_in_threadpool(self.authenticated, headers)`, rejects with 401 before reading any body (`api.py:92-95`). Streamed bodies remain capped at `cap` in `limited_receive` (`api.py:98-115`).
  - `api.py:185-199` `authenticated(headers)`: checks `Authorization: Bearer <token>` via `secrets.compare_digest` against `human_token` or `box.sandboxes.sandbox_for_token(token) is not None`, else parses `Cookie` with `http.cookies.SimpleCookie` and checks `box.desktop.session_scope(got.value)` for `D.COOKIE`. Route-level authorization (`human_only`, sandbox ownership, `same_origin`) still runs in route dependencies.
  - `config.py:68`: `max_connections` (`AGENTBOX_MAX_CONNECTIONS`, default 256; 0 disables); `cli.py:126-127` passes `limit_concurrency=s.max_connections` to `uvicorn.run`.
  - `deploy/Caddyfile:8-15`: `@upload path_regexp ^/sandboxes/[^/]+/files$` gets `AGENTBOX_PROXY_MAX_BODY` (256MB), `@other` gets `AGENTBOX_PROXY_MAX_JSON` (8MiB). `deploy/docker-compose.yml:20`: `mem_limit: ${AGENTBOX_MEM_LIMIT:-2g}`.
- **Desktop lock split and WebSocket threadpool offload (`desktop.py`, `desktop_ws.py`, `api.py`, PR #24 — run-5 F4 fix).**
  - `desktop.py:93-94`: `DesktopControl` splits `self._lock` (in-memory `_leases`, `_conns`, `_gui_locks`) from `self._db_lock` (SQLite `self._db`). Documented lock order when acquiring both: `_db_lock -> _lock`.
  - Ticket and session methods (`issue_ticket:116`, `redeem:124`, `start_session:139`, `end_session:147`, `session_scope:153`) take only `_db_lock`.
  - Lease and connection methods that touch both (`take:194`, `release:215`, `leftover_leases:235`, `forget_lease:246`, `close_all:299`) take `_db_lock` then `_lock`. In-memory-only methods (`lease`, `touch`, `is_stale`, `gui_lock`, `may_connect`, `add_conn`, `drop_conn`, `conns`, `end_session_conns`) take only `_lock`.
  - `api.py:441`: `desktop_ws` runs `await run_in_threadpool(box.desktop.session, cookie, sid)` before `same_origin(ws.headers)` (`api.py:442`, `same_origin` at `api.py:221-223`).
  - `desktop_ws.py:21-22`: `relay` runs `vnc_command` and `log_human("desktop_connect")` via `run_in_threadpool`. Periodic session recheck (`desktop_ws.py:76`) also uses `run_in_threadpool`. `finally` block (`desktop_ws.py:93-113`) runs `log_best_effort("desktop_disconnect")` on default executor inside `await asyncio.shield(logged)` before `box.desktop.drop_conn(conn)`.
- **GUI burst under takeover lease (`service.py`, PR #24 — run-5 F2 fix).**
  - `service.py:265-284` `_snapshot`: for `tool in GUI_INPUT`, after `sandboxes.snapshot`, acquires `with self._gui_locked(sid, "GUI 구간 열기"):`, runs `self._check_control(sid)`; only if no `HumanControl` is raised does it call `bursts.mark_snapshot(sid)` and `bursts.open(sid, snap["id"])`. Always appends the `snapshot` audit record (`service.py:280-281`), then if `human` was caught calls `self.bursts.reset_timers(sid)` and raises `human` (`service.py:282-284`).
  - `service.py:396-397`: `call_tool` catches `HumanControl` from `_snapshot` and delegates to `_human_blocked` (`service.py:411-419`, returns 423 and logs `tool_blocked`).
  - `service.py:498-514` `decide`: before `_snapshot`, if `tool in GUI_INPUT` and active lease or `_takeover_pending(sid)`, finishes approval as `FAILED` without taking a snapshot or opening a burst; also catches `HumanControl` from `_snapshot` (`service.py:511-514`).
- **Tool argument length cap, policy re-lex skip, and preview caps (`service.py`, `policy.py`, `preview.py`, `sandbox.py`, PR #24 — run-5 F1/F5/F6 fixes).**
  - `service.py:49`: `TOOL_ARG_MAX = 16 * 1024`. In `_call_tool` (`service.py:323-329`), before `tool_request` audit and `policy.decide`, rejects any arg `k != "content"` whose `len(v if isinstance(v, str) else json.dumps(v, default=str)) > TOOL_ARG_MAX` with 413 (`argument_too_long`).
  - `service.py:357-362`: in the `REQUIRE_APPROVAL` branch, applies `preview = bound_payload(preview)` before storing the pending approval row, and re-checks `if actor == "agent" and self.disk_low():` raising 507 before `_capture` and `approvals.create`.
  - `policy.py:27, 40-49, 73`: `_LEX_PUNCT = set(";&|()<>")`; `_relex_changes(t)` returns `False` for tokens consisting solely of `_LEX_PUNCT` or tokens with no whitespace, `_LEX_PUNCT`, quotes, or backslashes (e.g. `'x$'`), avoiding redundant recursive `_words(t, depth + 1)` calls.
  - `preview.py:70-71`: `PREVIEW_CALLS_MAX = 40`, `NOTES_MAX = 50`. `preview_command` (`preview.py:74-160`) deduplicates `rm` operands via `dict.fromkeys(operands)` (`:105`), caps total `expand`/`walk` calls at 40 via `budget()`, appends a Korean note when `skipped > 0` (`:154-156`), and truncates `notes` to `NOTES_MAX` plus a summary note (`:157-159`).
  - `sandbox.py:39, 104-106, 578-594`: `_PREVIEW_TIMEOUT = 10`; `_expand` and `_walk` wrap their container `sh -c` in `_timed(_PREVIEW_TIMEOUT, ...)` and call `_preview_ok(res)` (raises `SandboxError` on exit code 124 or 137).
- **Retention prune post-COMMIT archive safety (`retention.py`, PR #24 — run-5 F3 fix).**
  - `retention.py:104-108`: unlinks partial archive if `_write_archive` raises before the transaction.
  - `retention.py:131-145`: on exception inside the transaction block, rolls back only `if conn.in_transaction`; in the outer handler, queries `SELECT 1 FROM audit_anchor WHERE archive = ? AND archive_sha256 = ?` (defaulting `committed = True` on `sqlite3.Error`) and only unlinks the archive if `not committed`.
## 0.2 Run-5 delta (changes in PRs #16-#23, `346df29` line numbers)
- **Body cap (F1 fix, PR #16)**, **Audit cap (F3 fix, PR #16)**, **GUI gate (F2) and quota recheck (F7, PR #17)**, **Lifecycle lock (F6), F4 NUL-separated preview `_expand`/`_walk`, F5 single-flight `extract_novnc`, F8 login failure rate limit (PR #18)**, **Control-character filter `display.escape_controls` Cc/Cf/Zl/Zp (N5, PR #19)**, **Disk guard `disk_low` and finished-approval compaction (N2 stage 1, PR #20)**, **Host CLI `agentbox prune` and `audit_anchor` (N2 stage 2, PR #21)**, **Window owner via XRes `XResQueryClientIds` (N4, PR #22)**.
- **LLM-provider data path (PR #23)**: documented owner-accepted limitation; out of scope for hunting.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py`): full JSON API (`api.py` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default, and the bare `create_app` factory (`api.py`) that skips the serve-time gates. Container flags (`sandbox.py`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Windows 11 with Docker Desktop WSL2 Linux engine 29.9.2, runtimes `runc`/`io.containerd.runc.v2`, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1`, `agentbox-audit-sbx:1`. Agent-run code goes through `tools/sbx.py` (no network, read-only target at `/target`, writable `/scratch`, uid 65534, 512 MiB, 64 pids, 120 s). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`, `test_m5_unit.py`, `test_retention.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (16 KiB arg cap `TOOL_ARG_MAX` → audit with capped args `_logged_args` → `policy.decide` → quota → approval with bounded preview & `disk_low` recheck or `_snapshot` → `_run_tool`) on the 32-thread `tool_pool`. Pending approvals capped at 20.
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide`: atomic claim, GUI lease check, snapshot, run stored args. Preview (`preview.py` `preview_command` with `_expand`/`_walk` callbacks, 40-call budget, 10 s timeout per call) and capture run before the approval exists.
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per san

# Relevant companion blocks (verbatim)

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state -->
**Restore reintroduces invalid state**
Backup, undo, undelete, or replica recovery restores data, credentials, memberships, or permissions that current policy no longer allows. Re-authorize restored state and reapply lifecycle changes made after the snapshot.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

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

- Agent ID `v-gui-burst`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/v-gui-burst/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-gui-burst <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-gui-burst /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-gui-burst/artifacts/<file>`.
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
