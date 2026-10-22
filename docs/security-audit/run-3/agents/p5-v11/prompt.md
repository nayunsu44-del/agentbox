You are Phase 5 final-record verifier `p5-v11` in a defensive security audit of agentbox.
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
 "fingerprint": "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency",
 "title": "Idle GUI burst close runs another sandbox's untimed docker execs inline on unrelated tool threads and human approval/audit threads",
 "description": "close_idle_gui_bursts() iterates every sandbox's open GUI burst and is called before the per-sandbox tool_concurrency check at the start of every call_tool (service.py:273), from expire_stale (service.py:373, reached by GET /approvals, GET /approvals/{aid}, and POST /approvals/{aid} via decide->expire_stale at 385), and from GET /audit (api.py:258). Closing sandbox B's burst runs desktop_processes (ps + an xdotool search via _x) and workspace_manifest (find) and kill_processes against B's container with docker exec_run and no deadline. So B's maintenance runs on sandbox A's tool_pool thread or on a human request (Starlette threadpool) thread, outside B's tool_concurrency budget. If B's container/X server is unresponsive, the exec never returns and the unrelated caller blocks indefinitely. The burst is popped before closing (service.py:232), so one idle stuck burst permanently steals one caller thread; aggregating across many desktop sandboxes can exhaust the shared pools. The parent reproduced the cross-sandbox block against the real Docker-backed control plane: with B's Xvfb stopped and B's burst idle, A's list_dir did not return within 20s and returned 0.3s after B's Xvfb resumed.",
 "root_cause": "close_idle_gui_bursts() runs cross-sandbox maintenance (burst close) inline on whatever thread calls it - a tool_pool thread of an unrelated sandbox (service.py:273, before the tool_concurrency check at 275-278) or a human request thread (expire_stale service.py:373 from GET/POST approvals and decide; GET /audit api.py:258) - and the docker execs it performs (desktop_processes xdotool via _x sandbox.py:684/690-691, workspace_manifest find 499, kill_processes 697) use exec_run with no deadline, unlike exec/read_file/outbox_read which wrap the command in 'timeout'. An unresponsive owning container therefore blocks the unrelated caller indefinitely, with the work charged to no sandbox's budget.",
 "intended_behavior": "Work done for sandbox B should be charged to B's tool_concurrency budget and never run inline on another sandbox's tool thread or a human request thread, and every docker exec (as exec/read_file/outbox_read already do) should carry a deadline so an unresponsive container cannot stall unrelated sandboxes or the human approval/audit path.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 206,
   "scope": "POST /sandboxes/{sid}/tools/{tool} (call_tool route)",
   "description": "Agent of sandbox A posts any tool; it runs on the shared 32-thread tool_pool via run_in_executor (api.py:81,209-210). The same close_idle_gui_bursts maintenance is also reached from GET /audit (api.py:258) and, via expire_stale, from GET /approvals (217), GET /approvals/{aid} (222) and POST /approvals/{aid} decide (240-252) - all def routes on the Starlette threadpool."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 273,
   "scope": "AgentBox.call_tool",
   "description": "close_idle_gui_bursts() runs before the per-sandbox _busy/tool_concurrency check at 275-278, so the burst-close work is charged to no sandbox's budget."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 254,
   "scope": "AgentBox.close_idle_gui_bursts",
   "description": "Iterates list(self._gui_burst) - every sandbox's open burst - and closes any whose last GUI input is older than gui_snapshot_idle (default 60s) on the calling thread (loop 254-256), so sandbox B is closed on sandbox A's or a human's thread."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 235,
   "scope": "AgentBox._close_gui_burst",
   "description": "Pops burst B (232) then calls _stop_gui_strays(B) (235) before workspace_manifest (237)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 218,
   "scope": "AgentBox._stop_gui_strays",
   "description": "Calls self.sandboxes.desktop_processes(B) (218) against sandbox B's container."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 690,
   "scope": "SandboxManager.desktop_processes via _x",
   "description": "docker exec_run of the xdotool search command (via _x at sandbox.py:684, user=desktop) with no 'timeout' wrapper, run against sandbox B's container. The calling thread (sandbox A's tool_pool thread or a human request thread) blocks in exec_start until B's X server replies; a stopped/unresponsive Xvfb never replies and exec_run has no deadline. workspace_manifest find (499) and kill_processes (697) on the same path are likewise untimed."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 273,
   "description": "close_idle_gui_bursts() is invoked before the tool_concurrency check at 275-278, so burst-close work is never counted against any sandbox's per-sandbox budget."
  },
  {
   "file": "agentbox/service.py",
   "line": 256,
   "description": "The loop closes the burst of any sid in self._gui_burst, not just the calling sandbox's (254-256); _close_gui_burst pops the burst at 232 so each stuck burst costs one caller rather than all callers."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 684,
   "description": "_x issues c.exec_run(argv, user=DESKTOP_USER, ...) with no 'timeout' wrapper; the docker SDK exec_run/exec_start exposes no deadline. Used by desktop_processes xdotool (690-691)."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 531,
   "description": "Contrast: exec wraps the command in 'timeout -k 5 <exec_timeout>' (default 60); read_file (561) and outbox_read (665) use 'timeout -k 2 30'. The burst-close execs (499 find, 684/690-691 xdotool, 697 kill) have no such bound."
  },
  {
   "file": "agentbox/service.py",
   "line": 373,
   "description": "expire_stale() calls close_idle_gui_bursts(); decide() calls expire_stale() first (385), so a human approve/deny decision for any approval runs another sandbox's burst-close inline on the request thread."
  },
  {
   "file": "agentbox/api.py",
   "line": 258,
   "description": "GET /audit calls box.close_idle_gui_bursts() on the human request (Starlette threadpool) thread before listing."
  },
  {
   "file": "agents/parent-live/artifacts/l2_cross.out",
   "line": 2,
   "description": "Parent Docker-backed run (l2_cross.py): with sandbox B's Xvfb stopped and B's GUI burst idle, sandbox A's list_dir did NOT return within 20s, and returned 0.3s after B's Xvfb got SIGCONT - demonstrating A's unrelated tool call blocked indefinitely on B's untimed GUI exec."
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "Lowest-trust network principal: a prompt-injected agent holding an agt_ token for a desktop-template sandbox. GUI tools have no approval gate by design (architecture: Agent -> GUI approval gate = none)."
  },
  {
   "kind": "system_configuration",
   "description": "Desktop mode (Xvfb/Xfce) enabled for at least one sandbox so GUI bursts exist. Defaults: gui_snapshot_idle=60s, tool_concurrency=4, tool_pool max_workers=32 (api.py:81)."
  },
  {
   "kind": "environmental_dependency",
   "description": "The owning container's X server (or the docker exec) must be unresponsive so the untimed exec_run does not return; docker exec_run/exec_start provides no deadline parameter. The parent induced this by SIGSTOP of Xvfb as the desktop user."
  },
  {
   "kind": "timing_dependency",
   "description": "The victim's GUI burst must be idle (> gui_snapshot_idle) at the moment another sandbox's call_tool, a GET /audit, or an approval decision triggers close_idle_gui_bursts."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent on its own desktop sandbox B. Victims are other sandboxes' agents and the human operator (approval decisions and audit reads), who share the same control plane thread pools.",
  "payloads": [
   "POST /sandboxes/{B}/tools/click  {\"x\":5,\"y\":5}   (opens a GUI burst for sandbox B)",
   "inside B, as the desktop user (reachable via the ungated GUI tools / desktop shell): kill -STOP $(pgrep -x Xvfb)   (renders B's X server unresponsive)",
   "stop issuing GUI input for > gui_snapshot_idle seconds so B's burst becomes idle"
  ],
  "instructions": [
   "Create or use a desktop-template sandbox B and issue one GUI input tool so a GUI burst opens for B (service.py:_open_gui_burst via _snapshot).",
   "From within B, make B's X server unresponsive (e.g. SIGSTOP Xvfb as the desktop user, or hold an XGrabServer); let GUI input go quiet so B's burst is idle past gui_snapshot_idle.",
   "From an unrelated principal, trigger close_idle_gui_bursts: another sandbox A's POST /sandboxes/{A}/tools/list_dir (service.py:273), or a human GET /audit (api.py:258), or a human POST /approvals/{aid} decide (service.py:385->373).",
   "Observe that the triggering request blocks until B's container becomes responsive again, while B's _busy/tool_concurrency counter stays unchanged."
  ],
  "observed_result": "Decisive reproduction is the parent's (l2_cross.py/.out, real Docker-backed control plane + agentbox-desktop image; I could not run Docker in the sandbox). With B's Xvfb stopped and B's burst idle, sandbox A's list_dir did not return within 20s and returned only 0.3s after B's Xvfb was resumed, confirming A's unrelated tool call blocked on B's untimed GUI exec run on A's tool_pool thread. The h-pool stub run (agents/h-pool/artifacts/h.out) independently showed that B's close runs on A's thread and on the human (expire_stale) thread while B's _busy counter stays 0, confirming the work is charged to no sandbox. Because decide() and GET /audit enter the identical close_idle_gui_bursts path on the Starlette threadpool, a human approval decision or audit read blocks the same way and the blocked thread is leaked for the burst's lifetime (burst popped at service.py:232)."
 },
 "remediation": {
  "strategy": "Put a hard deadline on every docker exec reached from the burst-close and GUI paths (wrap the container command in 'timeout -k' as exec/read_file/outbox_read do, and/or use a client call with a socket timeout), and stop running cross-sandbox maintenance inline on an unrelated caller's thread: close idle bursts in a dedicated background worker, or charge each close to the owning sandbox's tool_concurrency budget and never to another sandbox's tool thread or a human request thread. Guard close_idle_gui_bursts/_close_gui_burst so one unresponsive container is skipped-and-logged after a bounded wait instead of stalling the loop for other sandboxes.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "# Give the maintenance/GUI execs the same deadline exec() uses, so an\n# unresponsive container cannot block the control plane indefinitely.\n@staticmethod\ndef _x(c, argv: list[str]):\n    return c.exec_run([\"timeout\", \"-k\", \"2\", \"15\", *argv], user=DESKTOP_USER,\n                      environment=DESKTOP_ENV, demux=True)\n\ndef workspace_manifest(self, sid):\n    c = self._container(sid)\n    res = c.exec_run([\"timeout\", \"-k\", \"2\", \"15\", \"sh\", \"-c\",\n        f\"find {WORKSPACE} -xdev ! -type d -printf '%P\\\\0%s\\\\0%T@\\\\0%C@\\\\0' | head -c {_MANIFEST_CAP}\"],\n        user=\"0:0\", demux=True)\n    return _parse_manifest(res.output[0] or b\"\")\n\ndef kill_processes(self, sid, pids):\n    if pids:\n        self._desktop(sid).exec_run([\"timeout\", \"-k\", \"2\", \"10\", \"kill\", \"-KILL\", \"--\", *map(str, pids)],\n                                    user=DESKTOP_USER)"
   },
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "# Do not run another sandbox's burst-close inline on the caller's thread.\n# Hand idle-burst closing to a single background worker so a stuck container\n# never blocks an unrelated call_tool, a human approval decision, or GET /audit.\ndef close_idle_gui_bursts(self) -> None:\n    idle = self.sandboxes.settings.gui_snapshot_idle\n    now = time.monotonic()\n    for sid in list(self._gui_burst):\n        if now - self._gui_input_at.get(sid, 0.0) > idle:\n            self._gui_closer.submit(self._close_gui_burst, sid, \"idle\")  # bounded background pool"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Requires a desktop sandbox and the agent to render its own X server/exec unresponsive; the GUI boundary is ungated by design and prompt injection is in the threat model, but weaponizing X unresponsiveness from the lowest-trust principal carries a desktop-image dependency (terminal/launcher reachability, X auth) that the parent demonstrated via a desktop-user action rather than a confirmed uid-1000-only path. The defect also triggers on benign causes (a slow or overloaded desktop container, a slow Docker exec), so exposure is not solely attacker-gated."
  },
  "impact": {
   "score": "high",
   "reason": "A single unresponsive desktop container indefinitely blocks an unrelated sandbox's tool call (demonstrated: 20s, bounded only by the test's external SIGCONT) and, by the identical close_idle_gui_bursts path, a human approval decision (POST /approvals/{aid}) or GET /audit, degrading the human-oversight safety function; the blocked shared control-plane thread (tool_pool of 32 or the Starlette threadpool) is leaked for the burst's lifetime. Single-principal effect is one leaked thread plus one indefinitely blocked cross-tenant request per compromised desktop sandbox (burst popped before close); aggregated across many desktop sandboxes it can exhaust both pools. Cross-tenant, persistent, poor recovery (operator must intervene)."
  },
  "overall_severity": "high"
 },
 "confidence": {
  "score": "high",
  "reason": "The entire source path was verified by reading: service.py:273 (before busy check 275-278), 254-256 (iterates all sandboxes), 232/235, 218 -> sandbox.py:684/690-691 untimed _x exec, with the timeout contrast at 531/561/665 and human entrypoints at api.py:258 and decide->expire_stale (385->373). The decisive runtime behaviour - the untimed exec blocks the caller indefinitely and blocks an unrelated sandbox - was reproduced by the parent against the real Docker-backed control plane and desktop image (agents/parent-live/artifacts/l2_cross.py/.out); I re-read that script and confirmed it exercises exactly this path, and I could not run it myself because the verification sandbox has no Docker. Source contains no deadline or per-sandbox accounting bound that refutes the trace."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.
Checks marked (after Phase 3) were run after this record was written and are not yet reflected in it.

- agents/parent-live/artifacts/l10_bound.out (after Phase 3)
- agents/parent-live/artifacts/l10_bound.py (after Phase 3)
- agents/parent-live/artifacts/l2_cross.out
- agents/parent-live/artifacts/l2_cross.py/.out

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

- Agent ID `p5-v11`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v11/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v11 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v11/artifacts/<file>`.

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
