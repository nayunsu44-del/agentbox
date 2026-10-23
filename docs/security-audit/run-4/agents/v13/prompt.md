You are candidate verifier `v13` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/web.py:unauthenticated-login-failure-audit-growth",
 "title": "Every unauthenticated failed POST /login appends a permanent hash-chained audit row, with no rate limit, cap or retention",
 "description": "web.py:130-139 compares the submitted form token with secrets.compare_digest and, on mismatch, calls box.log_human(\"ui_login_failed\", None, {}) (service.py:590-594 -> audit.append). audit.append takes the single process-wide audit lock, opens BEGIN IMMEDIATE, reads the previous hash, inserts a masked row and commits (audit.py:162-185). Nothing rate-limits, deduplicates, caps or prunes these rows: audit.py contains no DELETE, no retention and no compaction, and the table is the append-only hash chain the operator uses as the security record. The only precondition is same_origin (web.py:132-133), which returns True when the Origin header is absent, so a plain HTTP client reaches the audit write. The same handler shows the inverse gap: a non-ASCII token makes compare_digest raise TypeError (web.py:134), so the request returns a bare 500 before the failure is recorded and the attacker also controls which attempts enter the chain.",
 "root_cause": "An unauthenticated, attacker-paced write into the persistent audit chain: the failed-login path records every attempt through the same serialized append used by tool executions, without a per-source or global rate limit, without aggregation, and without any retention for the rows it creates.",
 "intended_behavior": "Anonymous authentication failures should be rate-limited and aggregated before they reach the audit chain, and the audit store should have a documented retention/compaction scheme, so an unauthenticated client cannot unilaterally grow the security log or monopolize the lock that every other audit append needs.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 131,
   "scope": "POST /login form handler",
   "description": "def login(request: Request, token: str = Form(...)) has no principal and no cookie requirement; the only precondition is same_origin at 132, which passes when Origin is absent."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 134,
   "scope": "token mismatch branch",
   "description": "A wrong token falls through to box.log_human(\"ui_login_failed\", None, {}) at 136 and then renders the error page at 139."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 590,
   "scope": "log_human -> audit.append",
   "description": "log_human forwards the event to the audit log; an AuditWriteError would become a 503, but on success the row is durable in SQLite."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 180,
   "scope": "INSERT INTO audit under the global lock",
   "description": "append() takes self._lock (162), BEGIN IMMEDIATE (163), reads the last hash (165), inserts the row (180) and commits (185); every other audit append and every human read waits on the same lock."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 126,
   "description": "One process-wide threading.Lock serializes all appends."
  },
  {
   "file": "agentbox/audit.py",
   "line": 129,
   "description": "The database runs in WAL mode with no row or page bound; audit.py has no retention, compaction or VACUUM call."
  },
  {
   "file": "agentbox/web.py",
   "line": 132,
   "description": "same_origin returns True when the Origin header is missing, so it does not stop a direct HTTP client."
  },
  {
   "file": "agentbox/config.py",
   "line": 86,
   "description": "The audit database lives at AGENTBOX_HOME/agentbox.db."
  },
  {
   "file": "deploy/docker-compose.yml",
   "line": 28,
   "description": "compose mounts ${AGENTBOX_HOME_DIR} into the container, so audit growth consumes host disk owned by the operator."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "None - a wrong form token and no cookie."
  },
  {
   "kind": "system_configuration",
   "description": "The control plane is reachable through the shipped proxy, and the audit table is persistent and never pruned."
  },
  {
   "kind": "timing_dependency",
   "description": "Rows serialize on the audit lock, which bounds the rate per second but never the total number of rows."
  }
 ],
 "execution": {
  "attacker_perspective": "An unauthenticated client posts the login form with a wrong token as fast as the server answers, adding one durable audit row and one global-lock acquisition per request.",
  "payloads": [
   "POST /login HTTP/1.1\r\nHost: agentbox.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\ntoken=nope",
   "POST /login  ...  token=%C3%BCn%C3%AFcode   (returns 500 and records nothing)"
  ],
  "instructions": [
   "In the approved sandbox, build the real app and drive POST /login at the ASGI layer with urlencoded bodies, no cookie and no Origin header.",
   "Count rows with event='ui_login_failed' before and after each request, and time 50 sequential wrong-token attempts.",
   "Repeat once with a non-ASCII token and compare the row count."
  ],
  "observed_result": "One wrong-token POST added exactly 1 ui_login_failed row; 50 further wrong-token POSTs added 50 more (51 rows) in 0.498 s, about 10 ms per attempt serialized on the audit lock, with no rate limit, cap or rejection at any point. The non-ASCII token request returned 500 (TypeError: comparing strings with non-ASCII characters is not supported) and added 0 rows, so the same client can also keep attempts out of the chain."
 },
 "remediation": {
  "strategy": "Rate-limit and aggregate failed logins before the audit append (a per-client-address token bucket plus a global cap), record a compacted 'N failures since T' summary instead of one row per attempt, and give the audit store a retention scheme that keeps chain verifiability (signed checkpoints plus archived segments). Validate that the token is ASCII (or compare bytes) before compare_digest so a malformed credential is a recorded 401 rather than a bare 500.",
  "code_changes": [
   {
    "file_name": "agentbox/web.py",
    "fixed_code": "    @app.post(\"/login\", include_in_schema=False)\n    def login(request: Request, token: str = Form(...)):\n        if not same_origin(request.headers):\n            raise HTTPException(403, \"다른 출처의 요청\")\n        if not token.isascii() or not secrets.compare_digest(token.strip(), human_token):\n            # 5마다 1건만 기록 + 주소별 초당 상한 (전체 상한은 _login_failures 쪽)\n            if _login_failures.allow(request.client.host if request.client else \"unknown\"):\n                try:\n                    box.log_human(\"ui_login_failed\", None, {})\n                except ServiceError:\n                    pass\n            return render(request, \"login.html\", error=\"사람 토큰이 아님 (에이전트 토큰으로는 들어갈 수 없습니다)\")\n        return start_session(request, \"/ui\", \"token\")"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "A form POST with a wrong token from any client that can reach /login; no cookie, Origin header or token knowledge required."
  },
  "impact": {
   "score": "low",
   "reason": "Unbounded persistent growth of the append-only audit database on the operator's data volume with no pruning path, plus contention on the single audit lock that every tool-call append and every human read needs; the entropy is low (~1 KB and ~10 ms per row), so the effect is slow disk growth rather than immediate outage."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Source trace is complete and the durable row growth and the non-ASCII bypass were both observed locally."
 },
 "x_proposed_by": "h-preauth"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29",
  "surface": "Unauthenticated network requests handled before any principal check: JSON and multipart bodies on POST /sandboxes, /sandboxes/{sid}/tools/{tool}, /sandboxes/{sid}/restore, /approvals/{aid} and POST /sandboxes/{sid}/files; the POST /login form; GET /static/novnc/{path}; GET /sandboxes/{sid}/desktop?ticket=; GET /healthz",
  "boundary": "Network attacker with no token -> control-plane memory, the /tmp multipart spool, the Docker daemon and the audit chain. FastAPI reads and parses the body before it resolves the principal and screen_human dependencies (agentbox/api.py:206-224, models at 44-60). The tool-args body cap that critic checks only guard authenticated agent args. extract_novnc runs docker create, get_archive into memory and extractall per request (agentbox/sandbox.py:774-798, api.py:431-437). Each failed POST /login appends a ui_login_failed audit row (agentbox/web.py:117-123). deploy/Caddyfile has no request_body limit.",
  "local_checks": [
   {
    "agent_id": "h-preauth",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/cli.py",
     "deploy/Caddyfile",
     "agentbox/config.py",
     "agentbox/service.py",
     "deploy/docker-compose.yml"
    ],
    "invariant": "No pre-authentication request-body bound anywhere in front of FastAPI's body parsing",
    "method": "local",
    "result": "Unauthenticated POSTs with a 16,777,220-byte JSON body were fully consumed and JSON-decoded before the 401 on /sandboxes, /sandboxes/{sid}/tools/exec, /sandboxes/{sid}/restore and /approvals/{id}; a 4 MiB multipart part was rolled onto disk in a SpooledTemporaryFile before the 401 on /sandboxes/{sid}/files. The only middleware is _NoFraming, uvicorn is started without size limits, and deploy/Caddyfile has no request_body directive.",
    "artifact": "agents/h-preauth/artifacts/h.out"
   },
   {
    "agent_id": "h-preauth",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "Unauthenticated static-asset route does not perform per-request Docker-daemon work",
    "method": "local",
    "result": "With home/novnc absent, six concurrent unauthenticated GET /static/novnc/core/rfb.js made six containers.create calls and five returned 500 (FileExistsError); the steady state made zero; three GETs for a non-existent asset each made another create call.",
    "artifact": "agents/h-preauth/artifacts/h3.out"
   },
   {
    "agent_id": "h-preauth",
    "reviewed_paths": [
     "agentbox/web.py",
     "agentbox/service.py",
     "agentbox/audit.py"
    ],
    "invariant": "Unauthenticated requests cannot grow the persistent audit chain without bound",
    "method": "local",
    "result": "51 wrong-token POST /login requests produced 51 durable ui_login_failed rows in 0.498 s (~10 ms each, serialized on the audit lock), with no cap, rate limit or retention; a non-ASCII token produced 0 rows because compare_digest raises before the append.",
    "artifact": "agents/h-preauth/artifacts/h.out"
   },
   {
    "agent_id": "h-preauth",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/api.py"
    ],
    "invariant": "The remaining unauthenticated routes do bounded work",
    "method": "source",
    "result": "GET /healthz returns a constant JSON object without touching a principal or a body (api.py:368-371). Ticket redemption for /sandboxes/{sid}/desktop?ticket= does one hashed SELECT plus one DELETE in ui_tickets and returns 403 on mismatch (desktop.py:118-128); it parses no body, runs no docker call and creates no session row for a bad ticket.",
    "artifact": null
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

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance -->
**Pre-authentication work imbalance**
Expensive parsing, key lookup, cryptography, decompression, or external requests happen before authentication and the earliest size/rate gate. Compare minimal requester effort to shared service cost and check upstream limits.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#File descriptor, handle, and temporary-resource leaks -->
**File descriptor, handle, and temporary-resource leaks**
Malformed or canceled work misses cleanup and retains sockets, files, database cursors, timers, subprocesses, temporary files, or object references. Confirm the leak repeats through bounded local iterations and affects a shared pool.

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

- Agent ID `v13`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v13/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v13 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v13 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
