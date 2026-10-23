You are final record verifier `r01` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
 "title": "Unauthenticated request bodies are fully read, JSON-decoded and multipart-spooled before the principal dependency rejects the request",
 "description": "agentbox's body routes declare a request-body model - or a File(...) list - together with Depends(principal) / human_only / screen_human (agentbox/api.py:175, 206, 216, 251, 277). In FastAPI's request handler the body is read and JSON-decoded - and on the upload route streamed through request.form() and spooled - before solve_dependencies resolves any of those dependencies, so an unauthenticated client decides how many bytes the control plane buffers, decodes and writes to TMPDIR before it is told 401. Nothing in the tree bounds that work: the only middleware is _NoFraming (api.py:63-80, registered at 113), the serve entry point passes no request-size or concurrency limit to uvicorn (agentbox/cli.py:127), and the shipped Caddy front end has no request_body directive (deploy/Caddyfile:5). The caps that do exist - max_upload_bytes per file (config.py:57, enforced inside the endpoint at api.py:278-283) and LOGGED_ARGS_MAX (service.py:37-38) - run only after a principal exists. Starlette's multipart parser bounds part cardinality (1000 files/fields) and 1 MiB for non-file fields, but not file-part bytes.",
 "root_cause": "Authentication dependencies run after FastAPI's body-parsing stage, and nothing in front of the app - ASGI middleware, uvicorn options, or the bundled Caddy reverse proxy - enforces a maximum request-body size, so unauthenticated work scales with the attacker's body size instead of with the negligible work needed to reject an unauthenticated request.",
 "intended_behavior": "Requests that cannot yet be authenticated should be rejected before their body is buffered, decoded or written to disk, and bodies above a documented cap should be refused with 413 regardless of credential state.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 174,
   "scope": "POST /sandboxes, and every sibling body route: /sandboxes/{sid}/restore (205-206), /sandboxes/{sid}/tools/{tool} (215-216), /approvals/{aid} (250-251), /sandboxes/{sid}/files (276-277)",
   "description": "A lower-trust network client with no token reaches a route that declares both a body (CreateSandbox) and Depends(human_only). Declaring the body is what makes FastAPI's handler stage read and JSON-decode the whole request body before any dependency is solved (verified in the installed fastapi 0.161.1 get_request_handler source: body read/decode block precedes the solve_dependencies call)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 115,
   "scope": "principal() - first credential check for the JSON API; human_only and screen_human build on it",
   "description": "principal() compare_digest's the bearer token (119), looks up an agent token (121) and raises 401 at 117/124. It runs only after the body stage, so no principal exists while the body is buffered and decoded."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 277,
   "scope": "POST /sandboxes/{sid}/files multipart body",
   "description": "files: list[UploadFile] = File(...) makes the handler call request.form() before screen_human runs; Starlette streams the whole multipart body and rolls every file part past the 1 MiB spool threshold into a SpooledTemporaryFile under the control plane's TMPDIR."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 278,
   "scope": "per-file cap applied after parsing and after authentication",
   "description": "limit = settings.max_upload_bytes with await f.read(limit + 1) at 281-283 executes only inside the endpoint, i.e. after the whole body has been spooled and only when a principal was already accepted, so it cannot bound pre-auth work."
  },
  {
   "kind": "sink",
   "file": "agentbox/api.py",
   "line": 113,
   "scope": "the only middleware installed on the app (no body-size gate on the way into FastAPI's body stage)",
   "description": "_NoFraming is the last app-owned code a request passes, and it only appends response headers. With cli.py:127 and deploy/Caddyfile:5 adding no limit either, the attacker-chosen body becomes control-plane heap and temp-disk state before principal()/screen_human can reject it."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 63,
   "description": "_NoFraming (63-80), registered at 113, is the app's only middleware: app.add_middleware appears exactly once in the tree, so there is no body-limit middleware."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 5,
   "description": "reverse_proxy agentbox:8765 with no request_body directive: the shipped proxy forwards request bodies without a size bound."
  },
  {
   "file": "agentbox/config.py",
   "line": 57,
   "description": "The only upload bound is max_upload_bytes (50 MiB per file by default); it is consumed inside the endpoint at api.py:278-283, after parsing and after authentication."
  },
  {
   "file": "agentbox/service.py",
   "line": 37,
   "description": "LOGGED_ARGS_MAX / LOGGED_ARGS_HEAD (37-38) cap only the audit copy of tool args, after a principal is established."
  },
  {
   "file": "deploy/docker-compose.yml",
   "line": 22,
   "description": "The compose deployment runs the single agentbox service behind Caddy with AGENTBOX_BEHIND_TLS_PROXY=1, no mem_limit and no request-size limit, exposing 8765 only on the compose network."
  },
  {
   "file": "deploy/Dockerfile",
   "line": 17,
   "description": "CMD agentbox serve --host 0.0.0.0 --port 8765 --behind-tls-proxy: the one uvicorn process (cli.py:127) serves the JSON API, the approval UI and the audit chain, so buffered bytes hit shared availability rather than one isolated worker."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "None: no Authorization header and no session cookie are required for the buffering; every tested path returned 401 only after the body had been consumed."
  },
  {
   "kind": "network_routing",
   "description": "The client can reach the control plane through the shipped Caddy front end (compose publishes 443/80 and forwards bodies without a size directive), or directly when agentbox serve is used."
  },
  {
   "kind": "environmental_dependency",
   "description": "Impact scales with the memory and TMPDIR of the single uvicorn process that also serves the human approval queue and the audit chain; the compose service sets no mem_limit, so exhausting the process takes the approval path down with it (pending approvals, 300 s default, age toward timeout while the operator restarts)."
  }
 ],
 "execution": {
  "attacker_perspective": "An unauthenticated network client that never holds a token sends bodies of its choosing to routes it knows will answer 401, or to the upload route, and lets the control plane read, decode and spool them. The attacker's spend is the bytes it uploads, while the server retains about twice that in heap per in-flight body (measured), with no per-request and no concurrency bound in the shipped configuration.",
  "payloads": [
   "POST /sandboxes HTTP/1.1\r\nHost: agentbox.example.com\r\nContent-Type: application/json\r\nContent-Length: 16777216\r\n\r\n{\"source_dir\": null, \"template\": \"cli\", \"pad\": \"AAAA...\"}",
   "POST /sandboxes/sid1/files HTTP/1.1\r\nHost: agentbox.example.com\r\nContent-Type: multipart/form-data; boundary=X-BOUNDARY\r\n\r\n--X-BOUNDARY\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n<4194304 bytes>\r\n--X-BOUNDARY--\r\n"
  ],
  "instructions": [
   "Inside the approved OS sandbox only (no network, no Docker socket, 512 MiB, 1 CPU, uid 65534, 120 s), with /target read-only on PYTHONPATH and AGENTBOX_HOME under /scratch: replace docker.from_env with an in-process fake whose info() reports only the runc runtime, then build the real app with api.build(Settings()) from the audited tree.",
   "Drive the app at the ASGI layer with an HTTP scope for the target path and a receive() that streams the declared body in 64 KiB http.request messages, recording how many body bytes the app consumed before it emitted http.response.start.",
   "Patch starlette.requests.Request.json to record len(raw body) at decode time, and starlette.formparsers.SpooledTemporaryFile to record max_size, bytes written, whether it rolled to a real temporary file and that file's on-disk size under TMPDIR.",
   "Send the payloads with no Authorization header and no cookie; record the status, the bytes consumed before the response started, and the decode/spool records. Read resource.getrusage(RUSAGE_SELF).ru_maxrss before and after the largest JSON request to bound the memory effect. Keep the largest body at 16 MiB so the sandbox limit is never approached, and stop after the first confirming observation.",
   "Send a control request (GET /healthz, no body) through the same driver to prove the app object is functional and the 401 comes from the credential check."
  ],
  "observed_result": "Installed stack: fastapi 0.161.1, starlette 1.9.0, uvicorn 0.54.0. POST /sandboxes with a 16,777,216-byte JSON body and no Authorization returned 401, but the app had consumed all 16,777,216 bytes before emitting http.response.start and Request.json() had decoded 16,777,216 bytes; peak RSS grew 32,768 KiB (2.0x the body). /sandboxes/{sid}/tools/exec, /sandboxes/{sid}/restore and /approvals/{aid} behaved identically with 4,194,304-byte bodies - all bytes consumed and decoded before the 401. POST /sandboxes/{sid}/files with one 4,194,304-byte part and no cookie returned 401 after consuming all 4,194,442 bytes; at that moment the SpooledTemporaryFile (max_size 1,048,576) had rolled to a real temporary file holding 4,194,184 bytes in TMPDIR, the endpoint's 50 MiB per-file cap never ran, and the temporary file was removed when the form closed (no residue afterwards). A control GET /healthz returned 200 with 0 body bytes consumed. The installed multipart parser carries max_files/max_fields = 1000 and max_part_size = 1 MiB, but max_part_size is applied only to non-file fields, so a 4 MiB file part passed untouched."
 },
 "remediation": {
  "strategy": "Reject oversized bodies before FastAPI's body stage and before any authentication work: install an ASGI middleware beside _NoFraming that answers 413 when the declared Content-Length already exceeds the cap and counts streamed bytes for chunked bodies, aborting at the cap; keep the application/JSON cap above the largest legitimate body (write_file content is bounded by max_write_bytes = 1 MiB, so a 64 KiB JSON cap would break authenticated tool calls) and give the multipart route an aggregate body cap from a new setting (default e.g. 64 MiB for the whole request, not per file); and add request_body { max_size ... } to deploy/Caddyfile so the shipped proxy refuses the same oversized bodies before they reach the process.",
  "code_changes": [
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "# from starlette.requests import ClientDisconnect\n\nclass _BodyLimit:\n    \"\"\"FastAPI가 본문을 읽기 전에 크기 상한을 강제한다 (인증 전, 보안 검수 run-4 v01).\"\"\"\n\n    def __init__(self, app, json_max: int, upload_max: int):\n        self.app, self.json_max, self.upload_max = app, json_max, upload_max\n\n    def _cap(self, scope) -> int:\n        return self.upload_max if scope.get(\"path\", \"\").endswith(\"/files\") else self.json_max\n\n    async def __call__(self, scope, receive, send):\n        if scope[\"type\"] != \"http\":\n            return await self.app(scope, receive, send)\n        cap = self._cap(scope)\n        declared = None\n        for name, value in scope[\"headers\"]:\n            if name == b\"content-length\":\n                try:\n                    declared = int(value)\n                except ValueError:\n                    declared = None\n        if declared is not None and declared > cap:\n            return await Response(\"요청 본문이 너무 큼\", status_code=413)(scope, receive, send)\n        seen = 0\n\n        async def limited():\n            nonlocal seen\n            message = await receive()\n            seen += len(message.get(\"body\", b\"\"))\n            if seen > cap:\n                raise ClientDisconnect()   # 스트리밍 본문이 상한을 넘으면 연결을 끊는다\n            return message\n\n        return await self.app(scope, limited, send)\n\n    # _NoFraming 등록 옆에:\n    app.add_middleware(_BodyLimit, json_max=settings.max_body_bytes,\n                       upload_max=settings.max_upload_body_bytes)"
   },
   {
    "file_name": "agentbox/config.py",
    "fixed_code": "    # FastAPI가 본문을 읽기 전에 거부할 요청 본문 상한. write_file 인자(max_write_bytes)보다 커야 한다.\n    max_body_bytes: int = field(default_factory=lambda: int(_env(\"AGENTBOX_MAX_BODY\", str(4 * 1024 * 1024))))\n    # 업로드 경로의 요청 전체 상한 (파일 하나가 아니라 한 요청)\n    max_upload_body_bytes: int = field(\n        default_factory=lambda: int(_env(\"AGENTBOX_MAX_UPLOAD_BODY\", str(64 * 1024 * 1024))))"
   },
   {
    "file_name": "deploy/Caddyfile",
    "fixed_code": "{$AGENTBOX_SITE} {\n\trequest_body {\n\t\tmax_size 64MB\n\t}\n\treverse_proxy agentbox:8765\n}"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "No token, no interaction and no knowledge beyond the route list: one ordinary HTTP request whose declared body the attacker chooses, and the same request works on four JSON routes and the upload route."
  },
  "impact": {
   "score": "medium",
   "reason": "Availability of the single control-plane process that also serves the human approval queue and the audit chain: memory grows about 2x the bytes sent per request (measured +32 MiB for a 16 MiB body), there is no per-request body cap and no concurrency limit, so retained memory scales with concurrent in-flight bodies; the decode/parse of the buffered body runs in the request task on the event loop, stalling unrelated requests while it works, and the multipart path also writes attacker-sized bytes to the container's TMPDIR. No confidentiality or integrity boundary is crossed, and an operator who adds a proxy body cap or a container mem_limit removes the effect."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Every cited line exists in the audited tree at 9805d91 (trace and evidence re-read line by line), and an independent ASGI-level reproduction on the real app object with the installed fastapi 0.161.1 / starlette 1.9.0 reproduced the claimed result: the full body was consumed and decoded before the 401, and the multipart part was on disk before the 401. No middleware, uvicorn option or shipped proxy directive bounds the body. The ordering is FastAPI/Starlette default behaviour (calibration only, since the architecture summary names no comparable product baseline); agentbox bounds its other resource paths explicitly (tool_pool, PENDING_APPROVALS_MAX, max_upload_bytes, LOGGED_ARGS_MAX), so this omission is not a deliberate design choice."
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

# Execution boundary and paths

- Agent ID `r01`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r01/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r01 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r01 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/api.py:preauth-request-body-read-before-principal"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
