You are candidate verifier `v-preauth` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/api.py:preauth-request-body-read-before-principal",
 "title": "Unauthenticated JSON bodies are still decoded before principal(); an 8 MiB body that passes the cap becomes about 220 MB of objects",
 "description": "The F1 fix (PR #16) caps every request body before routing, at 8 MiB (AGENTBOX_MAX_BODY) for JSON routes. FastAPI still reads and json.loads the body before it resolves the principal/human_only dependencies. The 8 MiB cap is the same for unauthenticated clients as for authenticated write_file calls. A body of empty objects decodes at about 26x its size, so one unauthenticated request with no token allocates about 220 MB of transient Python objects and about 0.35 s of event-loop CPU before it gets a 401. The fix bounds the work per request but does not tie it to authentication. How many such requests overlap in memory depends on concurrency and threadpool latency. Nothing in the repository bounds either one: there is no uvicorn limit_concurrency and no compose memory limit, and Caddy allows 256MB per request.",
 "claimed_root_cause": "Authentication dependencies still run after FastAPI's body-reading and JSON-decoding stage (fastapi routing get_request_handler reads request.body()/request.json() before solve_dependencies). The only pre-auth bound is a byte cap sized for the largest authenticated payload, with no smaller cap for requests that have no credentials and no limit on concurrent pre-auth decodes. Pre-auth memory is therefore bytes x JSON amplification (~26x) x concurrent requests, not the negligible cost of rejecting a missing token.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "call_tool route POST /sandboxes/{sid}/tools/{tool} (body: ToolCall, Depends(principal)); same for create_sandbox api.py:233, restore, decide",
   "description": "Unauthenticated client sends a JSON body of up to 8 MiB with no Authorization header."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 111,
   "scope": "_BodyLimit.__call__",
   "description": "Only check before routing: the body must be at most max_body_bytes (8 MiB, config.py:65). It is not tied to whether the request has credentials."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 122,
   "scope": "_BodyLimit.limited_receive",
   "description": "Streamed bytes are counted up to the cap and passed to the app."
  },
  {
   "kind": "sink",
   "file": "agentbox/api.py",
   "line": 173,
   "scope": "principal dependency",
   "description": "Runs only after FastAPI has buffered the body and json.loads produced the full object graph (about 26x the body size). Then 401."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 170,
   "description": "_BodyLimit installed with json_max=settings.max_body_bytes for every non-upload route regardless of authentication."
  },
  {
   "file": "agentbox/config.py",
   "line": 65,
   "description": "max_body_bytes defaults to 8 MiB (sized so that an escaped 1 MiB write_file fits)."
  },
  {
   "file": "agentbox/api.py",
   "line": 274,
   "description": "call_tool declares body: ToolCall plus Depends(principal). FastAPI decodes the body before the dependency runs. Local check: 1.05 MB -> 27.4 MB peak, 2.10 MB -> 54.9 MB peak, both 401 (agents/h-bodylimit/artifacts/h.out T7)."
  },
  {
   "file": "agentbox/cli.py",
   "line": 127,
   "description": "uvicorn.run has no limit_concurrency. Concurrent pre-auth decodes are unbounded in source."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 8,
   "description": "Proxy request_body max_size defaults to 256MB for all routes and does not enforce the 8 MiB JSON cap or anything smaller."
  }
 ],
 "blockers": [
  "Whether the transient ~220 MB per 8 MiB request turns into control-plane OOM or a stall for the human UI and agents depends on deployed host/container memory and on how many decoded bodies overlap (threadpool latency, concurrency). Both are outside the repository. A safe sandbox check (512 MiB) could only measure single requests at 1-2 MiB.",
  "Overlap of several decoded bodies needs a live uvicorn server with concurrent connections. Starting a server and running concurrent load was outside the hunter sandbox rules."
 ],
 "validation_plan": {
  "local": "Run agentbox serve on loopback in a disposable container with a fixed memory limit (e.g. 1 GiB) and a dummy human token. Send one unauthenticated POST /sandboxes/sb_x/tools/exec with Content-Type application/json and an 8 MiB body {\"args\":{\"a\":[{},{},...]}}. Record the 401 and the peak RSS increase of the uvicorn process (expected about 220 MB). Then send 3-4 such requests concurrently while a sync human route holds threadpool slots, and record peak RSS and whether a human GET /healthz or /ui is delayed. Stop at the first OOM-kill or at peak RSS above half the limit. Regression after the fix: the same requests without credentials get 413 or 401 with no measurable RSS growth.",
  "deployment": "Owner checks the memory limit of the agentbox control-plane container or host and whether the TLS proxy enforces a JSON-route body cap smaller than 8 MiB. The bundled Caddyfile allows 256MB on every route."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Every%20HTTP%20request%20before%20routing%20and%20authentication%3A%20_BodyLimit%20ASGI%20middleware%20%28Content-Length%20and%20streamed%20bodies%2C%20upload%20path%20selection%29%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%20multipart%20form%20%2B%20the%20%2Fui%20upload%20form%20%2B%20deploy%2FCaddyfile%20request_body::Pre-authentication%20and%20per-request%20body%20caps%20%28F1%20fix%2C%20PR%20%2316%29%3A%20JSON%2Fform%20bodies%20capped%20at%20AGENTBOX_MAX_BODY%2C%20uploads%20at%20AGENTBOX_MAX_UPLOAD_BODY%20selected%20by%20method%20and%20path%20regex%2C%20multipart%20parsed%20only%20after%20screen_human.%20Invariant%3A%20an%20unauthenticated%20or%20agent%20client%20cannot%20make%20the%20server%20buffer%2C%20parse%20or%20spool%20more%20than%20the%20cap%20%28or%20hang%20a%20worker%29%20before%20auth%2C%20through%20any%20HTTP%20framing%20%28chunked%2C%20missing%20or%20duplicate%20Content-Length%2C%20path%20variants%2C%20HEAD%2Fother%20methods%2C%20root_path%29.::agentbox%2Fapi.py%23_BodyLimit%2F_UPLOAD_PATH%2Fput_files%2Fbuild%20%2B%20agentbox%2Fweb.py%23upload%20form%20%2B%20agentbox%2Fconfig.py%23max_body_bytes%2Fmax_upload_body_bytes%20%2B%20deploy%2FCaddyfile::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance",
  "surface": "Every HTTP request before routing and authentication: _BodyLimit ASGI middleware (Content-Length and streamed bodies, upload path selection) + POST /sandboxes/{sid}/files multipart form + the /ui upload form + deploy/Caddyfile request_body",
  "boundary": "Pre-authentication and per-request body caps (F1 fix, PR #16): JSON/form bodies capped at AGENTBOX_MAX_BODY, uploads at AGENTBOX_MAX_UPLOAD_BODY selected by method and path regex, multipart parsed only after screen_human. Invariant: an unauthenticated or agent client cannot make the server buffer, parse or spool more than the cap (or hang a worker) before auth, through any HTTP framing (chunked, missing or duplicate Content-Length, path variants, HEAD/other methods, root_path).",
  "local_checks": [
   {
    "agent_id": "h-bodylimit",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/config.py",
     "tests/test_m4_unit.py"
    ],
    "invariant": "_BodyLimit (api.py:89-148, added at api.py:170) bounds every http-scope body before routing/auth under all framings: Content-Length over cap or non-digit, chunked/no Content-Length, duplicate Content-Length, path/method variants, root_path.",
    "method": "local",
    "result": "Drove the real build() ASGI app (fake docker client, raw ASGI messages) in the sbx sandbox. CL 9 MiB on POST /sandboxes -> 413 with 0 bytes read; CL '+2' -> 413 unread; duplicate CL (999999999999 then 2; dict keeps last) with 10 MiB streamed -> 413 after 9 MiB delivered to the middleware, the app never sees more than 8 MiB; chunked 10 MiB -> 413, same; PUT /sandboxes/x/files -> 405, POST .../files/ -> 307, //sandboxes/x/files -> 404, all under the 8 MiB JSON cap with 0 bytes read; unauthenticated POST /sandboxes/x/files with 10 MiB -> 401 with 0 bytes read (form parsed only after screen_human, api.py:336-340). root_path-prefixed scope paths do not match _UPLOAD_PATH, so they get the smaller 8 MiB cap (fails closed, functional only). After the fake http.disconnect FastAPI handles ClientDisconnect and guarded_send drops later messages; exactly one response.start was sent. A 5000-digit Content-Length makes int() raise ValueError inside _BodyLimit (500 for that request only; in deployment h11 parses Content-Length first). The byte cap holds in every framing.",
    "artifact": "agents/h-bodylimit/artifacts/h.out"
   },
   {
    "agent_id": "h-bodylimit",
    "reviewed_paths": [
     "agentbox/web.py",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "Unauthenticated form routes (/login Form, /ui/sandboxes Form) cannot be made to parse or spool more than the cap before auth.",
    "method": "local",
    "result": "POST /login with 10 MiB urlencoded body -> 400 'Field exceeded maximum size of 1024KB' after 2 MiB read (Starlette 1.7.0 FormParser max_part_size/max_fields=1000). Multipart /login with 900 file parts (961 KB) is parsed and spooled into SpooledTemporaryFile objects before the token check (status 200 failed-login page), which is bounded by the 8 MiB cap and max_files=1000 and closed by FastAPI's file_stack. The /ui upload form (templates/sandbox.html:51-53) posts to the same /sandboxes/{sid}/files route, so there is no separate upload parser. Login-failure audit rows (prior agentbox/web.py:unauthenticated-login-failure-audit-growth) are now rate-logged at 5 per 60 s globally with a suppressed count (web.py:89-114) and are removable via the host prune command, so the prior root cause of unbounded attacker-paced rows no longer holds.",
    "artifact": "agents/h-bodylimit/artifacts/h.out"
   },
   {
    "agent_id": "h-bodylimit",
    "reviewed_paths": [
     "agentbox/api.py"
    ],
    "invariant": "An unauthenticated client's work before principal() is small and does not scale far beyond the body cap (prior agentbox/api.py:preauth-request-body-read-before-principal).",
    "method": "local",
    "result": "Variant not covered by the fix: FastAPI still reads the body and runs json.loads before solve_dependencies, so principal() runs only after decoding. An unauthenticated POST /sandboxes/sb_x/tools/exec with body {\"args\":{\"a\":[{},{},...]}} returned 401 with tracemalloc peak 27.4 MB for 1.05 MB and 54.9 MB for 2.10 MB (26x, linear). By extrapolation one request at the 8 MiB default cap allocates about 220 MB of transient Python objects before rejection, plus about 80 ms of event-loop CPU per 2 MiB (about 0.35 s per 8 MiB). The 8 MiB cap was sized for authenticated write_file, but every JSON route gets it before auth. The deploy has no memory limit in docker-compose and no uvicorn limit_concurrency (cli.py:127). Caddy's request_body default is 256MB for all routes (deploy/Caddyfile:7-8), so the proxy does not bound JSON routes.",
    "artifact": "agents/h-bodylimit/artifacts/h.out"
   },
   {
    "agent_id": "h-bodylimit",
    "reviewed_paths": [
     "deploy/Caddyfile",
     "agentbox/cli.py"
    ],
    "invariant": "Deployment layers in front of the cap.",
    "method": "source",
    "result": "Caddyfile request_body max_size defaults to 256MB for every route (no per-route JSON cap). uvicorn.run (cli.py:127) passes no limit_concurrency, h11_max_incomplete_event_size or body-read timeout, so connections that trickle a body are not timed out. That is uvicorn's general behavior and holds no thread. httptools is not installed in this environment, so h11 0.16 is used, and h11 rejects conflicting duplicate Content-Length values before the app runs.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-4 wording)

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

# Parent-live evidence

- `agents/parent-live/artifacts/preauth_json.json`

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

<!-- WEB-PROTOCOL-AND-AUTH.md#Request framing and desynchronization -->
**Request framing and desynchronization**
Front end and back end disagree on request length or header normalization. Review multiple `Content-Length` values, `Transfer-Encoding`, HTTP/2 or HTTP/3 downgrade, header-name normalization, forbidden connection headers, and CR/LF conversion. Confirm which bytes one component assigns to a request and which bytes its peer assigns to the next request.

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

- Agent ID `v-preauth`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-preauth/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-preauth <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-preauth /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
