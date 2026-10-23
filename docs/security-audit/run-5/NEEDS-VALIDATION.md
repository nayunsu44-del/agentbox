# run-5 검증 필요 항목

소스로는 성립하지만, 이 감사 환경에서 결정적 증거를 만들지 못한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.

## N1. 인증 없는 JSON 본문을 principal() 전에 해석한다. 8MiB 요청 하나가 401 전에 약 200MB를 쓰고, 512MiB 제한에서는 동시 4건에 서버가 OOM으로 죽었다

- 지문: `agentbox/api.py:preauth-request-body-read-before-principal`
- 경로: `agentbox/api.py:274`(진입점), `agentbox/api.py:105`(전파), `agentbox/api.py:115`(전파), `agentbox/api.py:173`(도달점)

**설명.** run-4 F1 수정(PR #16)으로 본문 바이트는 라우팅 전에 8MiB로 묶였다. 그러나 이 상한은 인증 여부와 같고, FastAPI는 본문을 읽고 JSON을 해석한 뒤에야 `principal`·`human_only`를 푼다(모든 JSON 라우트에서 이벤트 루프 위에서). 빈 객체로 된 JSON은 크기의 약 26배 객체가 된다. 실제 uvicorn 서버에서 토큰 없는 8MiB 요청 하나가 RSS를 59→260MB로 올렸다(401). 1GiB 제한에서는 동시 8건까지 살아남았고(최고 734MB), 512MiB 제한에서는 동시 4건에 프로세스가 OOM으로 죽었다(exit -9, 세 번 재현). 실제 배포가 죽는지는 배포의 메모리 제한에 달렸다.

**주장하는 근본 원인.** 인증 의존성이 FastAPI의 본문 해석 뒤에 돈다. 인증 전 상한은 인증된 최대 요청에 맞춘 8MiB 바이트 상한 하나뿐이고, JSON 확대율, 자격 증명 없는 요청의 작은 상한, 인증 전 해석의 동시성 상한이 없다.

**막힌 지점.**

- 배포의 메모리 제한은 저장소 밖이다. compose에는 제한이 없다. 1GiB에서는 동시 8건을 견뎠고 512MiB에서는 동시 4건에 죽었다.
- 지속 부하 때의 이벤트 루프 굶주림과 재시작·복구 시간은 측정하지 않았다(부하 시험 금지). compose는 `restart: unless-stopped`다.
- 배포 앞단(엣지)이 더 작은 본문 상한이나 연결·속도 제한을 둘 수 있다. 동봉 Caddyfile은 모든 경로에 256MB다.

**검증 계획.** 로컬 OOM은 이미 세 번 재현했다(부모, r-preauth, rv-preauth). 남은 것은 수정 확인이다: 자격 증명 없는 JSON 요청을 본문을 읽기 전에 거절하거나 작은 상한을 둔 뒤, 같은 스크립트를 512MiB 제한에서 동시 4건으로 다시 돌려 401/413과 RSS 무증가를 본다. 배포 쪽은 메모리 제한, 엣지의 본문·속도 제한, 1초 이상 멈춤이나 재시작을 받아들일지를 소유자가 정한다.

**부모 실측 (에이전트 예산 밖).** 실측 결과는 5단계·재검증을 거쳐 레코드에 들어갔다. 판정은 배포의 메모리 제한을 몰라 검증 필요로 남았다.

- 1GiB: 단건 401(0.69초, RSS 59→260MB), 동시 4건 최고 703MB·그 사이 `/healthz` 1.23초, 동시 8건 최고 734MB·생존.
- 512MiB: 단건 401(최고 267MB), 동시 4건에서 연결 리셋·exit -9(OOM). r-preauth·rv-preauth가 각자 같은 결과를 냈다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The F1 fix (PR #16) caps request bodies before routing, at 8 MiB (AGENTBOX_MAX_BODY) for JSON routes. That cap is identical for unauthenticated and authenticated clients. FastAPI's get_request_handler (fastapi 0.161.1, routing.py:428-471) awaits request.body() and decodes the JSON in its async request handler before solve_dependencies (routing.py:511) runs principal()/human_only. Because the decode happens in that async handler, it runs on the event loop for every JSON-body route, including the sync create_sandbox, restore and decide routes as well as the async call_tool (api.py:274). A body of empty objects decodes at about 26x its size (hunter tracemalloc: 27.4 MB peak for 1.05 MB, 54.9 MB for 2.10 MB, both 401). Whole-process growth for an 8 MiB body is about 24x (RSS 59 MB to 260 MB). Parent-live check on a real uvicorn server (127.0.0.1, stub Docker client, dummy human token, no Authorization header, 8,388,580-byte body to POST /sandboxes/sb_x/tools/exec). At a 1 GiB container limit: idle RSS 59 MB; one request returned 401 after 0.69 s with RSS 260 MB afterwards and a high-water mark of 268 MB; four concurrent requests reached a 703 MB high-water mark and a human GET /healthz sent during the burst took 1.23 s against 0.003 s idle; eight concurrent requests reached 734 MB, all answered 401 in under 4 s, healthz 0.47 s; the server stayed alive. At a 512 MiB container limit: one request returned 401 (hwm 267 MB), but four concurrent unauthenticated 8 MiB requests got connection resets and the server process was OOM-killed (exit -9). Two later independent runs of the same script in 512 MiB no-swap sandboxes (r-preauth, then rv-preauth) reproduced the pattern: single request 401 in 0.28 s and 0.75 s with hwm 268 and 267 MB, then four concurrent requests were reset and the server exited -9. So the amplification, the missing authentication ordering, and process death under a memory limit are reproduced. Whether any real deployment is affected depends on its memory limit and host RAM, which the repository does not fix: deploy/docker-compose.yml sets no mem_limit, cli.py:127 passes no limit_concurrency, and the bundled Caddyfile allows 256MB per request by default. In the 512 MiB run the container supervisor policy in the repository (restart: unless-stopped) would restart the process. The attacker's cost in that case is about 32 MiB of upload (four 8 MiB bodies), with in-flight requests lost during the restart and the human approval UI and audit chain unavailable meanwhile. Pending approvals live in SQLite and are not shown to be lost. The run-4 finding (unbounded body size, multipart spooling) is fixed: bytes are now capped and the upload form is parsed only after screen_human. What remains is bounded per-request work, about 25x memory amplification, that is not tied to authentication.

**claimed_root_cause** Authentication dependencies run after FastAPI's body-reading and JSON-decoding stage. The only pre-auth bound is a byte cap (8 MiB) sized for the largest authenticated payload (an escaped 1 MiB write_file). It does not account for the roughly 26x object-graph amplification of JSON. There is no smaller cap or credential check for requests that carry no Authorization header, and no concurrency limit on pre-auth decodes (no uvicorn limit_concurrency, no container memory limit in the shipped compose file, no proxy JSON-route cap below 256MB).

**trace**

- `agentbox/api.py:274` (entrypoint, POST /sandboxes/{sid}/tools/{tool} (async call_tool, body: ToolCall, Depends(principal)); same shape at create_sandbox api.py:233, restore api.py:264, decide api.py:309) — A client with no token sends a JSON body of up to 8 MiB to a route it knows answers 401.
- `agentbox/api.py:105` (propagation, _BodyLimit.__call__ (installed at api.py:170)) — Content-Length is checked against the cap only (8 MiB for non-upload routes, cap from config.py:65). The check is independent of whether credentials are present.
- `agentbox/api.py:115` (propagation, _BodyLimit.limited_receive) — Streamed bytes are counted up to the cap and handed to the app. Bodies at or under 8 MiB pass unchanged.
- `agentbox/api.py:173` (sink, principal() dependency) — Runs only after FastAPI has buffered the body (await request.body()) and decoded the JSON into the full object graph (about 26x the body for empty objects), in the async request handler on the event loop. It then raises 401 at the missing Authorization header.

**blockers**

- Deployed memory limit of the agentbox control-plane container or host is outside the repository. The compose file sets none. The 1 GiB test survived 8 concurrent 8 MiB requests (734 MB hwm) and the 512 MiB test was OOM-killed by 4, so whether a real deployment dies depends on a limit or host RAM that the owner sets.
- Sustained-load behavior (event-loop starvation of the human UI and approvals under repeated pre-auth requests) and the actual restart and recovery time were not measured, because the audit rules forbid stress or saturation testing. The measured stall was about 1.2 s for a 4-request burst at 1 GiB. The repo's compose policy is restart: unless-stopped, but the owner's supervisor may differ.
- The deployed edge may enforce a stricter body cap, connection or rate limit than the bundled Caddyfile (default 256MB, no rate limit). That is the owner's configuration.

**validation_plan.local** Local OOM at 512 MiB is already reproduced three times (parent-live, r-preauth, rv-preauth). The remaining local check is the fix: after adding a smaller pre-auth cap, or a pre-body Authorization-present gate in _BodyLimit (reject JSON-route requests with no Authorization header or session cookie before reading the body), rerun agents/parent-live/parent_live_preauth_json.py in a disposable --network none container with --memory 512m and 4 concurrent 8 MiB bodies. Expect 401 or 413 for each request, no RSS growth beyond the baseline, and no exit -9.

**validation_plan.deployment** Owner checks the memory limit and swap of the agentbox control-plane container or host, and its restart policy (compose default restart: unless-stopped). The owner also checks whether the TLS proxy or edge applies a per-route or JSON body cap below 8 MiB (the bundled Caddyfile allows 256MB on every route) and any per-client rate or connection limit, and confirms that a stall of 1 s or more, or a process restart, on the single uvicorn process (which also serves the human approval queue and the audit chain) is acceptable. Suggested hardening: reject JSON-route requests without an Authorization header or session cookie before reading the body, set a lower AGENTBOX_PROXY_MAX_BODY for non-upload routes, add limit_concurrency, and set a container mem_limit sized for the cap.


</details>
