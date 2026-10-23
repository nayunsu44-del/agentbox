# run-4 검증 필요 항목

소스로는 성립하지만, 이 감사 환경에서 결정적 증거를 만들지 못한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.

## N1. `same_origin`이 Origin의 netloc만 Host와 비교해, 같은 호스트의 http:// 페이지가 TLS 배포의 CSRF 출처 검사를 통과하고 세션을 끊을 수 있다

- 지문: `agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare`
- 경로: `agentbox/web.py:217`(진입점), `agentbox/api.py:145`(전파), `agentbox/api.py:133`(전파), `agentbox/web.py:223`(도달점)

**설명.** 쿠키로 인증하는 UI 변경 요청은 모두 `api.same_origin`(api.py:131-133)을 거친다. 이 함수는 Origin이 없거나 `urlsplit(Origin).netloc`이 Host와 같으면 통과시키고 scheme은 보지 않는다. 그래서 `http://H` 페이지가 `https://H` 배포의 검사를 통과한다. 검증자가 실제 앱을 ASGI로 띄워 확인했다. `Origin: http://agentbox.example`이 `/login`, `/ui/approvals/.../approve`, `/ui/sandboxes`, `/logout`에서 모두 받아들여졌다. 다른 호스트, `null`, userinfo, 다른 포트는 403이었다.

**주장하는 근본 원인.** api.py:131-133이 netloc만 비교하고 scheme은 비교하지 않는다. 함수가 헤더만 받아 요청 scheme을 모른다. HSTS를 내보내는 곳도 없다.

**막힌 지점.**

- 결정적 사실은 브라우저 동작이다. 사람이 쓰는 브라우저가 `Secure; SameSite=Strict` 세션 쿠키를 `http://H` → `https://H` 폼 POST에 붙이는지 봐야 한다. run-3에서 Chromium 141은 붙이지 않았다. Firefox·WebKit은 확인하지 않았다. 쿠키가 안 붙으면 남는 영향은 강제 로그아웃뿐이다.
- 공격자가 같은 호스트 이름으로 평문 http를 띄울 수 있는지(경로상 공격자, 80 포트, DNS 탈취)는 배포 조건이다.
- 두 scheme이 같은 netloc으로 노출되는지는 배포 형태에 달렸다. HSTS나 preload가 있으면 http 페이지가 아예 열리지 않는다.

**검증 계획.** 로컬: H를 127.0.0.1로 잡고 자체 서명 TLS로 `https://H:443`을 띄운다. `http://H:80`에서 `/logout`과 `/ui/sandboxes`로 자동 제출하는 폼을 둔다. 로그인한 상태로 http 페이지를 열어 쿠키 전송 여부, 응답 코드, 세션 종료, 샌드박스 생성 여부를 Chromium·Firefox·WebKit에서 기록한다.
수정 방향(결과와 관계없이 권장): `same_origin`이 `request.url.scheme`까지 함께 비교하게 한다.

**부모 실측 (run 뒤, 에이전트 예산 밖).** 판정은 바꾸지 않았다. 판정을 바꾸려면 새 검증자가 필요하다.

Chromium 141에서 실측했다(`agents/parent-live/parent_live_scheme.py`, 결과 `artifacts/scheme-csrf.json`). 실제 앱을 `https://agentbox.test`(TLS, 443)로, 공격 페이지를 `http://agentbox.test`(80)로 띄웠다.
- 로그인 쿠키는 `Secure; SameSite=Strict; HttpOnly`였다.
- 공격 페이지의 `POST /ui/sandboxes`와 `POST /logout` 모두 서버에 쿠키 없이 도착했다. 샌드박스는 0개 생겼다.
- 다만 `/logout` 응답의 쿠키 삭제가 브라우저에 적용돼 세션 쿠키가 사라졌고, 다음 `/ui` 요청은 `/login`으로 갔다. 서버 쪽 세션 종료(`ui_logout` 행)는 없었다.
- 결론: Chromium에서는 '강제 로그아웃'만 성립하고, 사람 권한 실행은 성립하지 않는다. Firefox·WebKit은 이 환경에 없어 확인하지 못했다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** Every cookie-authenticated UI mutation funnels through api.same_origin (api.py:131-133), which returns True when Origin is absent or when urlsplit(Origin).netloc equals the Host header; the scheme is never compared. A plaintext http://H page is a different web origin from the TLS deployment https://H but carries the same netloc, so the gate accepts it. Independently reproduced (agents/v02/scratch/v02_origin.py, artifact v02_origin.out; api.build with docker.from_env stubbed, ASGI served as https://agentbox.example): Origin http://agentbox.example was accepted for POST /login (303, issuing the Secure SameSite=strict HttpOnly host-only session cookie), POST /ui/approvals/apr_000000000000/approve (200; box.decide entered with the '*' session and rendered approval-not-found), POST /ui/sandboxes (handler reached box.create_sandbox) and POST /logout (303; end_ui_session entered, server session ended - a later GET /ui with the same cookie redirected to /login). Origin https://agentbox.example was accepted identically; Origin https://evil.example, Origin: null, Origin http://agentbox.example@evil.example and Origin http://agentbox.example:8443 against Host agentbox.example were all 403; a POST with no Origin was accepted. Consequence (1): where a browser attaches the Strict cookie to a cross-scheme POST, the human-scoped action runs - approve/deny for a known apr_ id, a sandbox built for an attacker-chosen source_dir, or server-side session end. Consequence (2), browser-independent once the request is sent: POST /logout answers even a cookieless cross-origin request with 303 plus an unconditional cookie-clearing Set-Cookie (web.py:149-150), so a page served at http://H forces a client-side logout while the server-side session survives. No anti-CSRF token, Referer or Sec-Fetch check exists anywhere in agentbox/ (grep finds none) and the only response-wide guard is X-Object-Frame/CSP frame-ancestors (api.py:66), which stops iframe clickjacking but not a top-level auto-submitted form; no Strict-Transport-Security is emitted in agentbox/ or deploy/ (no response carries one; only audit docs mention it), so nothing forces the upgrade of http://H. The decisive unknown stays the browser's schemeful same-site behaviour: the run-3 loopback Chromium 141 run had the Secure cookie withheld (only the forced browser logout occurred), no browser exists in sbx, and Firefox/WebKit are unobserved, so whether consequence (1) is reachable cannot be decided from source or from this sandbox.

**claimed_root_cause** api.py:131-133: same_origin() returns True when urlsplit(origin).netloc == headers.get('host') (and when Origin is absent); the scheme is never compared, and the closure receives only headers (api.py:131) although the app derives the request scheme elsewhere (api.py:136, web.py:114). Nothing in agentbox/ or deploy/ emits Strict-Transport-Security (deploy/Caddyfile:5 is a bare reverse_proxy), so the CSRF gate degrades to whatever same-site semantics the browser applies to http://H versus https://H.

**trace**

- `agentbox/web.py:217` (entrypoint, decide - POST /ui/approvals/{aid}/{decision} (peers: create web.py:174, logout web.py:142)) — Cookie-authenticated, form-encodable mutations with no anti-CSRF token; the only origin binding is same_origin. All three decorators verified in the audited tree.
- `agentbox/api.py:145` (propagation, screen_principal) — Resolves the browser cookie via box.desktop.session_scope() at api.py:142 and then calls same_origin(request.headers) at api.py:145; logout calls the same closure directly at web.py:144. The cookie is checked before the origin, so a cross-scheme request without a cookie gets 401 rather than 403.
- `agentbox/api.py:133` (propagation, same_origin) — Netloc-only comparison, missing Origin accepted - reproduced: Origin http://agentbox.example passes against a request served over https://agentbox.example, foreign host, null, the userinfo trick and a port mismatch fail.
- `agentbox/web.py:223` (sink, box.decide (also create_sandbox web.py:178, end_ui_session web.py:146)) — With the request accepted the human-scoped action runs: decide executes the stored args with actor='human' and the '*' session, create builds a sandbox for a form-supplied source_dir, and logout ends the session when the cookie did arrive.

**blockers**

- Browser behaviour (decisive): whether a browser an operator actually uses attaches the Secure SameSite=strict session cookie to a cross-scheme http://H -> https://H form POST. Chromium 141 withheld it (docs/security-audit/run-3/agents/parent-live/artifacts/l3/l4.out:4, reported, not re-run in run-4); Firefox and WebKit current behaviour and the legacy cut-offs are untested, no browser exists in sbx, and the answer cannot be derived from source. Without the cookie only consequence (2), the client-side forced logout, remains.
- Network position: whether an attacker can serve plaintext http://H on the deployment host name at all (on-path network attacker, a plaintext listener on port 80, or a DNS/HTTP hijack). No Strict-Transport-Security is emitted anywhere in agentbox/ or deploy/, so nothing forces the upgrade, but whether an on-path attacker and browser preload state are in scope is an owner decision.
- Deployment shape: whether both schemes are exposed at the same effective netloc (direct TLS on 443 plus cleartext 80, or behind-proxy mode where Caddy owns the http->https redirect). In a loopback http-only deployment the scheme fork does not exist, and if HSTS or a preload entry is present the http page never loads.

**validation_plan.local** Repo-side half is done and reproduced by the verifier: agents/v02/scratch/v02_origin.py builds the real app (api.build with docker.from_env stubbed) and drives it over ASGI as https://agentbox.example - cross-scheme Origin accepted on /login, /ui/approvals approve, /ui/sandboxes and /logout, foreign/null/userinfo/port-mismatch 403, /logout always emitting the clearing Set-Cookie; artifact v02_origin.out. Remaining decisive step is a loopback browser lab run outside sbx (parent-live): map H to 127.0.0.1, start agentbox with --tls-cert/--tls-key (self-signed, lab-trusted) on https://H:443 with a dummy human token, and a plaintext http://H:80 page that auto-submits a top-level form to https://H/logout and to https://H/ui/sandboxes with source_dir set; log in on https://H, open http://H, and record (a) whether agentbox_session is sent on the POST, (b) whether the response is 303/200 (accepted) rather than 403, (c) for /logout whether the server session ends (GET /ui then 303 /login) and whether a ui_logout row appears in /audit, (d) for /ui/sandboxes whether a new sandbox exists. Repeat on current Firefox and WebKit and on any engine or policy that disables schemeful same-site. Regression: change same_origin to compare BOTH the scheme and the netloc, taking the served scheme from request.url.scheme (already used at api.py:136 and web.py:114, and X-Forwarded-Proto-aware under cli.py:126) instead of the headers-only signature at api.py:131; then both cross-scheme POSTs must return 403 and the clearing Set-Cookie must disappear, while Origin https://H with Host H still passes and the existing tests/test_unit.py suite stays green.

**validation_plan.deployment** Owner confirms, without probing live endpoints: (1) whether the operator-facing host name sends Strict-Transport-Security or is on the browser preload list; (2) whether a plaintext http:// listener for that name is reachable (direct TLS on 443 plus cleartext 80, or a TLS proxy fronting the plaintext port where the http->https redirect is the only barrier) and whether an on-path attacker is in scope; (3) which browser engines and versions operators use; (4) whether any operator browser or policy lacks schemeful same-site. If HSTS is present and every browser is schemeful, only the browser-independent forced-logout residual from the unconditional delete_cookie at web.py:149-150 remains, and the same scheme comparison removes it.


</details>

## N2. 에이전트가 늘리는 감사·승인 행에 전체 상한과 보존 정책이 없다. 호스트 디스크를 채울 수 있고, 어느 복구 방법을 써도 감사 체인을 지킬 수 없다

- 지문: `agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention`
- 경로: `agentbox/api.py:215`(진입점), `agentbox/service.py:295`(전파), `agentbox/service.py:189`(전파), `agentbox/service.py:324`(전파), `agentbox/audit.py:179`(전파), `agentbox/service.py:592`(전파), `agentbox/audit.py:230`(도달점)

**설명.** 에이전트 도구 호출마다 감사 행이 최소 2개 생긴다. 승인이 필요한 호출은 `approval_requested` 행과, 원본 인자를 담은 `approvals` 행을 더 남긴다. 레코드당 인자는 이제 16 KiB로 잘리지만, 테이블 전체에는 상한이 없다.
- 실측: 최대 크기 호출 하나에 17,203바이트, `ls` 하나에 512바이트가 늘었다.
- 400 KB 인자의 승인 행 5개가 2 MB를 차지했고, 실행·거절·만료 뒤에도 남았다.
- 감사 테이블은 트리거로 DELETE·UPDATE가 막혀 있다. 보존 작업도 없다.
디스크가 차면 `AuditWriteError`가 나고, 모든 샌드박스의 도구 호출·승인·인계가 503으로 멈춘다. 복구도 막혀 있다. 오래된 행만 지우면 `verify()`가 영구 실패하고, 전부 지우면 빈 로그가 통과한다.

**주장하는 근본 원인.** 감사 테이블은 설계상 추가 전용이다. 에이전트가 늘리는 양을 제한하는 것은 레코드당 인자 상한뿐이다. 감사·승인 테이블에 전체 할당량, 보존 기간, 정리 명령, 크기 검사가 없다.

**막힌 지점.**

- 남은 디스크 용량, 볼륨 할당량, 볼륨 수명은 배포 사실이다. 소진까지 걸리는 시간은 저장소만으로 정해지지 않는다.
- 에이전트가 낼 수 있는 호출 속도는 운영자가 앞단에 둔 제한에 달렸다. 저장소에는 속도 제한이 없다.
- 운영자가 SQLite 파일을 따로 정리하는지, 어떤 손실을 받아들일지는 소유자 결정이다.

**검증 계획.** 로컬(이미 수행): 스크래치 DB로 `_call_tool`이 쓰는 행을 재생해 위 수치를 얻었다. 디스크가 차서 503이 나는 과정은 포화 테스트라 직접 돌리지 않았다.
배포: 작은 볼륨(예: 64 MiB tmpfs)에 데이터 폴더를 두고, 더미 에이전트로 최대 크기 호출을 반복한다. 503이 모든 샌드박스로 번지는지, 정리 뒤 `verify()` 결과가 어떤지 기록한다.

**부모 실측 (run 뒤, 에이전트 예산 밖).** 판정은 바꾸지 않았다. 판정을 바꾸려면 새 검증자가 필요하다.

실제 Docker와 16 MiB 볼륨(ext4 11 MB 사용 가능)으로 실측했다(`agents/parent-live/parent_live_diskfull.py`, `_recovery.py`, 결과 `artifacts/diskfull*.json`).
- 샌드박스 A의 에이전트 하나가 스레드 4개로 허용된 `ls` 호출 417번을 보내 **18.9초 만에** 볼륨을 채웠다.
- 그 뒤 실패한 것:
  - 샌드박스 B의 에이전트 호출: 503
  - 사람의 B 스냅샷: 503
  - 사람의 A·B 삭제: 503. 문제를 일으킨 샌드박스조차 지울 수 없었다.
  - 사람의 승인 결정: 503이 아니라 처리되지 않은 `sqlite3.OperationalError`가 났다. API에서는 500이다.
- 읽기와 `verify()`는 됐다.
- 실행이 끝난 호출 3개는 `tool_result` 기록이 빠졌다(`tool_request` 420, `tool_result` 417).
- 복구: 오래된 100행을 지우면 `verify()`가 '1 다음에 101'로 영구 실패한다. 전부 지우면 0행을 검사하고 통과한다.
- 남은 배포 사실은 실제 볼륨 크기뿐이다(소진 시간이 그것에 비례한다).

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** Every accepted agent tool request appends two audit rows (tool_request before the policy decision, policy_decision as soon as decide() returns) before any approval request, snapshot or execution, a risky call adds an approval_requested row plus an approvals row holding the full raw args, and every failed POST /approvals/{aid} adds an approval_forbidden row. Args are now capped per record (80,000-byte command is stored as a 16,384-byte head), but nothing bounds the tables: in an isolated fixture two rows per call added 17,203 bytes to the .db file, identically at n=20 and n=40, and 512 bytes per call for {command: ls}; five approval rows of 400,000-byte args took 2,007,040 bytes and every row survived executed/denied/expired. Triggers abort UPDATE and DELETE on audit, grep finds no DELETE for audit or approvals, no VACUUM, no count/size quota and no retention job, so growth is permanent and host disk is the only limit. When the volume fills, AuditLog.append raises AuditWriteError, which service.py turns into 503 for tool calls, human lifecycle, approval decisions and handbacks, so all sandboxes stop rather than the offending one. Recovery is not available either: deleting the oldest rows made verify() fail permanently at the first survivor (broken_at=7, 'id가 1 다음에 7로 건너뜀'), while deleting every row made verify() report ok=True with checked=0, so an operator must choose between permanently broken verification and a silently erased history.

**claimed_root_cause** The audit table is append-only by design (audit.py:35-38) and the per-record arg cap (service.py:37-38, 180-194) is the only bound on agent-driven growth; grep over agentbox/ finds no aggregate quota, retention window, pruning command or size check for the audit or approvals tables (the only sqlite DELETEs are ui_tickets, ui_sessions and takeover_leases in desktop.py), and the delete path for a sandbox only unlinks capture PNGs (service.py:106-109, 471-475). The shared SQLite file used by AuditLog, SandboxManager, ApprovalStore and DesktopControl (api.py:86-94, config.py:84-86, default ./data/agentbox.db, host bind mount at deploy/docker-compose.yml:28) therefore has the host volume as its only limit, and capacity recovery is mutually exclusive with the integrity contract (audit.py:230-236).

**trace**

- `agentbox/api.py:215` (entrypoint, call_tool (POST /sandboxes/{sid}/tools/{tool})) — An agent token reaches this route through principal() (api.py:115-124). The body is ToolCall whose args is an unconstrained dict[str, Any] (api.py:51-52), and there is no request-body, key-count or value-size cap on this route; the only body cap in the API is the human upload route (api.py:278-283) and the shipped Caddyfile is a bare reverse_proxy with no request_body limit (deploy/Caddyfile:4-6).
- `agentbox/service.py:295` (propagation, _call_tool: tool_request and policy_decision appends) — tool_request is appended with _logged_args(args) (295-296) and policy_decision is appended the moment policy.decide returns (297, appended at 303), before any approval request (324), snapshot (343) or execution, so every accepted request writes two rows even when the decision is DENY (308-309) and nothing runs.
- `agentbox/service.py:189` (propagation, _logged_args per-record cap) — Only the single record is bounded: args over 64 KiB become a 16 KiB head plus args_bytes and args_sha256. Measured: {'command': 'a'*80000} produced args_head of exactly 16,384 bytes and args_bytes 80,015; the two rows added 17,203 bytes per call at both n=20 and n=40 (linear), and {command: 'ls'} added 512 bytes per call, so per-record capping does not bound the table.
- `agentbox/service.py:324` (propagation, _call_tool REQUIRE_APPROVAL branch) — approvals.create stores the full raw args and preview with no cap (approvals.py:49-59); PENDING_APPROVALS_MAX=20 (service.py:44, 312-316) limits pending concurrency only, and measured rows of 400,000-byte args took 401,408 bytes each and were still present after executed, denied and expired transitions. A sandbox delete does not remove them.
- `agentbox/audit.py:179` (propagation, AuditLog.append INSERT) — The row is inserted into the same SQLite file; the append-only triggers (audit.py:35-38) abort any UPDATE and DELETE (both reproduced: 'audit log is append-only'), and no code path in the package removes audit rows.
- `agentbox/service.py:592` (propagation, log_human fail-closed conversion) — At disk-full every append raises AuditWriteError, which becomes ServiceError(503) here (593-594) and likewise for tool calls (305-306), approval decisions (402-404) and handbacks (539-541), so the blast radius is every sandbox and every human operation rather than the agent's own process.
- `agentbox/audit.py:230` (sink, AuditLog.verify chain and id check) — verify starts from GENESIS with expected_id 1 and rejects the first row that does not chain (233-236). Reclaiming space by deleting the oldest rows therefore fails permanently (measured: after removing ids 1..6, ok=False, broken_at=7), while deleting every row returns ok=True with checked=0, so capacity recovery either breaks /audit/verify for good or erases the history without a trace.

**blockers**

- Free space, any filesystem or volume quota, and the planned lifetime of the volume holding data/agentbox.db (config.py:29 home=./data, config.py:84-86 db_path, deployed as a host bind mount at deploy/docker-compose.yml:26-28) are deployment facts. Nothing in the repository bounds stored total: no retention, no count or size quota, no VACUUM. At the measured 17,203 bytes per maximum-size tool call (512 bytes for a trivial call) the time to exhaustion depends entirely on that free space, from minutes on a small volume to months on a large one, and no repository fact decides it.
- The call rate an agent can sustain is partly a deployment fact: the repository has no rate limit on the tool route, tool_concurrency=4 (config.py:53) and the 32-thread tool_pool (api.py:103) bound concurrency only, and the shipped Caddyfile is a bare reverse_proxy (deploy/Caddyfile:4-6), but any operator-added proxy or network control is outside the source.
- Whether operators prune or rotate that SQLite file out of band, and which loss they accept, is a deployment/owner decision: source and fixture show that partial pruning permanently fails /audit/verify (audit.py:230-236) while total truncation passes as an empty log, so the product offers no capacity recovery that keeps the history verifiable.

**validation_plan.local** Already performed in the approved sandbox (tools/sbx.py v03: /target read-only on PYTHONPATH, /scratch writable, no network, no Docker socket, uid 65534, 512 MiB, 120 s). Built AuditLog and ApprovalStore on scratch databases and replayed exactly what _call_tool writes: (1) _logged_args('exec', {'command': 'a'*80000}) returned args_head of 16,384 bytes and args_bytes 80,015; (2) 20 and 40 pairs of tool_request plus policy_decision rows added 344,064 and 688,128 bytes after PRAGMA wal_checkpoint(TRUNCATE), i.e. 17,203 bytes per call at both sizes, and 40 pairs with {'command': 'ls'} added 20,480 bytes, i.e. 512 bytes per call; (3) DELETE FROM audit and UPDATE audit both failed with sqlite3.IntegrityError 'audit log is append-only'; (4) dropping only the delete trigger and removing ids 1..6 left verify() returning ok=False, checked=0, broken_at=7, reason 'id가 1 다음에 7로 건너뜀', while deleting every row left verify() returning ok=True with checked=0; (5) five ApprovalStore rows of 400,000-byte args took 2,007,040 bytes (401,408 each) and all five were still listed after executed, denied and expired, with no delete method on the store; (6) approvals.list() re-parses full args. The disk-full to AuditWriteError to 503 conversion was not exercised (filling a filesystem is a saturation test); it rests on audit.py:193-194 wrapping sqlite3.Error and the fail-closed handlers cited in the trace. Output: scratch/fixout.txt and scratch/fixout2.txt; the numbers above were observed directly, the files are supplementary.

**validation_plan.deployment** Owner-observed on a throwaway deployment, never a shared or production host, and without filling the volume: record the free space and any quota on the volume holding data/agentbox.db; issue 200 bounded tool calls from one agent token with 80,000-byte exec commands (denied calls are sufficient, since the two audit rows are written before any execution) and 200 with {command: ls}; confirm the .db size delta is about 3.4 MB and 0.1 MB respectively and that it does not shrink after the calls stop, after sandbox deletion, or after any documented maintenance command; then check whether the operator has any out-of-band retention or rotation for that file, and confirm that once the volume is full the tool route and the human lifecycle route both return 503 from AuditWriteError while other sandboxes are unaffected by definition only. Extrapolate from the per-call delta instead of filling the disk.


</details>

## N3. `list_dir`, `outbox_list`, 미리보기 glob 확장, 스크린숏이 컨테이너 출력을 상한 없이 컨트롤 플레인 메모리에 올린다

- 지문: `agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap`
- 경로: `agentbox/api.py:216`(진입점), `agentbox/service.py:350`(전파), `agentbox/service.py:127`(전파), `agentbox/service.py:141`(전파), `agentbox/service.py:318`(전파), `agentbox/sandbox.py:428`(전파), `agentbox/sandbox.py:560`(전파), `agentbox/sandbox.py:534`(전파), `agentbox/sandbox_desktop.py:88`(도달점)

**설명.** 에이전트 토큰이 다루는 샌드박스에서 네 리더가 Docker의 비스트리밍 `exec_run`으로 출력을 통째로 받는다. 바이트 상한이 없고, 셋은 컨테이너 쪽 제한 시간도 없다. 대상은 `list_dir`(sandbox.py:428), `outbox_list`(534), `_expand`(560), `screenshot`(sandbox_desktop.py:86-88)이다. `_truncate`와 `_parse_outbox`는 버퍼가 다 찬 뒤에 돈다. 그래서 반환 값만 줄이고 최대 사용량은 줄이지 못한다.
가짜 `exec_run` 실측:
- 16 MiB 출력에서 `list_dir`가 16.19 MiB까지 썼다(exec의 `_Head`는 0.32 MiB).
- `find` 출력 5 MB가 파싱 뒤 72.6 MiB까지 올라갔다.
- 8 MiB PNG를 그대로 받아 base64로 11.2 MB 응답을 만들었다.

**주장하는 근본 원인.** exec의 `_Head` 상한과 read_file 쪽 컨테이너 상한을 리더마다 따로 붙였다. 위 네 리더는 빠졌다.

**막힌 지점.**

- 결정적인 양은 실제 컨테이너가 스트리밍할 때 docker SDK 안에서 생긴다. 감사 샌드박스에는 Docker 데몬이 없어 가짜 `exec_run`으로만 쟀다. 실제 값은 SDK가 한 번 더 버퍼링하므로 더 크다.
- 스크린숏 변형은 데스크톱 컨테이너 안에서 uid 1001이 스크린숏 경로를 `/dev/zero` 심볼릭 링크로 바꿔야 한다. 이 환경에는 데스크톱 이미지와 X 세션이 없었다.
- 치명적인지는 컨트롤 플레인 메모리 제한과 호스트 메모리에 달렸다. 배포에 메모리 상한이 없다.

**검증 계획.** 로컬: 일회용 샌드박스(`AGENTBOX_DISK=2g`, 네트워크 없음)의 `/workspace`에 빈 파일 약 20만 개를 만든다. `list_dir` 호출 전후로 컨트롤 플레인 VmHWM을 잰다. 대조군으로 같은 디렉터리를 상한이 있는 exec(`ls -la`)로 읽는다. outbox와 `rm /workspace/*` 미리보기도 같은 방식으로 잰다. 데스크톱 샌드박스에서는 스크린숏 경로를 `/dev/zero`로 바꿔 증가가 보이면 바로 멈춘다.
배포: compose 스택에서 같은 비교를 하고, 메모리 제한과 OOM 동작을 기록한다.

**부모 실측 (run 뒤, 에이전트 예산 밖).** 판정은 바꾸지 않았다. 판정을 바꾸려면 새 검증자가 필요하다.

실제 Docker와 데스크톱 샌드박스로 실측했다(`agents/parent-live/parent_live_readers.py`, 결과 `artifacts/readers-*.json`). 파일은 20만 개이고, 측정값은 프로세스 VmHWM 증가분이다.

| 리더 | 최대 메모리 증가 |
|---|---|
| `list_dir` (`ls -la` 출력 17.4 MB, 반환 64 KiB) | 33.6 MiB |
| 상한 있는 exec(`ls -la`, 대조군) | 0.5 MiB |
| outbox 목록 | 90.2 MiB |
| `rm /workspace/many/*` 미리보기 glob | 64.7 MiB |
| 스크린숏 경로를 `/dev/zero` 링크로 | 77.8 MiB, 15초 X 제한 시간에 끊김 |

결론: 증가는 실제이고 파일 수에 비례한다. 다만 스크린숏 최악 경우도 제한 시간으로 묶인다. 메모리 상한이 없는 배포에서 해가 되려면 수백만 개 파일이나 많은 동시 호출이 필요하다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** On a sandbox that the agent token controls, four control-plane readers take the whole container-produced stream through Docker's non-streaming exec_run, with no byte cap and, for three of them, no container-side timeout: SandboxManager.list_dir (sandbox.py:428) runs `ls -la` on any /workspace or /source path; SandboxManager.outbox_list (sandbox.py:534) runs an unbounded `find -maxdepth 1 -printf`; SandboxManager._expand (sandbox.py:560) globs a preview pattern; DesktopTools.screenshot (sandbox_desktop.py:86-88) `cat`s /home/desktop/.cache/agentbox-shot.png and only then checks the PNG magic. _truncate (sandbox_common.py:24-32) and _parse_outbox (sandbox.py:111-124) run after the whole buffer exists, so they bound the returned value, not the peak. The peak is paid by the one shared FastAPI process, so one sandbox's listing is charged to every sandbox. Measured locally against the real reader functions with a fake exec_run: a 16 MiB stream makes list_dir peak at 16.19 MiB, against 0.32 MiB for exec's _Head reader on the same stream; 5.0 MB of find output becomes 58.6 MiB retained and 72.6 MiB peak after _parse_outbox (12.3x, record count uncapped); 4.2 MB of glob output becomes 209,715 Python strings; an 8 MiB PNG is accepted unchanged and then base64-encoded to 11.2 MB for the agent response (service.py:143). The screenshot path is the one with superlinear amplitude: the shot file sits in the desktop user's writable home (_SHOT, sandbox_desktop.py:32), so uid 1001 can point it at a character device and turn one cheap call into up to 15 s of unthrottled `cat`, bounded only by a wall clock (_X_TIMEOUT, sandbox_desktop.py:26,46-50), whose exit-code check also runs after the read. The host-disk half of the claim is narrower than proposed: service.py:328 writes the captured PNG with no size check, but only after the magic test passes, so a /dev/zero symlink costs memory and no disk; a huge PNG-prefixed file is needed for the disk variant. The list_dir/outbox_list/_expand variants are ~1:1 with container output, and the container's output ceiling is its writable layer, which the repository caps only when the optional AGENTBOX_DISK is set (config.py:42, sandbox.py:263-264).

**claimed_root_cause** The _Head/_OUT_LIMIT discipline for exec and the container-side _timed plus head -c discipline for read_file, outbox_read and workspace_manifest were applied reader by reader; four readers that consume attacker-selected container output were left with a plain exec_run read (sandbox.py:428, 534, 560 and sandbox_desktop.py:86-88), and the screenshot reader's only bound is a timeout that is checked after the full read.

**trace**

- `agentbox/api.py:216` (entrypoint, POST /sandboxes/{sid}/tools/{tool} (Depends(principal))) — Agent-token route for the sandbox's own tools. default_policy.yaml:10 is `default: allow`, so list_dir and screenshot reach the readers below with no approval and no snapshot.
- `agentbox/service.py:350` (propagation, _call_tool ALLOW branch -> self._run_tool) — Runs on a tool_pool thread; the reader work and its peak memory happen on that shared pool, outside any per-call size accounting.
- `agentbox/service.py:127` (propagation, _run_tool list_dir branch) — Returns sb.list_dir(sid, path) straight into the tool result with no byte, entry or time check on the way.
- `agentbox/service.py:141` (propagation, _run_tool screenshot branch (inside gui_lock)) — Calls sb.screenshot and then base64-encodes the entire PNG into the tool response at 143, so the response holds a second full copy of container-controlled bytes.
- `agentbox/service.py:318` (propagation, _call_tool REQUIRE_APPROVAL branch: preview = self._preview(...)) — The exec preview is computed before the approval row exists, so sandboxes.preview -> _expand streams glob output even if the human then denies, and once per pending request (up to PENDING_APPROVALS_MAX).
- `agentbox/sandbox.py:428` (propagation, SandboxManager.list_dir: c.exec_run(['ls','-la','--',p], user=AGENT_UID, demux=True)) — The whole ls stream is read into the control plane with no byte cap and no container-side timeout; _truncate at 432 shortens the value only after the peak has been allocated.
- `agentbox/sandbox.py:560` (propagation, SandboxManager._expand: c.exec_run(['sh','-c', glob loop, '_', pattern])) — Shell glob output is buffered whole, then decoded and returned as one string per match; the caller materialises the entire list into preview notes.
- `agentbox/sandbox.py:534` (propagation, SandboxManager.outbox_list: c.exec_run(['sh','-c', find -printf])) — find -printf output is buffered whole and parsed afterwards into one dict per record, then sorted, with no count cap; reached from the human routes api.py:290 and web.py:233, where container-chosen names drive the cost.
- `agentbox/sandbox_desktop.py:88` (sink, DesktopTools.screenshot: png = res.output[0] or b'') — `cat {_SHOT}` (86) is buffered completely, bounded only by the 15 s timeout, and the PNG magic plus exit-code checks run at 89 only after the full read.

**blockers**

- The decisive quantity - how much memory the control plane actually holds while a real container streams - is produced inside the docker SDK's non-streaming exec_start reader. The approved sandbox has no Docker daemon or socket (uid 65534, no /var/run/docker.sock), so no real exec stream can be created or sized; the peaks reported here come from an in-process fake exec_run that hands the real reader functions pre-built bytes, which understates the real peak because the SDK buffers the same bytes as well.
- The superlinear variant needs /home/desktop/.cache/agentbox-shot.png replaced by a symlink to /dev/zero (or to a huge PNG-prefixed file) by uid 1001 inside a live agentbox-desktop sandbox; the audit sandbox has neither that image nor an X session, and the control plane's own `scrot -o -z` overwrites the path on the non-symlink case.
- Whether the resulting peak is fatal depends on owner-side topology that the repository does not fix: deploy/ sets no memory limit for the agentbox service, the host's memory and any cgroup limit are unknown, AGENTBOX_DISK is unset by default, and the blast radius (control-plane restart drops every sandbox's desktop session and in-flight approvals) is an operational fact.

**validation_plan.local** Owner-run on a disposable Docker-backed sandbox with AGENTBOX_DISK=2g and no network. (1) Create ~200k empty files in /workspace using unapproved batch `touch` calls (touch is in the read-only allowlist, default_policy.yaml:25-27) or one gated exec. (2) Record VmHWM from /proc/<pid>/status of the control-plane process, call POST /sandboxes/{sid}/tools/list_dir {"path":"/workspace"} with a dummy agent token, record VmHWM again, and confirm the returned listing stops at 64 KiB while the peak grew by roughly the raw ls size. (3) Control: run the same directory through the capped exec reader (`ls -la /workspace`) and confirm the delta stays near 64 KiB. (4) Put 200k files in /workspace/outbox, call GET /sandboxes/{sid}/outbox, and check for the ~12x parse amplification measured here. (5) Send one `rm /workspace/*` exec so the REQUIRE_APPROVAL branch runs _preview before any human decision, and measure the _expand cost. (6) Desktop variant: in a disposable desktop sandbox, as uid 1001 point the shot path at /dev/zero, call POST /tools/screenshot, and stop the test as soon as VmHWM growth is visible, noting whether the 15 s timeout keeps it under the host limit.

**validation_plan.deployment** Owner-observed on the compose stack: watch the agentbox container's RSS while a dummy agent lists a 200k-entry /workspace, compare it with the same agent running an allowlisted `ls -la` through the capped exec reader, and record whether the service has a cgroup memory limit and what an OOM does to running sandboxes and pending approvals. Then, with captures enabled, watch the same RSS during a burst of gated calls against a desktop sandbox whose shot path was replaced by a device symlink, and confirm that no file appears under settings.home/captures in the /dev/zero case while a huge PNG-prefixed file does produce one.


</details>

## N4. GUI 구간 정리가, 클라이언트가 스스로 선언한 `_NET_WM_PID`에 이름이 오른 uid 1001 프로세스를 죽이지 않는다

- 지문: `agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process`
- 경로: `agentbox/api.py:215`(진입점), `agentbox/service.py:343`(전파), `agentbox/service.py:148`(전파), `agentbox/gui_bursts.py:120`(전파), `agentbox/sandbox_desktop.py:59`(전파), `agentbox/gui_state.py:85`(전파), `agentbox/gui_bursts.py:85`(도달점)

**설명.** GUI 구간을 닫을 때 `_stop_strays`가 새로 생긴 uid 1001 프로세스를 죽인다(gui_bursts.py:83-85). 예외는 창 검사 하나다. pid나 새 조상 pid가 창 pid 목록에 있으면 남긴다(gui_state.py:85-86). 창 pid 목록은 `xdotool getwindowpid` 출력이고, 이 값은 X 클라이언트가 직접 써 넣는 `_NET_WM_PID`다. 검증자가 실제 함수로 재현했다. 구간 시작 세션의 데몬은 창 목록이 비면 죽었고, 창 목록에 그 pid가 있으면 살아남았다.

**주장하는 근본 원인.** 정리 예외를 컨트롤 플레인이 확인할 수 있는 관계가 아니라, 컨테이너가 선언한 X 창 정보로 정한다. 데스크톱 세션의 모든 프로세스가 디스플레이 :0에 접근할 수 있으니 공격자가 남길 pid를 고를 수 있다.

**막힌 지점.**

- 이 환경에는 X 서버와 X 클라이언트가 없어 `_NET_WM_PID` 위조와 그 값이 `xdotool`에 보이는지를 관찰할 수 없었다.
- 이미지(`images/desktop/Dockerfile`)에는 xprop·python·컴파일러가 없다. 임의의 `_NET_WM_PID`를 쓸 프로그램이 실제 이미지에 있는지 확인해야 한다. 없으면 위조 경로는 이 이미지에서 성립하지 않는다.
- 데몬이 구간 시작 때 있던 세션 안에 있어야 한다. GUI 입력만으로 그렇게 만들 수 있는지는 런타임 성질이다.

**검증 계획.** 로컬: 네트워크 없는 일회용 `agentbox-desktop:0.1`에서 다음을 순서대로 한다.
1. 속성을 쓸 수 있는 도구를 확인한다(`command -v xprop python3 gcc socat xdotool`).
2. desktop 계정으로 구간 시작 세션에 쓰기 데몬을 띄운다.
3. 1×1 창의 `_NET_WM_PID`를 데몬 pid로 설정한다. 도구가 없으면 여기서 멈추고 '위조 경로 불성립'으로 기록한다.
4. 실제 `desktop_processes`와 `gui_strays`로 정리 목록에 그 pid가 빠지는지 본다.

**부모 실측 (run 뒤, 에이전트 예산 밖).** 판정은 바꾸지 않았다. 판정을 바꾸려면 새 검증자가 필요하다.

실제 `agentbox-desktop:0.1` 샌드박스에서 끝까지 재현했다(`agents/parent-live/parent_live_netwmpid.py`, `netwmpid_forge.py`, 결과 `artifacts/netwmpid-stray.json`).
- 이미지 도구 확인: xprop과 컴파일러는 없다. 하지만 `python3`와 `libX11.so.6`이 있어, ctypes로 아무 `_NET_WM_PID`나 쓸 수 있다.
- 구간 시작 세션에 넣기: `xfconf-query`로 사용자 단축키 명령을 등록하고 키를 누르면, 기준 프로세스인 `xfsettingsd`가 쓰기 데몬을 띄운다. 데몬은 sid 1에 있고 docker exec 출신이 아니다. 에이전트가 GUI 입력만으로 할 수 있는 경로다.
- 위조 창(1×1, `_NET_WM_PID`=데몬 pid)을 띄우자 실제 `desktop_processes`가 그 pid를 창 pid로 보고했다. `gui_strays`는 데몬을 정리 목록에서 뺐고, `kill_processes` 뒤에도 데몬이 살아 `/workspace` 파일을 계속 갱신했다.
- 대조: 위조 창을 빼면 데몬이 정리 목록에 들어갔다.
- 한 번 살아남으면 다음 구간의 기준(baseline)에 들어가 계속 면제된다.
- 막힌 지점 세 개(이미지 도구, 세션 배치, 실제 정리)가 모두 풀렸다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** Verified in the audited tree (9805d91): at GUI-burst close GuiBursts._finish (gui_bursts.py:120) calls _stop_strays, which reads desktop_processes (gui_bursts.py:83) and kills gui_strays(procs, wins, burst['pids']) (gui_bursts.py:84-85). For a new uid-1001 process the only remaining exemption is the window test: p['pid'] in window_pids or a non-baseline ancestor pid in window_pids (gui_state.py:85-86); baseline pids, pid 1, other uids and docker-exec roots are exempted earlier (gui_state.py:80). window_pids are the decimal tokens of `xdotool getwindowpid` over `xdotool search --onlyvisible --name .` (sandbox_desktop.py:59-61), i.e. the _NET_WM_PID property the X client writes for itself; the parser filters with isdigit only, never checks that the pid owns a window or is the declaring client, and xdotool is run as the desktop account on the desktop-owned display (sandbox_desktop.py:46-47, images/desktop/agentbox-desktop-start:20,30,38). I re-ran the real gui_state.gui_strays and the real GuiBursts._stop_strays in the sandbox (agents/v05/artifacts/v05_probe.out): a headless uid-1001 daemon 300 in the burst-start session sid 1, parented by the baseline Thunar 85, is killed when window_pids is empty (line 2) and is spared when the window list merely names 300 (line 3); naming an unrelated pid 301 does not spare it (line 4), and a windowed but baseline ancestor 85 does not spare it (line 5). With the real _stop_strays the forged case killed nothing and emitted no gui_processes_stopped record at all, while the control case killed [300] and logged it (lines 20-22). Two preconditions bound the claim, and both are runtime facts of the image rather than source facts. (1) The window test is reached only when p['sid'] is in base_sids, the sessions of the uid-1001 baseline pids (gui_state.py:63,82-84); a new session is killed regardless of window, which my run confirms for a daemon in sid 777 (line 8). tests/test_unit.py:330-334 encodes exactly that for a terminal opened during a burst: the terminal window 150 is spared but its shell 152 and the shell's job 160 are killed as a new session, so a daemon typed into a terminal opened during the burst is not in this candidate's class. (2) The attacker needs an X client that can set _NET_WM_PID to another process's pid and then have xdotool report it; the image recipe installs xdotool, socat and x11-xserver-utils but not x11-utils (xprop), python or a compiler (images/desktop/Dockerfile:17-23), so whether such a client exists in the running image is unobserved. Impact is bounded and detective-control shaped: GUI input is approval-free by design (N-1) and the burst's snapshot and gui_changes are its documented record. A spared daemon keeps writing /workspace after the close, where the only manifest read (gui_bursts.py:122) has already happened, and its writes produce no gui_changes and no gui_processes_stopped row; because it is then present at the next burst open (gui_bursts.py:70,76), gui_state.py:80 treats it as baseline forever, which is the candidate's 'survives every burst close'. Calibration, not dismissal: the by-design ancestor clause already spares a helper of any windowed app opened during the burst (tests/test_unit.py:335-336; my line 9), so the forgery route adds capability mainly for a process with no new windowed ancestor, for example one started from a baseline windowed app such as the pre-existing file manager (tests/test_unit.py:337 keeps such a script in the kill list).

**claimed_root_cause** The stray-kill exemption is decided from container-declared X window metadata instead of a control-plane-verifiable link. sandbox_desktop.desktop_processes (sandbox_desktop.py:59-61) turns every decimal token printed by xdotool getwindowpid into a window pid, gui_state.gui_strays (gui_state.py:85-86) spares a new uid-1001 process in a burst-start session when its pid, or a new ancestor pid, is in that set, and gui_bursts._stop_strays (gui_bursts.py:83-85) kills only the remaining pids. Because _NET_WM_PID is written by the X client and every process in the desktop session can reach display :0 (images/desktop/agentbox-desktop-start:20,30,38), the attacker chooses which of its base-session processes look windowed, so the burst-end kill no longer bounds what keeps running.

**trace**

- `agentbox/api.py:215` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — Agent token (lowest-trust network principal, prompt-injectable) posts a GUI input tool. GUI tools are in the allowed set with no approval (service.py:135-139), and GUI input executes as uid 1001 in the desktop session (sandbox_desktop.py:94-129).
- `agentbox/service.py:343` (propagation, AgentBox._call_tool -> _needs_snapshot) — For GUI input _needs_snapshot is true, so _snapshot (250-265) takes the recovery snapshot and opens the burst, whose baseline is the workspace manifest plus the current pid set (gui_bursts.py:65-77).
- `agentbox/service.py:148` (propagation, AgentBox._run_tool (type)) — The typed command is delivered into the desktop session as uid 1001. Whether the resulting shell or daemon ends up in a session that existed at burst open is a runtime fact of the image's terminal/launcher behaviour (tests/test_unit.py:330-334 models a terminal shell as a new session that is killed), not a source fact.
- `agentbox/gui_bursts.py:120` (propagation, GuiBursts._finish) — When the burst closes (close_idle, gui_bursts.py:137-155) the strays are collected and killed (120) before the closing manifest is read (122).
- `agentbox/sandbox_desktop.py:59` (propagation, DesktopTools.desktop_processes) — window_pids is the isdigit-filtered set of xdotool getwindowpid values for every visible window with a non-empty name, i.e. client-declared _NET_WM_PID integers; no window ownership or declaring-client identity is checked (59-61).
- `agentbox/gui_state.py:85` (propagation, gui_strays) — A new uid-1001 process in a burst-start session is spared when its pid is in window_pids, or when a non-baseline ancestor pid is, regardless of which process actually owns that window.
- `agentbox/gui_bursts.py:85` (sink, GuiBursts._stop_strays) — kill_processes receives only the unexempted pids (kill -KILL -- <pids> as the desktop account, sandbox_desktop.py:64-67), so a forged-window daemon is not signalled and keeps modifying /workspace after the close.

**blockers**

- The decisive platform step is not observable here: this sandbox has no X server and no X client. Reproduced in the run (agents/v05/artifacts/v05_probe.out:25-33): DISPLAY unset, /tmp/.X11-unix absent, xdotool/xprop/Xvfb absent, python Xlib absent. So neither 'a uid-1001 client sets _NET_WM_PID to another process's pid' nor 'xdotool getwindowpid reports that value for its window' can be observed.
- Related image fact: the recipe (images/desktop/Dockerfile:17-23) provides xdotool and socat but no xprop/x11-utils, no python and no compiler, and xdotool has no generic property setter. Whether the running image contains any program able to write an arbitrary _NET_WM_PID (base-layer or Xfce component, or a hand-written X11-protocol client over the unix socket via socat) must be read from the live image; if none exists the forgery route is refuted for this image and only the by-design ancestor route remains.
- Reachability needs the daemon's sid to be one that existed at burst open (gui_state.py:63,82-84): a typed command's shell normally gets a new session (tests/test_unit.py:330-334, my line 8). Whether GUI-only input can place a headless daemon in the startxfce4 session is a runtime property of the image's terminal/launcher behaviour.
- Observing survival after a real idle close needs the Docker-backed desktop container (docker exec for ps, xdotool, kill and the audit read); the Docker daemon is forbidden in this verifier sandbox, so the end-to-end kill/no-kill result and the missing gui_processes_stopped row are shown only against the real pure function and the real _stop_strays with a fake container.

**validation_plan.local** Disposable agentbox-desktop:0.1 container, network none, built from the audited tree, dummy files only. (1) Record `command -v xprop python3 gcc cc socat xdotool` and `dpkg -l x11-utils` as the property-setter inventory. (2) Start the desktop; as the desktop account via docker exec -u desktop, first start the helper in a burst-start session (launched from the panel/Thunar or from a pre-existing windowed app) and confirm with `ps -eo pid=,ppid=,sid=,uid=,args=` that its sid equals a session that predates the burst; then start the headless writer `sh -c 'while :; do date +%s >> /workspace/_v05_probe; sleep 2; done' &` in that same session. (3) With the inventory from step 1, map a 1x1 titled visible window in that session and set its _NET_WM_PID to the writer's pid (a second window may carry the helper's own pid). If no tool can set the property, stop: the forgery route is refuted for this image. (4) Call the real SandboxManager.desktop_processes(sid) and feed procs/wins into the real gui_state.gui_strays with baseline = the pids taken immediately before step 2; record the wins set and the returned kill list. Expected if the finding holds: the writer pid is absent from the list, while the same call with wins=set() returns it. (5) Call kill_processes(sid, returned list), then confirm by ps that the writer still runs and that /workspace/_v05_probe's mtime advances past AGENTBOX_GUI_SNAPSHOT_IDLE. Non-destructive: dummy probe file only, writer killed and container discarded at the end.

**validation_plan.deployment** Owner-observed on a disposable desktop sandbox with dummy tokens and dummy files: during a real burst drive the agent's click/type to open a terminal from the panel and start `nohup sh -c "while :; do date +%s >> /workspace/_v05_probe; sleep 2; done" &`, plus the property helper if the image has one. Just before close record `ps -eo pid=,ppid=,sid=,uid=,args=` and `for w in $(xdotool search --onlyvisible --name .); do xdotool getwindowpid $w; done`, let the burst close on AGENTBOX_GUI_SNAPSHOT_IDLE, then read GET /audit as the human: the gui_processes_stopped record for that close must omit the writer pid, an exec ps must still show it running, and no later gui_changes row may exist for its writes. Refuted if the writer is killed, or if its session is new so the sid rule kills it, or if the image has no property setter. Fix check: exempt only baseline pids/sessions and control-plane docker-exec ancestry, or bind any spared pid to a control-plane-verified owner (for example the X socket owner in /proc/<pid>/fd) instead of trusting _NET_WM_PID. Audit reads and dummy files only.


</details>

## N5. 공용 제어 문자 필터가 U+061C(빠진 유일한 Bidi_Control)와 Cf·Zl·Zp 보이지 않는 문자를 놓쳐, 승인 카드가 실행될 명령 옆에 이 문자를 그대로 보여 준다

- 지문: `agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized`
- 경로: `agentbox/api.py:215`(진입점), `agentbox/service.py:324`(전파), `agentbox/web.py:208`(전파), `agentbox/web.py:94`(전파), `agentbox/templates/_approvals.html:8`(도달점)

**설명.** run-3 v13 수정으로 `web._shown`이 모든 템플릿 출력에 `display.escape_controls`를 걸고, run-3 공격 문자열은 막힌다. 다만 문자 집합을 손으로 나열해 Bidi_Control 12개 중 U+061C가 빠졌다. U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028, U+2029도 빠졌다. 이 문자들은 카드의 명령 `<pre>`와 영향 경로 칸에 그대로 나오고, CLI의 `_safe`도 같다. 다만 이 문자들로 카드가 다른 명령처럼 읽히는지는 확인하지 못했다. U+061C는 강한 RTL 문자라 ASCII 글자 순서를 뒤집지 못하고, 주변 문장 부호 방향에만 영향을 준다.

**주장하는 근본 원인.** display.py:13·15가 제어·bidi 문자를 손으로 나열해 U+061C와 Cf 보이지 않는 문자, 줄·문단 구분자가 빠졌다.

**막힌 지점.**

- 감사 샌드박스에는 브라우저와 터미널 렌더러가 없어 실제로 어떻게 그려지는지 볼 수 없었다. 이 문자들이 카드에 그대로 나오고 실행되는 명령에도 그대로 있다는 데까지만 확인했다.
- 결정적 사실은 이 문자들 때문에 카드가 다른 명령처럼 읽히는가다. 브라우저 엔진, 기본 방향, 글꼴에 달렸고 저장소가 정하지 않는다.
- 운영자가 쓰는 브라우저와 터미널을 감사가 알 수 없다.

**검증 계획.** 로컬: 같은 카드 조각을 루프백 정적 파일로 Playwright Chromium·Firefox·WebKit에 띄운다. 남은 문자만으로 만든 문자열을 캡처한다. 예: `echo 'x' + ALM + ';>' + ALM + ' ; python3 …'`, U+2028 삽입, 옵션 안의 ZWSP. 화면에 보이는 순서가 실제 argv와 다른지 기록한다.
수정(결과와 관계없이 권장): display.py 두 정규식에 U+061C와 Cf·Zl·Zp 문자를 더하고 회귀 테스트를 추가한다.

**부모 실측 (run 뒤, 에이전트 예산 밖).** 판정은 바꾸지 않았다. 판정을 바꾸려면 새 검증자가 필요하다.

실제 앱의 `/ui/approvals` 카드를 Chromium 141로 그려 캡처했다(`agents/parent-live/parent_live_bidi.py`, 결과 `artifacts/bidi-*.png`, `bidi-render.json`).
- `cat /workspace/notes.txt ALM>ALM /workspace/outbox/copy.txt`는 카드에 **`cat /workspace/notes.txt < /workspace/outbox/copy.txt`**로 보였다. 두 ALM 사이의 `>`가 오른쪽→왼쪽으로 풀리며 `<`로 거울 반전됐다.
- 같은 문자열을 bash로 실행하면 이름이 ALM인 새 파일을 만들고 내용을 써 넣는다(`artifacts/bidi-bash-exec.txt`). 화면은 '입력 리디렉션(읽기)'인데 실제는 '출력 리디렉션(쓰기)'이다.
- U+2028은 같은 줄에 공백처럼 보였고, ZWSP는 보이지 않았다. 둘 다 위험한 쪽으로 오해시키지는 않았다.
- 결론: Chromium에서 승인 카드가 다른 명령처럼 읽힌다. Firefox·WebKit은 확인하지 못했다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** Source and a local render confirm a residual gap in the run-3 fix, but not its security outcome. web._shown (web.py:33-37) sends every template output through display.escape_controls with keep_newlines=True (web.py:94), and that class does neutralise the run-3 payloads: rendering the real _approvals.html through web.py's exact Jinja wiring turns U+200E/U+200F/U+202A-E/U+2066-9 into literal \uXXXX escapes while markupsafe escapes markup. The class is hand-written (display.py:13,15) and covers 11 of the 12 Unicode Bidi_Control characters: U+061C ARABIC LETTER MARK is absent, and so are U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029. Measured in the approved sandbox, all of them survive raw in both the command <pre> and the affected-path cell of the same card, and cli._safe (cli.py:33-35) is byte-identical, so the terminal approval view carries the same gap rather than disagreeing with the web view. What is not established is whether any of them lets the card read as a different command in the operator's browser. U+061C is bidi class AL, a strong right-to-left character, not an isolate: on its own it cannot reverse a run of ASCII letters (they stay strong L), and its bidi effect is limited to the resolved direction of adjacent neutral punctuation sitting between two of them. U+2028/U+2029 are mandatory line breaks that would split one argv into two visual lines inside the same pre block without hiding either line, and the remaining characters are invisible rather than reordering. That leaves a display-integrity question whose answer lives in the renderer, which no surface in this audit can observe.

**claimed_root_cause** display.py:13 and display.py:15 enumerate the control and bidi characters by hand. The set is C0/C1 plus exactly Bidi_Control minus U+061C, so ALM (Bidi_Control=Yes, bidi class AL) together with the Cf invisibles U+200B-200D, U+2060, U+FEFF, U+00AD and the separators U+2028/U+2029 pass through. web._shown applies that class to every str template output (web.py:35-36, 94) and cli._safe applies it to the terminal view (cli.py:35), so both human surfaces share the residual gap; nothing else filters those characters on the path from the stored approval args to the card.

**trace**

- `agentbox/api.py:215` (entrypoint, call_tool (POST /sandboxes/{sid}/tools/{tool}, agent token)) — The lowest-trust agent principal posts an exec call whose args.command it chooses; policy.decide routes a non-allowlisted program to approval, and nothing normalises or rejects unusual code points in the string.
- `agentbox/service.py:324` (propagation, call_tool REQUIRE_APPROVAL branch) — The approval is created with the agent's original args dict and the system preview (service.py:318; preview adds no affected paths for a plain echo/python3 command). approvals.py:56 persists the args with json.dumps(ensure_ascii=False), so the code points are stored as bytes the card will show and service.py:398/421 later executes.
- `agentbox/web.py:208` (propagation, approvals_view) — Pending approvals, including the original args and the system-computed preview paths, are listed and rendered into _approvals.html by the same view that serves both GET /ui/approvals and the approve/deny POST handlers.
- `agentbox/web.py:94` (propagation, tpl.env.finalize = _shown) — finalize runs _shown over every output expression, which applies escape_controls(value, keep_newlines=True) to str values only (web.py:33-37); no template uses |safe or Markup, so this hand-written class is the entire filter for the card.
- `agentbox/templates/_approvals.html:8` (sink, exec command <pre> (and the affected-path cell at line 14)) — The command is emitted into <pre> without short(), so only autoescape plus display.py:13/15 apply. Locally rendered with U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029 placed in the command and in an affected path, every one of them reaches the HTML raw in both cells while U+200E/U+200F/U+202A-E/U+2066-9 come out as visible \uXXXX escapes.

**blockers**

- No browser or terminal renderer is reachable from the approved sandbox (python3 plus the repo and jinja2/fastapi only, no network, no display), so the rendered order of the residual code points cannot be observed. The local run proves the reachability half only: U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029 arrive raw in the card's <pre> and path cell while the argv executed by service.decide (service.py:398,421 -> service.py:126) keeps the same code points.
- The decisive fact is whether a residual code point makes the card read as a different command. U+061C is bidi class AL, a strong right-to-left character that cannot reverse ASCII letter runs; U+2028/U+2029 add a mandatory break inside the same pre block but hide nothing; U+200B-200D/U+2060/U+FEFF/U+00AD are invisible and only affect how individual characters join. Which of these, if any, yields a misstatement depends on the browser engine, the resolved base direction and the font stack, none of which the repository pins (base.html:23 sets white-space: pre-wrap and no unicode-bidi isolation).
- Which browser engine versions, fonts and terminal emulator the operator actually uses is unknown to this audit, and that choice decides whether ALM and the separator characters produce any visible difference between the approved view and the executed command.

**validation_plan.local** Already done in this run (artifact v12bidi.out): a per-code-point table (unicodedata.category, unicodedata.bidirectional, UNSAFE/_UNSAFE_KEEP_NEWLINES match) plus a render of the real _approvals.html through web.py's exact wiring (Jinja2Templates over agentbox/templates, env.finalize = web._shown, env.filters['short'] = web._short) with a command and an affected path carrying every candidate code point and an inline script tag. Result: U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028, U+2029 raw in both cells; U+200E/U+200F/U+202A-E/U+2066-9 as literal escapes; markup escaped; cli._safe output byte-identical to web._shown. Next, still offline with dummy data: render the same fragment from a loopback static file in a local browser engine (Playwright Chromium, Firefox, WebKit) and capture the rendered line/baseline order of the pre block for payloads built only from the residual set - (a) echo 'x' + ALM + ';>' + ALM + ' ; python3 /workspace/job.py', (b) the same command with U+2028 placed before the trailing echo, (c) a ZWSP inside one option token - then compare each capture with the argv string and record whether the card states a different command. Regression, worth doing regardless of the browser result: add U+061C to both regexes in display.py plus the Cf/Zl/Zp invisibles (keeping tab/newline in the keep_newlines variant) and add a test asserting escape_controls neutralises U+061C, U+200B and U+2028 in both modes; grep shows no test currently exercises this class.

**validation_plan.deployment** Owner-side and non-destructive: on a dummy sandbox, queue one pending exec approval whose command contains two ALMs around a ';' and a U+2028 between two shell commands, open /ui/approvals in the operator's real browser and the same request in the terminal 'agentbox approve' view, and compare what is rendered with the exact argv returned by GET /approvals/{aid} (or the audit 'tool_execute' args). No probing of live endpoints beyond the owner's own instance.


</details>
