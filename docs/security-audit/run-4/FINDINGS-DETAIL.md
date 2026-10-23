# run-4 확정 상세

`findings.json`의 확정 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같다. 항목마다 아래에 영어 레코드 원문을 접어 두었고, 원문이 기준이다. 줄 번호는 감사 기준 `9805d91`을 따른다. 확정 건은 아직 고치지 않았다.

## F1. [중간] 인증 전 요청 본문을 401로 거절하기 전에 끝까지 읽고 JSON 해석·멀티파트 임시 저장까지 한다

- 지문: `agentbox/api.py:preauth-request-body-read-before-principal`
- 심각도: 가능성 높음 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/api.py:174`(진입점), `agentbox/api.py:115`(전파), `agentbox/api.py:277`(전파), `agentbox/api.py:278`(전파), `agentbox/api.py:113`(도달점)

**설명.** 본문 모델이나 `File(...)`을 받는 라우트(`POST /sandboxes`, `/restore`, `/tools/{tool}`, `/approvals/{aid}`, `/files`)는 FastAPI가 본문을 읽고 해석한 다음에야 `principal`·`human_only`·`screen_human` 의존성을 푼다. 그래서 토큰이 없는 클라이언트가 고른 크기만큼 컨트롤 플레인이 메모리에 올리고, 업로드 라우트는 TMPDIR에 임시 파일까지 쓴 뒤에 401을 돌려준다. 앱 미들웨어는 `_NoFraming` 하나뿐이다. `agentbox serve`는 uvicorn에 본문·동시성 상한을 넘기지 않고, 배포용 Caddyfile에도 `request_body` 제한이 없다. 파일당 상한(`max_upload_bytes`)과 `LOGGED_ARGS_MAX`는 인증이 끝난 뒤에만 적용된다.

**근본 원인.** 인증 의존성이 FastAPI의 본문 해석 단계 뒤에 돈다. 그리고 앞단(ASGI 미들웨어, uvicorn 옵션, 동봉 Caddy)에 본문 크기 상한이 없다. 그래서 인증 없는 요청에 드는 일이 공격자가 고른 본문 크기에 비례한다.

**지켜야 할 동작.** 인증할 수 없는 요청은 본문을 버퍼링·해석·디스크 기록하기 전에 거절해야 한다. 문서화한 상한을 넘는 본문은 자격 증명과 관계없이 413이어야 한다.

**재현 관측.**

fastapi 0.161.1 / starlette 1.9.0 / uvicorn 0.54.0에서 확인했다.
- 인증 없이 16 MiB JSON을 `POST /sandboxes`에 보냈다. 401이 나왔지만 응답 전에 16,777,216바이트를 모두 읽고 해석했고, RSS가 32 MiB(본문의 2배) 늘었다.
- `/tools/exec`, `/restore`, `/approvals/{aid}`도 4 MiB 본문으로 같았다.
- `/files`에 4 MiB 파일 한 개를 보냈다. 401 전에 TMPDIR에 4 MiB 임시 파일이 생겼다. 엔드포인트의 파일당 50 MiB 상한은 실행되지 않았다.

**성립 조건.** 인증 수준, 네트워크 경로, 환경 의존. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** FastAPI 본문 단계 앞에 ASGI 미들웨어를 둔다. Content-Length가 상한을 넘으면 413을 주고, chunked 본문은 읽은 바이트를 세다 상한에서 끊는다. JSON 상한은 정상 최대(`write_file` 1 MiB)보다 크게 잡고, 멀티파트는 요청 전체 상한을 새 설정으로 둔다. `deploy/Caddyfile`에 `request_body { max_size … }`를 추가한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** agentbox's body routes declare a request-body model - or a File(...) list - together with Depends(principal) / human_only / screen_human (agentbox/api.py:175, 206, 216, 251, 277). In FastAPI's request handler the body is read and JSON-decoded - and on the upload route streamed through request.form() and spooled - before solve_dependencies resolves any of those dependencies, so an unauthenticated client decides how many bytes the control plane buffers, decodes and writes to TMPDIR before it is told 401. Nothing in the tree bounds that work: the only middleware is _NoFraming (api.py:63-80, registered at 113), the serve entry point passes no request-size or concurrency limit to uvicorn (agentbox/cli.py:127), and the shipped Caddy front end has no request_body directive (deploy/Caddyfile:5). The caps that do exist - max_upload_bytes per file (config.py:57, enforced inside the endpoint at api.py:278-283) and LOGGED_ARGS_MAX (service.py:37-38) - run only after a principal exists. Starlette's multipart parser bounds part cardinality (1000 files/fields) and 1 MiB for non-file fields, but not file-part bytes.

**root_cause** Authentication dependencies run after FastAPI's body-parsing stage, and nothing in front of the app - ASGI middleware, uvicorn options, or the bundled Caddy reverse proxy - enforces a maximum request-body size, so unauthenticated work scales with the attacker's body size instead of with the negligible work needed to reject an unauthenticated request.

**intended_behavior** Requests that cannot yet be authenticated should be rejected before their body is buffered, decoded or written to disk, and bodies above a documented cap should be refused with 413 regardless of credential state.

**trace**

- `agentbox/api.py:174` (entrypoint, POST /sandboxes, and every sibling body route: /sandboxes/{sid}/restore (205-206), /sandboxes/{sid}/tools/{tool} (215-216), /approvals/{aid} (250-251), /sandboxes/{sid}/files (276-277)) — A lower-trust network client with no token reaches a route that declares both a body (CreateSandbox) and Depends(human_only). Declaring the body is what makes FastAPI's handler stage read and JSON-decode the whole request body before any dependency is solved (verified in the installed fastapi 0.161.1 get_request_handler source: body read/decode block precedes the solve_dependencies call).
- `agentbox/api.py:115` (propagation, principal() - first credential check for the JSON API; human_only and screen_human build on it) — principal() compare_digest's the bearer token (119), looks up an agent token (121) and raises 401 at 117/124. It runs only after the body stage, so no principal exists while the body is buffered and decoded.
- `agentbox/api.py:277` (propagation, POST /sandboxes/{sid}/files multipart body) — files: list[UploadFile] = File(...) makes the handler call request.form() before screen_human runs; Starlette streams the whole multipart body and rolls every file part past the 1 MiB spool threshold into a SpooledTemporaryFile under the control plane's TMPDIR.
- `agentbox/api.py:278` (propagation, per-file cap applied after parsing and after authentication) — limit = settings.max_upload_bytes with await f.read(limit + 1) at 281-283 executes only inside the endpoint, i.e. after the whole body has been spooled and only when a principal was already accepted, so it cannot bound pre-auth work.
- `agentbox/api.py:113` (sink, the only middleware installed on the app (no body-size gate on the way into FastAPI's body stage)) — _NoFraming is the last app-owned code a request passes, and it only appends response headers. With cli.py:127 and deploy/Caddyfile:5 adding no limit either, the attacker-chosen body becomes control-plane heap and temp-disk state before principal()/screen_human can reject it.

**conditions**

- authentication_level: None: no Authorization header and no session cookie are required for the buffering; every tested path returned 401 only after the body had been consumed.
- network_routing: The client can reach the control plane through the shipped Caddy front end (compose publishes 443/80 and forwards bodies without a size directive), or directly when agentbox serve is used.
- environmental_dependency: Impact scales with the memory and TMPDIR of the single uvicorn process that also serves the human approval queue and the audit chain; the compose service sets no mem_limit, so exhausting the process takes the approval path down with it (pending approvals, 300 s default, age toward timeout while the operator restarts).

**execution.attacker_perspective** An unauthenticated network client that never holds a token sends bodies of its choosing to routes it knows will answer 401, or to the upload route, and lets the control plane read, decode and spool them. The attacker's spend is the bytes it uploads, while the server retains about twice that in heap per in-flight body (measured), with no per-request and no concurrency bound in the shipped configuration.

**execution.instructions**

1. Inside the approved OS sandbox only (no network, no Docker socket, 512 MiB, 1 CPU, uid 65534, 120 s), with /target read-only on PYTHONPATH and AGENTBOX_HOME under /scratch: replace docker.from_env with an in-process fake whose info() reports only the runc runtime, then build the real app with api.build(Settings()) from the audited tree.
2. Drive the app at the ASGI layer with an HTTP scope for the target path and a receive() that streams the declared body in 64 KiB http.request messages, recording how many body bytes the app consumed before it emitted http.response.start.
3. Patch starlette.requests.Request.json to record len(raw body) at decode time, and starlette.formparsers.SpooledTemporaryFile to record max_size, bytes written, whether it rolled to a real temporary file and that file's on-disk size under TMPDIR.
4. Send the payloads with no Authorization header and no cookie; record the status, the bytes consumed before the response started, and the decode/spool records. Read resource.getrusage(RUSAGE_SELF).ru_maxrss before and after the largest JSON request to bound the memory effect. Keep the largest body at 16 MiB so the sandbox limit is never approached, and stop after the first confirming observation.
5. Send a control request (GET /healthz, no body) through the same driver to prove the app object is functional and the 401 comes from the credential check.

**execution.observed_result** Installed stack: fastapi 0.161.1, starlette 1.9.0, uvicorn 0.54.0. POST /sandboxes with a 16,777,216-byte JSON body and no Authorization returned 401, but the app had consumed all 16,777,216 bytes before emitting http.response.start and Request.json() had decoded 16,777,216 bytes; peak RSS grew 32,768 KiB (2.0x the body). /sandboxes/{sid}/tools/exec, /sandboxes/{sid}/restore and /approvals/{aid} behaved identically with 4,194,304-byte bodies - all bytes consumed and decoded before the 401. POST /sandboxes/{sid}/files with one 4,194,304-byte part and no cookie returned 401 after consuming all 4,194,442 bytes; at that moment the SpooledTemporaryFile (max_size 1,048,576) had rolled to a real temporary file holding 4,194,184 bytes in TMPDIR, the endpoint's 50 MiB per-file cap never ran, and the temporary file was removed when the form closed (no residue afterwards). A control GET /healthz returned 200 with 0 body bytes consumed. The installed multipart parser carries max_files/max_fields = 1000 and max_part_size = 1 MiB, but max_part_size is applied only to non-file fields, so a 4 MiB file part passed untouched.

**remediation.strategy** Reject oversized bodies before FastAPI's body stage and before any authentication work: install an ASGI middleware beside _NoFraming that answers 413 when the declared Content-Length already exceeds the cap and counts streamed bytes for chunked bodies, aborting at the cap; keep the application/JSON cap above the largest legitimate body (write_file content is bounded by max_write_bytes = 1 MiB, so a 64 KiB JSON cap would break authenticated tool calls) and give the multipart route an aggregate body cap from a new setting (default e.g. 64 MiB for the whole request, not per file); and add request_body { max_size ... } to deploy/Caddyfile so the shipped proxy refuses the same oversized bodies before they reach the process.

`agentbox/api.py`:

```python
# from starlette.requests import ClientDisconnect

class _BodyLimit:
    """FastAPI가 본문을 읽기 전에 크기 상한을 강제한다 (인증 전, 보안 검수 run-4 v01)."""

    def __init__(self, app, json_max: int, upload_max: int):
        self.app, self.json_max, self.upload_max = app, json_max, upload_max

    def _cap(self, scope) -> int:
        return self.upload_max if scope.get("path", "").endswith("/files") else self.json_max

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cap = self._cap(scope)
        declared = None
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
        if declared is not None and declared > cap:
            return await Response("요청 본문이 너무 큼", status_code=413)(scope, receive, send)
        seen = 0

        async def limited():
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > cap:
                raise ClientDisconnect()   # 스트리밍 본문이 상한을 넘으면 연결을 끊는다
            return message

        return await self.app(scope, limited, send)

    # _NoFraming 등록 옆에:
    app.add_middleware(_BodyLimit, json_max=settings.max_body_bytes,
                       upload_max=settings.max_upload_body_bytes)
```

`agentbox/config.py`:

```python
    # FastAPI가 본문을 읽기 전에 거부할 요청 본문 상한. write_file 인자(max_write_bytes)보다 커야 한다.
    max_body_bytes: int = field(default_factory=lambda: int(_env("AGENTBOX_MAX_BODY", str(4 * 1024 * 1024))))
    # 업로드 경로의 요청 전체 상한 (파일 하나가 아니라 한 요청)
    max_upload_body_bytes: int = field(
        default_factory=lambda: int(_env("AGENTBOX_MAX_UPLOAD_BODY", str(64 * 1024 * 1024))))
```

`deploy/Caddyfile`:

```python
{$AGENTBOX_SITE} {
	request_body {
		max_size 64MB
	}
	reverse_proxy agentbox:8765
}
```

</details>

## F2. [중간] 사람이 화면을 돌려주는 사이 `gui_lock`을 기다리던 GUI 입력이, 열린 구간 없이 실행돼 스냅샷과 `gui_changes` 기록이 남지 않는다

- 지문: `agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback`
- 심각도: 가능성 중간 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/api.py:215`(진입점), `agentbox/service.py:343`(전파), `agentbox/service.py:136`(전파), `agentbox/service.py:152`(전파), `agentbox/service.py:542`(전파), `agentbox/service.py:543`(전파), `agentbox/service.py:139`(전파), `agentbox/gui_bursts.py:62`(전파), `agentbox/gui_bursts.py:113`(도달점)

**설명.** GUI 입력이 스냅샷을 찍을지는 `gui_lock`을 잡기 전에 정한다(service.py:343). 사람이 화면을 쥔 동안에는 리스가 있어서 `needs_snapshot`이 False가 되고, 입력은 구간을 열지 않은 채 `gui_lock`을 기다린다. 그사이 사람이 화면을 돌려주면 입력은 리스 검사를 통과해 구간 없이 uid 1001로 실행된다. 이어서 `mark_input`이 입력 시각을 갱신한다. 그래서 그 뒤 입력도 60초 동안 입력이 없거나 마지막 스냅샷 뒤 600초가 지날 때까지 스냅샷·구간·`gui_changes`가 생기지 않는다.

**근본 원인.** 구간을 열지 결정하는 일이, 실행을 직렬화하는 락 밖에서 일어난다. 락 안에서 다시 확인하는 `_check_control`은 리스 상태만 보고 구간이 있는지는 보지 않는다.

**지켜야 할 동작.** 실행되는 GUI 입력은 모두, 그 입력 전에 찍은 스냅샷에 묶인 열린 구간 안에 있어야 한다. 락을 기다리기 전에 내린 결정은 락을 잡은 뒤 다시 확인해야 한다.

**재현 관측.**

대기하던 클릭이 200으로 실행됐고, 판단 시점에는 리스가 있어 `needs_snapshot`이 False였다. 스냅샷은 1개 그대로였고 `gui_changes`도 인수 때 쓴 1행 그대로였다. 클릭과 뒤이은 3번의 클릭(모두 200)이 파일 4개를 만들었지만 아무 기록이 없었다. 같은 4번의 클릭을 열린 구간 안에서 한 대조군은 `gui_changes added=4`를 남겼다. 시간 창을 넓히려고 인계의 감사 기록 안에 멈춤을 넣었는데, 그 순서 자체는 코드가 허용한다.

**성립 조건.** 인증 수준, 타이밍, 사용자 상호작용, 데이터 상태. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** `_run_tool`이 `gui_lock`을 잡은 뒤 `needs_snapshot`을 다시 판단하고 그 자리에서 스냅샷·구간을 연다. 구간이 없으면 실패로 닫는다. 판단 기준은 입력 시각뿐 아니라 구간이 있는지까지 본다. 인계 경로에서는 다음 입력이 새 구간을 열게 한다. 위 순서로 회귀 테스트를 추가한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** AgentBox decides whether a GUI input needs a snapshot before it acquires gui_lock. While a human holds the desktop a takeover lease exists, so GuiBursts.needs_snapshot returns False and the input blocks on gui_lock instead of opening a burst. If the human hands the desktop back while that input is queued, the input runs with a lease check that now passes and no burst open: it writes as uid 1001, calls mark_input, and its fresh input timestamp makes needs_snapshot False for every later input until 60 s of input silence (gui_snapshot_idle) or 600 s after the last snapshot (gui_snapshot_interval). Those inputs produce no snapshot, no burst, and no gui_changes row; the only recovery point predates the human takeover, and the file effects of the inputs are never diffed or attributed.

**root_cause** The burst decision is taken outside the lock that serializes execution: service.py:343 evaluates _needs_snapshot (gui_bursts.py:52-63, which returns False while a non-stale lease or pending takeover exists) before _run_tool acquires gui_lock at service.py:136, and the only re-check under the lock (_check_control, service.py:152-161) validates the stale-lease/lease/pending-takeover state, never burst presence. _handback_locked (service.py:528-543) releases the lease (542) and calls forget_input (543) while still holding gui_lock, so the queued input resumes into a state where its earlier premise is gone and nothing takes a snapshot; mark_input (service.py:139) then suppresses the next burst decision.

**intended_behavior** Every GUI input that executes must be covered by an open burst bound to a snapshot taken before that input, and each burst must close into a gui_changes record (service.py:261-264 fails closed when a burst baseline cannot be opened; gui_bursts.py:157-162 re-timers lifecycle paths for exactly this reason). A burst decision taken before waiting on a lock must be re-validated after the lock is acquired.

**trace**

- `agentbox/api.py:215` (entrypoint, POST /sandboxes/{sid}/tools/{tool} -> AgentBox.call_tool) — Agent token from principal; default_policy.yaml has default: allow and no rule for click/type/key, so GUI inputs are approval-free, are audited as tool_request, and take the ALLOW branch.
- `agentbox/service.py:343` (propagation, AgentBox._call_tool (ALLOW branch)) — _needs_snapshot is evaluated before any lock; while a takeover lease is present _over_snapshot_quota is skipped too and GuiBursts.needs_snapshot returns False, so no snapshot is taken and no burst is opened.
- `agentbox/service.py:136` (propagation, AgentBox._run_tool (GUI branch)) — gui_lock is acquired afterwards without a timeout, so an input that already decided 'no burst needed' can sit queued while the human's handback holds the same lock.
- `agentbox/service.py:152` (propagation, AgentBox._check_control) — The only re-check after acquiring gui_lock handles a stale lease, a live lease and the pending-takeover marker; burst presence and the earlier needs_snapshot result are never re-validated.
- `agentbox/service.py:542` (propagation, AgentBox._handback_locked) — While gui_lock is still held, the human handback releases the lease; the queued input then acquires the lock with no lease and no pending marker, so _check_control passes.
- `agentbox/service.py:543` (propagation, AgentBox._handback_locked) — forget_input only drops the input timestamp; the handback opens no burst, so the resumed input's decision premise is gone but nothing forces a snapshot.
- `agentbox/service.py:139` (propagation, AgentBox._run_tool (GUI branch)) — The resumed input executes the GUI action and calls bursts.mark_input although no burst is open.
- `agentbox/gui_bursts.py:62` (propagation, GuiBursts.needs_snapshot) — The fresh input timestamp makes the next decision False, so later inputs run burstless until gui_snapshot_idle of silence or gui_snapshot_interval since the last snapshot.
- `agentbox/gui_bursts.py:113` (sink, GuiBursts._finish) — Only an open burst is ever diffed and logged as gui_changes; no burst exists for these inputs, so their /workspace changes are never recorded.

**conditions**

- authentication_level: A sandbox agent token (agt_...); GUI tools are default-allow (default_policy.yaml default: allow) and need no human approval.
- timing_dependency: The single in-flight GUI input must take its burst decision while the takeover lease exists and then acquire gui_lock after the handback released the lease. A tight loop of click/type calls during the takeover (each 423) raises the hit rate; the window is the handback's lock-held section (audit write plus lease release), which SQLite/audit contention widens.
- user_interaction: The human must hand the desktop back through handback, logout, or pause/restore/delete via end_desktop, because that path is the one that holds gui_lock across the lease release.
- data_state: A snapshot taken within gui_snapshot_interval (default 600 s) exists, so after the burstless input the fresh mark_input timestamp keeps later inputs from opening a burst; the queued input itself needs only the lease.

**execution.attacker_perspective** An agent that wants to change the desktop without a gui_changes row and without a fresh recovery point keeps issuing GUI inputs while a human holds the desktop, so one of them is queued on gui_lock when the human hands back, and then keeps clicking/typing immediately afterwards.

**execution.instructions**

1. Bounded harness in the approved audit sandbox (sbx.py v08, no network, /target read-only): real AgentBox, GuiBursts and DesktopControl (sqlite :memory:); fake SandboxManager (click/type add a manifest entry), in-memory AuditLog with one hook, default-allow Policy, empty ApprovalStore.
2. Seed one click so a snapshot (snap_1) and an open burst exist; call box.takeover(sid, 'hs_human') so the burst is closed and a lease is held.
3. Install a hook on AuditLog.append('human_handback'): it starts the agent's click thread, waits until that thread has recorded its needs_snapshot decision (False, lease present, no burst), verifies it is blocked on gui_lock, then returns so box.handback(sid, 'hs_human') can release the lease and unlock.
4. Join the agent thread, then issue three more clicks, and read snapshot count, bursts._gui_burst, audit gui_changes rows and needs_snapshot.
5. Control run on a fresh box: seed click, three clicks while the burst is open, then takeover to close the burst, and compare the gui_changes diff.

**execution.observed_result** The queued click executed with status 200 executed and needs_snapshot False taken while the lease was still present and no burst open; snapshots stayed 1 and gui_changes stayed at the single row the takeover wrote for the seed burst, while the click plus three following clicks (all 200) added 4 files (5 files total). All four burst decisions were False, so no new snapshot or burst appeared. The control run with the same four clicks inside an open burst logged gui_changes added=4 for snap_1 when the burst closed. The only artificial element is a pause inside the handback's audit append (a real SQLite write), which widens the natural window; the ordering it produces is one the code allows.

**remediation.strategy** Decide the GUI burst requirement under the same lock that serializes GUI execution: after gui_lock is acquired in _run_tool, re-evaluate needs_snapshot and take the snapshot / open the burst there, and fail closed with reset_timers if no burst is open. Key the decision on burst presence rather than only on input timestamps, and make the handback path force the next input to open a new burst instead of only forgetting the timestamp. Regression test: hold gui_lock with an input queued, release the lease inside the lock, release the lock, and assert the input never calls mark_input or executes without an open burst.

`agentbox/service.py`:

```python
if tool in GUI_TOOLS:
    with self.desktop.gui_lock(sid):
        self._check_control(sid)
        if tool in GUI_INPUT:
            if self.bursts.needs_snapshot(sid):   # must be re-decided here, not at _call_tool:343
                self._snapshot(sid, tool, f"before {tool}", {})
            if not self.bursts.is_open(sid):
                self.bursts.reset_timers(sid)   # next input re-decides and opens a burst
                raise SandboxError("GUI 구간이 열려 있지 않아 GUI 입력을 실행하지 않음. 잠시 뒤 다시 호출할 것")
            self.bursts.mark_input(sid)
```

`agentbox/gui_bursts.py`:

```python
def is_open(self, sid: str) -> bool:
    """입력이 실행될 때 열린 구간이 있는가. 구간 없이 실행하면 바뀐 것이 기록되지 않는다."""
    with self._lock:
        return sid in self._gui_burst
```

</details>

## F3. [중간] 에이전트 도구 입력이 승인 미리보기와 도구 오류 문자열을 거쳐 여전히 상한 없이 추가 전용 감사 로그에 들어간다

- 지문: `agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap`
- 심각도: 가능성 높음 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/api.py:216`(진입점), `agentbox/service.py:295`(전파), `agentbox/service.py:318`(전파), `agentbox/service.py:330`(전파), `agentbox/service.py:361`(전파), `agentbox/audit.py:183`(도달점)

**설명.** run-3 v08 수정(`_logged_args`)은 `tool_request`와 `tool_execute` 두 기록만 자른다. 같은 요청 경로에서 에이전트 문자열이 상한 없이 들어가는 곳이 두 군데 남았다.
1. 승인이 필요한 호출의 `approval_requested` 기록이 미리보기를 그대로 담는다. 미리보기는 exec 명령 원문 전체와 조각마다 붙는 메모를 개수 제한 없이 담고, 실패하면 에이전트 경로가 든 오류 문자열을 담는다.
2. 승인 없이 허용되는 `read_file`이 실패하면 오류 문자열 전체를 `tool_error`에 남긴다.
본문 크기 제한도, `audit.append`의 크기 검사도 없다. 감사 행은 지울 수 없다.

**근본 원인.** `_call_tool`은 `_logged_args`를 거치는 두 기록만 자른다. 미리보기와 `SandboxError` 문자열은 그대로 기록되고, `audit.append` 자체에는 길이 제한이 없다.

**지켜야 할 동작.** 추가 전용 감사 로그에 들어가는 모든 payload는 어디서 만들어졌든 넣기 전에 크기가 제한돼야 한다. 오류 문자열, 미리보기 명령, 메모, 영향 경로를 자르고, 메모 개수도 제한한다.

**재현 관측.**

- `tool_request`는 `_logged_args`로 제한됐다.
- 131,072바이트 경로의 `read_file`은 승인 없이 131,142바이트 `tool_error` 행을 남겼다.
- 262,144바이트 경로의 `delete_file`은 262,342바이트 `approval_requested` 행을 남겼다.
- 2,001조각 exec는 96,207바이트 행과 메모 2,001개를 남겼다.
- `DELETE FROM audit`은 'append-only'로 거부됐다.

**성립 조건.** 인증 수준, 시스템 설정, 사용자 상호작용. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** `AuditLog.append` 안에 해시 계산 전에 문자열과 목록을 자르는 함수를 둔다. 그래야 `verify()`가 일관된다. 미리보기 명령·메모·영향 목록과 `SandboxError` 문자열도 기록 전에 자른다. 다층 방어로 도구 인자 본문 크기를 라우트와 프록시에서 제한한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The new _logged_args cap (service.py:181-194) bounds only the two audit copies that pass through it (tool_request at 295-296, tool_execute at 413-414). The same agent-controlled strings still reach audit.append uncapped through two other sinks on the same request path. (1) For an approval-requiring call the payload appended at service.py:330-333 carries the preview dict verbatim (line 332); _preview returns sandbox.preview's preview_command, which copies the whole raw exec command (preview.py:131) and appends one note per command segment with no count cap (preview.py:125, only 'affected' is truncated at 126-128), and when _preview raises, the failure note embeds str(SandboxError) - that is the raw agent path from safe_path (service.py:319-320, sandbox.py:156). (2) For read_file, which the default policy allows without approval, the same SandboxError text is stored as tool_error payload.error (service.py:360-362). Neither the tool route (api.py:216; ToolCall.args is an unconstrained dict at api.py:51) nor the shipped reverse proxy (deploy/Caddyfile:5) bounds the body, and AuditLog.append inserts json.dumps(payload) with no size check (audit.py:183). Audit rows are append-only (audit.py:35-38), so every retained byte is permanent; at disk-full the audit-writing paths fail closed with 503.

**root_cause** _call_tool caps only the two _logged_args mirrors (service.py:295-296, 413-414). The approval_requested payload passes preview through unchanged (service.py:330-333) while _preview copies the raw command and one note per segment (service.py:213-226, preview.py:125,131), and the SandboxError handler at service.py:360-362 logs str(e) untruncated although safe_path (sandbox.py:156) embeds the agent raw path. audit.append imposes no length bound of its own.

**intended_behavior** Every payload that reaches the append-only audit log is bounded before the insert regardless of the producing call site: error strings, preview command, notes and affected paths are truncated to a fixed budget, the note count is capped, and the tool-args body is rejected above a small limit.

**trace**

- `agentbox/api.py:216` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — Agent-token route; ToolCall.args (api.py:51-52) is parsed from the JSON body with no size limit, so the argument size equals what the agent sends.
- `agentbox/service.py:295` (propagation, tool_request record) — Records args through the capped _logged_args, then evaluates policy; the capped copy is not the only path the arguments take.
- `agentbox/service.py:318` (propagation, _preview producer) — For exec, sandbox.preview returns preview_command's full raw command; for an invalid workspace path, safe_path raises with the raw path and the handler at 319-320 turns str(e) into a preview note; raw args also go to ApprovalStore.create at 324.
- `agentbox/service.py:330` (propagation, approval_requested audit append) — The payload carries the preview dict minus the capture image with no truncation of command, notes or affected entries (line 332), written before any human is involved.
- `agentbox/service.py:361` (propagation, SandboxError handler) — The untruncated str(e) is appended as payload.error; read_file and write_file need no approval, so this row is written on the first request.
- `agentbox/audit.py:183` (sink, AuditLog.append INSERT) — json.dumps of the masked payload is inserted into the append-only audit table with no length or count bound.

**conditions**

- authentication_level: Any valid agent token for one sandbox; the human token is not needed.
- system_configuration: Default policy: delete_file always requires approval, non-allowlisted exec requires approval, while read_file and write_file are allowed, so the tool_error variant needs no approval at all.
- user_interaction: None: approval_requested rows are written before any human sees the request, and the read_file variant needs no approval.

**execution.attacker_perspective** A prompt-injected agent sends one oversized tool argument and picks whichever tool gives the largest uncapped echo into the audit log.

**execution.instructions**

1. In the approved OS-enforced sandbox (sbx v09: /target read-only on sys.path, /scratch writable, uid 65534, 512 MiB, 1 CPU, 120 s, no network, no Docker), run /scratch/v09_repro.py with /usr/bin/python3.
2. The script builds a real AgentBox with real AuditLog, ApprovalStore, Policy(default_policy.yaml), safe_path, SandboxManager.read_file and preview_command, faking only the Docker- and SQLite-facing SandboxManager methods (get, template_of, _require_running, _container, _expand, _walk, exists).
3. Call box.call_tool with each payload and read back SELECT id,actor,event,tool,length(payload) FROM audit plus length(args),length(preview) from the approvals table.
4. Attempt DELETE FROM audit on an oversized row, then set PRAGMA max_page_count as a deterministic full-disk stand-in and observe the next append and the following tool call.

**execution.observed_result** tool_request stayed bounded by _logged_args: 16,543 B for the two oversized-argument requests, and roughly 10.9 KB (not capped, because it fits under the 64 KiB LOGGED_ARGS_MAX) for the 10,003-byte exec request. The other sinks were not bounded: read_file with a 131,072-byte path outside /workspace returned 400 with a 131,115-byte message and wrote a 131,142-byte tool_error row with no approval; delete_file with a 262,144-byte path outside /workspace wrote a 262,342-byte approval_requested row whose single preview note began '미리보기 실패: 허용되지 않은 경로: /etc/AAAA…' (approval row: 262,156 B args, 262,244 B preview); exec with a 10,003-byte, 2001-segment command wrote a 96,207-byte approval_requested row carrying the full 10,003-byte preview.command and 2,001 notes (approval row: 10,018 B args, 96,109 B preview). DELETE FROM audit raised 'audit log is append-only'. With the page cap as a full-disk stand-in the append raised AuditWriteError 'database or disk is full' and the following tool call failed closed with 503.

**remediation.strategy** Bound payloads at the sink and at the producers: one recursive bounder inside AuditLog.append (string truncation plus list/dict cap) applied before compute_hash so verify() stays consistent, truncate the preview command/notes/affected and the SandboxError text before they are appended, and reject oversized tool-args bodies at the route with a request_body limit in the shipped proxy as defense in depth.

`agentbox/audit.py`:

```python
AUDIT_STR_MAX = 4096
AUDIT_LIST_MAX = 200

def _bound(v):
    if isinstance(v, str):
        return v if len(v) <= AUDIT_STR_MAX else v[:AUDIT_STR_MAX] + f"...({len(v)} bytes)"
    if isinstance(v, dict):
        return {k: _bound(x) for k, x in list(v.items())[:AUDIT_LIST_MAX]}
    if isinstance(v, list):
        return [_bound(x) for x in v[:AUDIT_LIST_MAX]]
    return v

# in append(), before compute_hash(prev_hash, record):
payload = _bound(self._mask(payload or {}))
```

`agentbox/service.py`:

```python
AUDIT_TEXT_MAX = 512

def _audit_text(s: Any) -> str:
    t = str(s)
    return t if len(t) <= AUDIT_TEXT_MAX else t[:AUDIT_TEXT_MAX] + f"...({len(t)} bytes)"

# _preview failure note and exec command, before they are appended/created:
notes = [f"미리보기 실패: {_audit_text(e)}"]
preview["command"] = _audit_text(preview.get("command"))
preview["notes"] = [_audit_text(n) for n in (preview.get("notes") or [])][:200]
preview["affected"] = (preview.get("affected") or [])[:200]

# SandboxError handler:
except SandboxError as e:
    short = _audit_text(e)
    self.log_best_effort(sid, tool, "tool_error", {"request": req_id, "error": short})
    raise ServiceError(400, short) from e
```

</details>

## F4. [낮음] 승인 카드 영향 표가 공백·줄바꿈이 든 `rm` 대상을 잘못 보여 준다(있는 파일을 '없음'으로 표시)

- 지문: `agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets`
- 심각도: 가능성 중간 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/api.py:215`(진입점), `agentbox/service.py:318`(전파), `agentbox/service.py:215`(전파), `agentbox/sandbox.py:573`(전파), `agentbox/preview.py:89`(전파), `agentbox/sandbox.py:559`(전파), `agentbox/sandbox.py:562`(전파), `agentbox/preview.py:90`(전파), `agentbox/sandbox.py:411`(도달점)

**설명.** 승인이 필요한 exec의 '시스템 계산 영향' 표는 `_expand`·`_walk`와 `preview_command`가 만든다.
- `_expand`는 이미 따옴표를 벗긴 `rm` 인자를 `$1`로 넘기고 따옴표 없이 순회한다. 그래서 인자가 IFS로 쪼개지고 조각마다 다시 확장된다.
- 결과는 줄바꿈으로 나뉜다.
- 실제 `rm`은 원래 따옴표대로 `bash -c`에서 돈다.
그래서 `rm "final report.docx"`의 카드는 '삭제 시도 (현재 존재하지 않음)' 한 줄만 보여 주는데, 실제로는 그 파일이 지워진다. 같은 이름 조각의 미끼 파일이 있으면 미끼가 삭제 목록에 오른다. run-3 v17(인식 못 한 조각 경고)은 고쳐져 있음을 함께 확인했다.

**근본 원인.** 미리보기 경로 전달이 파일 경로를 손실 없이 나타내지 못한다. sandbox.py:559가 `$1`을 따옴표 없이 순회하고, 결과를 줄 단위로 나눈다. preview.py:90-98은 빈 결과를 '없음' 행으로, 줄마다 '삭제' 행으로 바꾼다.

**지켜야 할 동작.** 승인 카드 옆 영향 목록은 저장된 명령이 실제로 건드릴 경로를 정확히 보여 줘야 한다. 있는 경로를 없다고 하거나, 지우지 않을 경로를 삭제 목록에 넣어서는 안 된다.

**재현 관측.**

- 경우 B: 실제로 있는 `final report.docx`가 '삭제 시도 (현재 존재하지 않음)'로 표시됐고 메모도 없었다.
- 경우 C: 미끼 파일 `final`과 `report.docx`가 삭제 행으로 나왔고 실제 대상은 나오지 않았다.
- 실행: `sh -c 'rm "final report.docx"'`가 0으로 끝났고 파일이 지워졌다.
- 제안한 수정(IFS 비우기와 NUL 구분)을 같은 입력에 돌리면 정확한 목록이 나왔다.

**성립 조건.** 인증 수준, 사용자 상호작용, 데이터 상태, 시스템 설정. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** `_expand`에서 IFS를 비워 인자를 한 단어로 다루고, 결과를 NUL로 구분한다. `_walk`는 `find -print0 | head -z`를 쓰고 NUL로 나눈다. 공백·탭·줄바꿈 이름으로 회귀 테스트를 추가한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** For a gated exec the "system-computed impact" table is produced by SandboxManager._expand / _walk and preview_command. _expand hands the already-unquoted rm operand to sh as $1 and iterates over $1 unquoted, so the operand is word-split on IFS and each fragment is pathname-expanded before the [ -e ] existence test; results are newline-framed and re-split in Python, and _walk frames find output the same way. preview_command turns an empty match list into "삭제 시도 (현재 존재하지 않음)" and every returned line into a "삭제" row. The rm itself later runs through bash -c with the original quoting, so the computed path set and the executed path set differ: an agent whose workspace target contains a space obtains approval for a deletion the card describes as an apparent no-op, or for a card that lists unrelated decoy files, while the real file is deleted. Reproduced with the verbatim scripts: the card for a lone rm of an existing "final report.docx" showed exactly one row, "삭제 시도 (현재 존재하지 않음)", and no note.

**root_cause** The preview path transport is not a lossless representation of a filesystem path. sandbox.py:559 iterates $1 unquoted under the default IFS, so an operand that shlex already unquoted (preview.py:33-44) is re-split into words and each word is expanded again before the existence test; matches are framed with printf "%s\n" and re-split by splitlines() (sandbox.py:562), and _walk's find | head output is split the same way (sandbox.py:565-569). preview.py:90-91 maps an empty expansion to the "does not currently exist" row and preview.py:96-98 maps each returned line to a deletion row, so a split operand both hides the real target and can manufacture paths the command will never touch. The executed command keeps its quoting (sandbox.py:411), so the card and the effect diverge.

**intended_behavior** The affected list shown beside the approval must name exactly the paths the stored command will act on, so approving the card is equivalent to approving the effect: a path that exists must never be reported as nonexistent, and a path must never be listed as deleted unless the command deletes it.

**trace**

- `agentbox/api.py:215` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — The agent posts tool=exec with body.args.command under its own sandbox token.
- `agentbox/service.py:318` (propagation, AgentBox._call_tool) — For a REQUIRE_APPROVAL decision (default_policy.yaml:12-16 routes rm to require_approval) the preview is computed while the approval is created, before any human sees it.
- `agentbox/service.py:215` (propagation, AgentBox._preview) — exec previews delegate to SandboxManager.preview with the raw command string.
- `agentbox/sandbox.py:573` (propagation, SandboxManager.preview) — preview_command runs with expand=_expand and walk=_walk bound to the running container.
- `agentbox/preview.py:89` (propagation, preview_command rm branch) — Each rm operand (quotes already consumed by _split_segments, preview.py:33-44) is expanded once through the container callback.
- `agentbox/sandbox.py:559` (propagation, SandboxManager._expand) — The operand is passed as $1 and iterated unquoted, so the shell word-splits it on IFS and globs the fragments before [ -e "$p" ]; the surviving words are what get tested.
- `agentbox/sandbox.py:562` (propagation, SandboxManager._expand return) — Matches are framed one per line and re-split with splitlines(), so a name containing a newline arrives as two or more fake paths.
- `agentbox/preview.py:90` (propagation, preview_command affected rows) — An empty expansion becomes the "삭제 시도 (현재 존재하지 않음)" row and each returned line becomes a deletion row; the result is stored with the approval and rendered as the system-computed impact.
- `agentbox/sandbox.py:411` (sink, SandboxManager.exec after approval) — After the human approves, decide() snapshots (service.py:412) and _run_tool passes the stored command unchanged (service.py:126) to exec, which runs it verbatim through bash -c; the quoting is intact there, so the file the table called nonexistent is actually deleted.

**conditions**

- authentication_level: A sandbox agent token (or prompt-injected code running as uid 1000 inside that sandbox) submits the rm; the default policy routes rm to require_approval, so the approval card is the only control between it and the deletion.
- user_interaction: A human opens the pending approval in the /ui/approvals card or agentbox approve and presses approve, relying on the system-computed impact table rather than re-reading the raw command.
- data_state: The rm operand names an existing /workspace path containing whitespace (space or tab) or a newline; the agent can produce that state itself, since creating a new file with write_file needs no approval.
- system_configuration: Stock default_policy.yaml, where exec commands containing rm route to require_approval (default_policy.yaml:12-16).

**execution.attacker_perspective** The sandbox agent wants to delete /workspace/final report.docx but wants the card not to say so, so it submits exec rm "final report.docx". The card describes the target as "삭제 시도 (현재 존재하지 않음)" - an apparently already-failed no-op - and with decoy names present it lists files that will not be touched, while the approved command deletes the real file.

**execution.instructions**

1. Create fixtures in the approved sandbox (tools/sbx.py v06, no network, read-only /target, writes only /scratch): a directory holding one file literally named final report.docx plus notes.txt.
2. Copy the sandbox.py:559 and sandbox.py:565 scripts verbatim, changing only cd /workspace to the fixture directory (the sandbox has no /workspace and uid 65534 cannot create one), and wrap them exactly as sandbox.py:560-562 / 567-569 do (decode, splitlines) to build the expand and walk callbacks.
3. Import agentbox.preview from /target (PYTHONPATH) and call preview_command('rm "final report.docx"', 200, expand, walk); compare the affected rows and notes with os.path.exists on the real file.
4. Repeat with decoy files final and report.docx present, and with fixtures named "a\nb" and "a\tb.txt" for the expand path and "dir with space/inner\nname.txt" for the walk path.
5. Re-run the run-3 v17 case rm notes.txt; mv important /tmp/important and check that its per-segment note still appears.
6. Show the sink: run sh -c 'rm "final report.docx"' in the fixture directory (the quoting sandbox.py:411 hands to bash) and confirm the file the table called nonexistent is gone.

**execution.observed_result** Case B: affected=[{path: "final report.docx", effect: "삭제 시도 (현재 존재하지 않음)"}], notes=[], real target exists: true. Case C (decoys present): affected=[{path: "final", effect: "삭제"}, {path: "report.docx", effect: "삭제"}] while the real target still exists and is never listed. Newline case: expand("*") -> ["a", "b", "ok.txt"] for files "a\nb" and ok.txt, and the old find framing returned ["dir with space", "dir with space/inner", "name.txt"]. Sink: sh -c 'rm "final report.docx"' exited 0 and the directory went from [final report.docx, notes.txt] to [notes.txt]. Case A (revalidation): "rm notes.txt; mv important /tmp/important" produced the rm row AND the per-segment note, so the run-3 omission defect is fixed. The proposed fix was also executed against the same fixtures: with IFS= and NUL framing expand returned ["final report.docx"] and a single "a\nb", and find -print0 | head -z kept "dir with space/inner\nname.txt" whole. Everything ran inside tools/sbx.py v06.

**remediation.strategy** Make both preview transports lossless. In _expand, disable IFS word splitting (IFS=) so the operand is tested as one word while pathname expansion still happens, and frame results with NUL instead of newline; in _walk, use find -print0 with head -z and split on NUL. Then one match is one path: the "does not currently exist" row is emitted only when the path really is absent, and no row names a path the command will not touch. Add a regression test that pushes names containing a space, a tab and a newline through both the non-recursive and the recursive branch and asserts the returned list equals the fixture paths.

`agentbox/sandbox.py`:

```python
def _expand(self, c, pattern: str) -> list[str]:
    """컨테이너 안에서 glob만 펼친다. 명령 치환은 일어나지 않는다."""
    script = ('cd /workspace; IFS=; for p in $1; do if [ -e "$p" ] || [ -L "$p" ]; then printf "%s\\0" "$p"; fi; done')
    res = c.exec_run(["sh", "-c", script, "_", pattern], user=AGENT_UID, demux=True)
    out = (res.output[0] or b"").decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]
```

`agentbox/sandbox.py`:

```python
def _walk(self, c, path: str, limit: int) -> list[str]:
    res = c.exec_run(["sh", "-c", 'cd /workspace; case "$1" in -*) set -- "./$1" "$2";; esac; find "$1" -print0 2>/dev/null | head -z -n "$2"',
                      "_", path, str(limit)],
                     user=AGENT_UID, demux=True)
    out = (res.output[0] or b"").decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]
```

</details>

## F5. [낮음] 인증 없는 `GET /static/novnc/*`가 표식 파일이 없는 동안 요청마다 `docker create`와 noVNC 전체 tar 추출을 한다(동시 실행 제어 없음)

- 지문: `agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight`
- 심각도: 가능성 중간 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/api.py:355`(진입점), `agentbox/api.py:358`(전파), `agentbox/sandbox_desktop.py:148`(전파), `agentbox/sandbox_desktop.py:152`(도달점)

**설명.** `GET /static/novnc/{path}`(api.py:355-358)에는 인증 의존성이 없고, 경로를 확인하기 전에 `extract_novnc`를 부른다. `extract_novnc`(sandbox_desktop.py:146-169)의 보호 장치는 `core/rfb.js` 존재 확인 하나다. 이 파일이 없는 동안에는 요청마다 다음을 한다.
- `containers.create`로 컨테이너를 만든다.
- `/usr/share/novnc` 아카이브를 메모리로 읽는다.
- 데이터 폴더에 풀고 컨테이너를 지운다.
락, 진행 중 표시, 실패 캐시가 없다. Docker 클라이언트를 대역으로 바꾼 실측에서 동시 요청 6개가 create 6회를, 12개가 12회를 일으켰다. 디렉터리 항목이 없는 아카이브에서는 동시 요청 5개가 `FileExistsError` 500으로 끝났다. 실제 `get_archive` 형태에서는 전부 200이었다.

**근본 원인.** 인증 없는 정적 파일 라우트가 Docker 데몬 작업과 압축 해제를 한다. 이를 표식 파일 하나의 확인-후-실행으로만 막고, 락·진행 중 표시·실패 캐시가 없다.

**지켜야 할 동작.** 정적 파일은 요청마다 데몬 작업을 일으키면 안 된다. 추출은 시작할 때나 인증된 첫 데스크톱 요청에서 락을 잡고 한 번만 해야 한다. 실패하면 일정 시간 다시 시도하지 않는 상태를 남겨야 한다.

**재현 관측.**

- 트리를 지우고 인증 없이 GET 1회: 200, create 1회, `rfb.js` 생성. 다음 요청은 create 0회.
- 트리를 지우고 동시 6회: create 6회. 동시 12회: create 12회. 둘 다 전부 200.
- 디렉터리 항목 없는 아카이브: 200 1개와 500 5개.
- 없는 파일을 3번 요청: create 3회, 응답은 모두 404.

**성립 조건.** 인증 수준, 시스템 설정, 타이밍. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 추출을 요청 경로 밖으로 옮긴다(시작할 때나 인증된 첫 데스크톱 라우트). 디렉터리별 락과 진행 중 이벤트를 두고, 성공한 뒤에만 표식을 쓴다. 실패하면 일정 시간 짧게 거절하는 실패 표식을 남긴다. 표식이 없으면 `/static/novnc/*`는 컨테이너를 만들지 않고 404·503을 준다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** api.py:355-356 registers GET /static/novnc/{path:path} with no Depends(), principal, cookie or ticket and calls box.sandboxes.extract_novnc(novnc_dir) at api.py:358 before it resolves or validates the requested path. extract_novnc (sandbox_desktop.py:146-169) has one guard: it returns True when dest/core/rfb.js exists (148). While that marker is absent, every request runs self.client.containers.create(desktop_image, ["true"], network_mode="none") (152), joins the whole /usr/share/novnc archive into memory with b"".join(stream) (156-157), extractall()s it into the control plane's data directory (163-166) and removes the container (160-161). There is no lock, no in-flight marker and no negative cache, so every concurrent caller passes the line-148 check and duplicates the daemon work: measured in the approved sandbox with the Docker client stubbed, six concurrent unauthenticated GETs made six containers.create calls, and twelve concurrent GETs made twelve. The claimed concurrent 500/FileExistsError outcome is fixture-dependent rather than universal: it reproduces (1 x 200, 5 x 500 FileExistsError on '<home>/novnc/core') only when the served tar has no directory members, because tarfile's own os.makedirs(upperdirs) in _extract_member is unguarded; with a directory-complete archive of the kind containers.get_archive('/usr/share/novnc') produces, all six and all twelve concurrent requests returned 200 while still performing six and twelve creates. Failures are still uncaught and unbounded in time: a truncated or corrupt archive raised ReadError outside the narrow ImageNotFound/NotFound/APIError handlers, producing 500 on every request, three creates for three requests and a marker that never appears, and the route also pays the create before it answers 404 (three unauth GETs for /static/novnc/does-not-exist.js each made one create). Once one extraction succeeds the marker makes later requests cheap, so the duplication is confined to the pre-marker window and to broken states.

**root_cause** An unauthenticated static-asset route performs Docker-daemon work and an archive extraction behind a check-then-act test on a single marker file, with no lock, no in-flight flag and no negative cache; exceptions outside the narrow docker-error handlers escape as a 500 without publishing the marker or any bounded negative state, so the expensive state persists and the work is repeatable by any anonymous client.

**intended_behavior** Static assets should not require per-request daemon work: the extraction should happen once (at startup or on the first authenticated desktop route) under a lock that lets one caller do it while the others wait or observe the result, and a failed extraction should leave a bounded negative state instead of being retried by every request. /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.

**trace**

- `agentbox/api.py:355` (entrypoint, GET /static/novnc/{path:path}) — The route decorator adds no Depends() and the handler at 356 takes only the path, so it is exempt from the human, desktop-link and agent principals used everywhere else and is reachable by any network client; deploy/Caddyfile:4-5 exposes it through a bare reverse_proxy with no auth, rate limit or body limit.
- `agentbox/api.py:358` (propagation, extract_novnc called on every request) — The handler calls box.sandboxes.extract_novnc(novnc_dir) before resolving or validating path (360-362), so the only thing that keeps a request cheap is the marker file the function itself is supposed to create.
- `agentbox/sandbox_desktop.py:148` (propagation, the sole guard is a marker-file existence check) — if (dest / "core" / "rfb.js").exists(): return True - a check-then-act test performed outside any lock, with no in-flight marker and no negative cache, so N concurrent callers all proceed to the sink.
- `agentbox/sandbox_desktop.py:152` (sink, containers.create + get_archive + extractall) — Each request that finds no marker creates a container from the desktop image (152), pulls the whole /usr/share/novnc tar into memory with b"".join(stream) (156-157), extracts it into settings.home (162-166) and removes the container (161).

**conditions**

- authentication_level: None - the route requires no principal, cookie or ticket.
- system_configuration: The desktop image is present (otherwise create raises ImageNotFound and the route is cheap) and home/novnc/core/rfb.js is absent: a fresh install before anyone opened a desktop page, or a state left behind by a failed or partial extraction. Nothing else in the tree calls extract_novnc, so the marker is created by this unauthenticated route on first use.
- timing_dependency: Two or more requests must be in flight together to duplicate the daemon work; a single request duplicates nothing, and the first success publishes the marker and ends the window for later requests.

**execution.attacker_perspective** An unauthenticated client issues GETs to /static/novnc/core/rfb.js (or any path under that prefix), early in a deployment's life and in parallel, so the first-time extraction happens under its timing instead of a real user opening the desktop page, and so one marker miss is multiplied by the number of simultaneous requests.

**execution.instructions**

1. In the approved sandbox, patch docker.from_env to return an in-process fake client whose containers.create counts calls and whose get_archive serves a fixed tar containing novnc/core/rfb.js (the sandbox has no daemon), then build the real app with fastapi 'build(Settings(home=<scratch>/home))'.
2. Delete home/novnc and issue one GET, then a second GET, recording status codes and the number of containers.create calls (marker published, steady state cheap).
3. Delete home/novnc again and issue six, then twelve, concurrent GETs with asyncio/threads using separate TestClient instances (raise_server_exceptions=False) and an app-level exception handler that records exception types, recording status codes and containers.create calls.
4. Repeat with an archive that omits directory members, and with a truncated archive, to separate the fixture-dependent FileExistsError outcome from the fixture-independent duplication and 500-on-error outcomes.

**execution.observed_result** With home/novnc deleted, one unauthenticated GET returned 200, made 1 containers.create call and wrote home/novnc/core/rfb.js; the next GET made 0 create calls and returned 200 (marker hit). After deleting the tree, six concurrent unauthenticated GETs made 6 create calls, and in a second run twelve concurrent GETs made 12 create calls; with a directory-complete archive all of those responses were 200 and no exception was raised. With an archive that has no directory members, the same six-request burst returned one 200 and five 500s with FileExistsError: [Errno 17] File exists: '<home>/novnc/core' while still making 6 creates. Three unauthenticated GETs for /static/novnc/does-not-exist.js, each with the tree deleted first, made 3 more create calls and returned 404 each time. With a truncated archive, three sequential unauthenticated GETs each made another containers.create call and returned 500 ReadError: unexpected end of data with the marker still absent, and four concurrent requests against a truncated archive made 4 creates and 4 x 500.

**remediation.strategy** Extract once, under a lock, outside the request path: do it at startup or on the first authenticated desktop route, guard it with a per-directory lock plus an in-flight event so concurrent callers wait for the winner, publish the marker only after a successful extraction, and treat any failure as a bounded negative state (a timestamped failure marker that short-circuits the route for a cooldown). /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.

`agentbox/sandbox.py`:

```python
        self.client = docker.from_env()
        self._lock = threading.Lock()
        self._novnc_lock = threading.Lock()   # single-flight for extract_novnc
```

`agentbox/sandbox_desktop.py`:

```python
    def extract_novnc(self, dest: Path) -> bool:
        marker = dest / "core" / "rfb.js"
        if marker.exists():
            return True
        with self._novnc_lock:            # one extraction per process
            if marker.exists():           # a waiter re-checks after the winner finished
                return True
            try:
                c = self.client.containers.create(self.settings.desktop_image, ["true"], network_mode="none")
            except (ImageNotFound, APIError):
                return False
            try:
                stream, _ = c.get_archive("/usr/share/novnc")
                out = b"".join(stream)
            except (NotFound, APIError):
                return False
            finally:
                try:
                    c.remove(force=True)
                except APIError:
                    pass
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                with tarfile.open(fileobj=io.BytesIO(out)) as tf:
                    members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
                    tf.extractall(dest.parent, members=members, filter="data")
            except (OSError, tarfile.TarError):
                shutil.rmtree(dest, ignore_errors=True)   # never serve a half tree
                return False
            return marker.exists()
```

`agentbox/api.py`:

```python
    @app.get("/static/novnc/{path:path}")
    def novnc(path: str):
        root = novnc_dir.resolve()
        # 정적 파일은 요청 경로에서 컨테이너를 만들지 않는다. 시작 시 한 번만 꺼낸다.
        if not (root / "core" / "rfb.js").is_file():
            raise HTTPException(404)
        f = (root / path).resolve()
        if not f.is_relative_to(root) or not f.is_file():
            raise HTTPException(404)
        return FileResponse(f)
```

</details>

## F6. [낮음] 복원과 삭제가 겹치면 삭제한 샌드박스 행이 되살아나고, 폐기한 에이전트 토큰이 다시 유효해진다

- 지문: `agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token`
- 심각도: 가능성 낮음 · 영향 중간 · 종합 **낮음**. 신뢰도: medium
- 경로: `agentbox/api.py:206`(진입점), `agentbox/service.py:465`(전파), `agentbox/sandbox.py:388`(전파), `agentbox/sandbox.py:393`(전파), `agentbox/sandbox.py:397`(전파), `agentbox/api.py:211`(전파), `agentbox/sandbox.py:326`(전파), `agentbox/sandbox.py:330`(전파), `agentbox/sandbox.py:398`(전파), `agentbox/sandbox.py:216`(전파), `agentbox/sandbox.py:221`(도달점)

**설명.** `DELETE /sandboxes/{sid}`와 `POST /sandboxes/{sid}/restore`는 같은 행을 락 없이 읽고 고쳐 쓴다. 복원이 새 컨테이너를 만든 뒤 마지막 상태를 쓰기 전에 삭제가 끝나면 다음 일이 생긴다.
- 삭제는 성공을 돌려주고 `sandbox_delete`를 감사에 남긴다.
- 복원의 마지막 쓰기가 `status='running'`과 새 `container_id`를 되돌려 놓는다.
- 토큰 폐기는 `status!='deleted'`로만 표현되므로, 삭제가 폐기한 `agt_` 토큰이 다시 그 샌드박스로 연결되고 도구 호출이 새 컨테이너에서 실행된다.
- 스냅샷 행도 남는다.
컨트롤 플레인은 삭제가 끝났다고 보고하지만 샌드박스, `/workspace`, 에이전트 권한은 살아 있다.

**근본 원인.** 수명 주기 작업에 샌드박스별 락이 없다. 각각 행을 한 번 읽고, 상태 조건 없는 `UPDATE`로 덮어쓴다(sandbox.py:234-237). `restore`는 `status=='deleted'`를 확인하지 않는다.

**지켜야 할 동작.** `deleted`는 최종 상태여야 한다. 삭제된 샌드박스는 쓸 수 없고 그 에이전트 토큰은 무효다. 뒤이은 수명 주기 호출이나 동시 호출이 행을 되살리거나 컨테이너를 다시 붙이면 안 된다.

**재현 관측.**

- 경쟁 실행: 삭제가 오류 없이 끝나 상태가 `deleted`가 되고 토큰이 무효로 나왔다. 그다음 멈춰 있던 복원이 정상 반환했다.
- 결과: 상태 `running`, 새 컨테이너가 살아 있었고 옛 토큰이 다시 유효했다. `list_dir` 호출이 200으로 실행됐다.
- 부모가 실제 Docker로 재현했다(`agents/parent-live/artifacts/lifecycle-race.json`, 6회 중 5회). 0.25초와 0.4초 오프셋에서 되살아났고, 0.7초에서는 삭제가 이겼다.

**성립 조건.** 권한, 타이밍, 데이터 상태, 시스템 설정. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 샌드박스별 수명 주기 락 하나로 pause·resume·snapshot·restore·delete를 직렬화한다. `restore`는 락 안에서 행을 다시 읽고 `deleted`면 거절한다. `_set`에 상태 조건을 넣는 방법도 함께 검토한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** DELETE /sandboxes/{sid} and POST /sandboxes/{sid}/restore each perform an unlocked read-modify-write on the same sandboxes row. If a DELETE completes between the restore's creation of the replacement container and the restore's final status write, the delete reports success and audits 'sandbox_delete', but the restore's last write puts status='running' and the new container_id back on the row. Neither operation rewrites token_hash, and revocation is expressed only as status!='deleted', so the agt_ token the delete revoked resolves to that sid again and its tool calls execute in the replacement container. The snapshots row also survives (delete removes only images), and the running replacement keeps the snapshot image in use, so the best-effort image removal raises and is swallowed. The control plane therefore reports a completed deletion while the sandbox, its /workspace and its agent authority are live again.

**root_cause** Lifecycle operations take no per-sandbox lock and re-read nothing. Service.restore_sandbox and Service.delete_sandbox (service.py:462-475) call SandboxManager.restore and SandboxManager.delete (sandbox.py:387-401, 320-332); each reads the row once with _rec, acts, and writes status/container_id unconditionally through _set, which is a bare UPDATE with no status predicate (sandbox.py:234-237). SandboxManager.restore never checks status=='deleted', so its final _set (sandbox.py:398) overwrites the delete's status write (sandbox.py:326) and reinstates the record. Revocation of the agent token is expressed only as status!='deleted' (sandbox.py:216, 221), so the overwritten status silently re-authorizes the original token hash.

**intended_behavior** _container (sandbox.py:225-232) and the token lookups (sandbox.py:211-223) treat status=='deleted' as final: a deleted sandbox is unusable and its agent token is invalid. DELETE is the revocation contract (service.py:471-475 logs sandbox_delete, ends the desktop, deletes the container, drops captures). No later or concurrent lifecycle call may reinstate the record, re-point it at a container, or make the revoked token valid again.

**trace**

- `agentbox/api.py:206` (entrypoint, POST /sandboxes/{sid}/restore) — sync human_only route hands the client-supplied snapshot_id to box.restore_sandbox and runs in the Starlette threadpool with no serialization against other lifecycle calls
- `agentbox/service.py:465` (propagation, AgentBox.restore_sandbox) — calls SandboxManager.restore outside any lock, after end_desktop has already run
- `agentbox/sandbox.py:388` (propagation, SandboxManager.restore) — reads the row with _rec, which returns deleted rows too, and never checks status
- `agentbox/sandbox.py:393` (propagation, SandboxManager.restore) — force-removes the row's old container (NotFound swallowed), so the row's stale container_id no longer exists
- `agentbox/sandbox.py:397` (propagation, SandboxManager.restore) — starts the replacement container from the snapshot image; from this point the new container exists while no lock protects the row
- `agentbox/api.py:211` (propagation, DELETE /sandboxes/{sid}) — second human request for the same sid runs as a separate threadpool worker, so delete_sandbox executes concurrently with an in-flight restore
- `agentbox/sandbox.py:326` (propagation, SandboxManager.delete) — marks the row deleted (unconditional UPDATE), after removing the old container_id the restore already removed
- `agentbox/sandbox.py:330` (propagation, SandboxManager.delete) — snapshot image removal fails because the restore's new running container uses the image; APIError is swallowed, so the image and its snapshots row survive
- `agentbox/sandbox.py:398` (propagation, SandboxManager.restore) — final _set overwrites the deleted status with status='running' and the replacement container_id
- `agentbox/sandbox.py:216` (propagation, SandboxManager.token_matches) — only rejects status=='deleted', so the original agent token hash is accepted again
- `agentbox/sandbox.py:221` (sink, SandboxManager.sandbox_for_token) — resolves the revoked token back to the sid, which api.principal turns into an agent principal (api.py:121-123)

**conditions**

- authorization_role: Both requests need the human token or a browser session with scope '*'; the agent never issues them, but it holds the agt_ token whose revocation DELETE implements and needs no new credential, so the failure is a revocation/TOCTOU defect rather than an attacker-triggered request.
- timing_dependency: The DELETE must complete its row read, status write and image-removal attempt inside the window that opens when the restore's replacement container has been created (sandbox.py:397) and closes at the restore's status write (sandbox.py:398), and the restore must be preempted in that window. This window is a few milliseconds of SQLite/thread scheduling, not the whole restore: in the measured alternative schedule where the DELETE lands during the long container-start portion, the delete removes the snapshot image first, the restore then fails with ImageNotFound, and the row stays deleted with the token invalid. So the overlap is reachable but narrow.
- data_state: The sandbox has at least one snapshot row; DELETE never removes snapshots rows (sandbox.py:327-332 only tries to remove images) and restore accepts any row of that sid.
- system_configuration: No special runtime or container capability is needed: the resurrection is decided entirely in the SQLite row and the token lookups. The daemon fact that matters (images.remove refusing while a running container holds the image) is what real Docker does; the harness models it, and even if the image were removed the running replacement and the surviving snapshots row would still leave the sandbox resurrected.

**execution.attacker_perspective** Holder of the agt_ token whose authority the human tried to revoke with DELETE. It needs no new credential and takes no action: after the overlapping restore the same token maps to the sid again and its tool calls return 200. The overlap itself requires two human-issued requests (restore and delete) whose timing the agent cannot control, so this is a failed revocation contract rather than a directly attacker-triggered race.

**execution.instructions**

1. Bounded local harness in the approved sbx sandbox (no network, no Docker daemon): real agentbox.config.Settings, agentbox.audit.AuditLog, agentbox.approvals.ApprovalStore, agentbox.policy.Policy, agentbox.desktop.DesktopControl, agentbox.service.AgentBox and agentbox.sandbox.SandboxManager with SQLite files under /scratch, driven through AgentBox methods (no HTTP server needed; the route bodies are one-line guard calls).
2. Docker is replaced by a fake client that models only the daemon facts this check needs: containers.run registers name and image and refuses a duplicate container name, images.remove refuses while a running container uses the image (the real docker conflict), and running an absent image raises ImageNotFound.
3. Create a cli-template sandbox with an empty source dir, take one snapshot (docker commit is faked into the image set), then start box.restore_sandbox(sid, snap) on a thread whose containers.run hook parks it after the replacement container exists but before its status write. The main thread runs box.delete_sandbox(sid) to completion and then releases the restore.
4. Read back: sandboxes.get(sid)['status'] and container_id, sandboxes.token_matches(sid, old_token), sandboxes.sandbox_for_token(old_token) (the value api.principal turns into Principal('agent', sid)), box.call_tool(sid, 'list_dir', {'path': '/workspace'}), snapshot rows/images, and audit.list(sandbox_id=sid).
5. Sequential control in the same process: create, snapshot, delete, then restore - it fails with ImageNotFound and leaves status 'deleted' with the token invalid.
6. Alternative schedule: park the restore before the replacement container is created, then run the delete to completion and release it.

**execution.observed_result** Race run (delete parked inside the post-create window): delete_sandbox returned without error after status had become 'deleted' and token_matches and sandbox_for_token reported the token invalid; the parked restore then returned normally. Read-back: status 'running', container_id c2 present and alive, sandboxes.token_matches(sid, old_token)=true, sandbox_for_token(old_token)=sid, snapshot rows still 1, the snapshot image still present (delete's image removal raised because c2 runs it), and box.call_tool(sid, 'list_dir', {'path': '/workspace'}) returned 200 {'status': 'executed', 'result': {'path': '/workspace', 'listing': '...'}}. Audit sequence: sandbox_created, snapshot_request, snapshot, restore_request, sandbox_delete, restored, tool_request, policy_decision, tool_result. Sequential control: ImageNotFound 'no such image: agentbox-snap:sb_9df2e832-snap_3e1280c2', final status 'deleted', token invalid. Alternative schedule (delete before the replacement container exists): delete removed the image, the restore raised ImageNotFound, final status 'deleted', token invalid - so this ordering does not resurrect and bounds the vulnerable window.

**remediation.strategy** Serialize all lifecycle transitions per sandbox and make deletion final at the point of the check. Take one per-sid lifecycle lock in AgentBox (reuse the _snap_locks map with a distinct key) around pause/resume/snapshot/restore/delete so delete and restore cannot interleave, and have SandboxManager.restore re-read the row under that lock and refuse status=='deleted' before it removes the old container or starts the replacement. The two methods below are the decisive pair for this race; the same lock should wrap pause_sandbox/resume_sandbox/snapshot_sandbox as well, since pause's unconditional _set(status='paused') has the same shape. Regression case: drive restore and delete concurrently with the harness and assert that the row is either deleted with the old token invalid and no replacement container, or still not deleted only when no delete was observed.

`agentbox/service.py`:

```python
    def _lifecycle_lock(self, sid: str) -> threading.Lock:
        with self._busy_lock:
            return self._snap_locks.setdefault("lifecycle:" + sid, threading.Lock())

    def restore_sandbox(self, sid: str, snap_id: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle_lock(sid):
            self.log_human("restore_request", sid, _with_session({"snapshot_id": snap_id}, session))
            self.end_desktop(sid, "sandbox_restored")
            rec = self.sandboxes.restore(sid, snap_id)
            self.bursts.reset_timers(sid)
            self.log_human("restored", sid, _with_session({"snapshot_id": snap_id, "container_id": rec["container_id"]}, session))
            return rec

    def delete_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> None:
        with self._lifecycle_lock(sid):
            self.log_human("sandbox_delete", sid, _with_session({}, session))
            self.end_desktop(sid, "sandbox_deleted")
            self.sandboxes.delete(sid)
            self.drop_captures(sid)
```

`agentbox/sandbox.py`:

```python
    def restore(self, sid: str, snap_id: str) -> dict[str, Any]:
        rec = self._rec(sid)
        if rec["status"] == "deleted":   # 삭제는 되돌릴 수 없다: 지운 샌드박스의 행·토큰은 되살리지 않는다
            raise SandboxError(f"삭제된 샌드박스는 되돌릴 수 없음: {sid}")
        snaps = {s["id"]: s for s in self.list_snapshots(sid)}
        if snap_id not in snaps:
            raise SandboxError(f"이 샌드박스의 스냅샷이 아님: {snap_id}")
        try:
            self.client.containers.get(rec["container_id"]).remove(force=True)
        except NotFound:
            pass
        tpl = self.template_of(sid)
        c = self._run_container(tpl, snaps[snap_id]["image"], rec["source_dir"], f"agentbox-{sid}")
        self._set(sid, container_id=c.id, status="running")
        if tpl.desktop:
            self._wait_display(c)
        return self.get(sid)
```

</details>

## F7. [낮음] 스냅샷 상한은 컨테이너를 한 번 확인해서 정하는데, docker commit은 상한이 보지 않는 두 번째 확인으로 일어난다

- 지문: `agentbox/service.py:snapshot-quota:toctou-between-quota-gate-and-pre-exec-snapshot`
- 심각도: 가능성 높음 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/api.py:216`(진입점), `agentbox/service.py:283`(전파), `agentbox/service.py:298`(전파), `agentbox/service.py:248`(전파), `agentbox/sandbox.py:461`(전파), `agentbox/service.py:343`(전파), `agentbox/sandbox.py:355`(도달점)

**설명.** 샌드박스가 `snapshot_quota`(기본 50)에 도달하면, 스냅샷이 필요한 허용 호출은 승인 요청으로 바뀌어야 한다. `_call_tool`은 상한 확인(service.py:298)에서 `_needs_snapshot`을 부른다. `write_file`이면 이것은 컨테이너 안의 `test -e` 확인이다(service.py:236 → sandbox.py:458-461). 이 확인이 '스냅샷 불필요'를 돌려주면 호출은 허용으로 남는다. 그런데 실행 직전(service.py:343)에 `_needs_snapshot`을 한 번 더 부르고, 그 결과로 상한을 다시 보지 않은 채 커밋한다(345). 두 확인 사이에 대상 경로가 생기면, 승인으로 가야 할 상한 초과 호출이 승인 없이 커밋된다. 에이전트는 허용 목록의 `touch`를 `write_file`과 동시에 보내 경로를 만들 수 있다. exec는 `SNAPSHOT_TOOLS`가 아니라 `_snap_locks`로 직렬화되지 않는다. 대기 승인 상한(20)은 승인 분기에만 걸려 이를 막지 못한다. 상한은 커밋이 쓰기 층 전체를 복사하므로 사람 없이 호스트 디스크를 채우지 못하게 하려고 있다(config.py:44-46).

**근본 원인.** `_call_tool`이 에이전트가 바꿀 수 있는 컨테이너 상태를 두 번 읽는다. 상한 게이트와 커밋을 하나의 '스냅샷 필요' 판단에 묶지 않고, 커밋 자리에서 상한을 다시 확인하지도 않는다.

**지켜야 할 동작.** 스냅샷 수가 상한에 이르면 허용 경로의 어떤 도구 호출도 사람 승인 없이 docker commit을 일으키면 안 된다. 상한 판단과 커밋을 같은 판단에 묶거나, 커밋 경로가 상한을 직접 다시 확인해야 한다.

**재현 관측.**

부모가 실제 Docker 엔진에서 감사 소스를 그대로 돌려 재현했다(`agents/parent-live/artifacts/snapquota-race.json`). 상한은 2이고 수동 스냅샷 2개를 먼저 만들었다.
- 대조군: 이미 있는 파일 덮어쓰기는 202 승인 대기(규칙 `snapshot-quota`)가 됐고 커밋은 없었다.
- 경쟁: `touch /workspace/pN`과 `write_file /workspace/pN`을 동시에 보냈다. 21번 중 18번 `write_file`이 200으로 실행되며 승인 없이 커밋됐고, 스냅샷 수가 2에서 20이 됐다.
- write가 20ms 먼저 시작한 경우부터 exec가 10ms 먼저 시작한 경우까지는 3/3이 뚫렸다. exec가 20ms 먼저면 첫 확인이 파일을 봐서 0/3이었다.
- 3단계 샌드박스 하네스(지연을 모델링)도 같은 모양이었다.
- r14가 제안 수정을 적용한 하네스에서는 상한 초과 커밋이 0이었다.

**성립 조건.** 인증 수준, 타이밍, 시스템 설정, 데이터 상태. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 실행 직전 `_needs_snapshot`이 True이고 스냅샷 수가 상한 이상이면 커밋하지 않는다. 그 호출은 스냅샷 상한 승인 요청으로 돌리거나 409로 거절해 다시 부르게 한다. 이 확인을 `write_file`·`delete_file`을 이미 직렬화하는 샌드박스별 락 안에서 하면, 두 쓰기가 함께 통과하지 못한다. 두 확인 사이에 대상을 바꾸는 회귀 테스트를 추가한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** An agent that holds only its own sandbox's agent token can get docker commits without approval after its sandbox has reached snapshot_quota (default 50). For an ALLOW decision, _call_tool consults _over_snapshot_quota (service.py:298). That function returns False whenever _needs_snapshot is False. For write_file, _needs_snapshot runs sandboxes.exists(), an untimed `test -e` exec inside the agent's own container (service.py:236 -> sandbox.py:458-461). The ALLOW branch then calls _needs_snapshot a second time (service.py:343) and commits on that result without checking the quota again (service.py:345 -> _snapshot -> sandbox.py:355). If the target path appears between the two probes, an over-quota call that should have become REQUIRE_APPROVAL/snapshot-quota becomes an unapproved commit. The agent can make the path appear in two ways. (a) It sends an allowlisted exec `touch <path>` (default_policy.yaml:22-29; touch is on line 27) at the same time as the write. exec is not in SNAPSHOT_TOOLS (service.py:35), so call_tool does not serialize it with the write_file under _snap_locks (service.py:278-285); tool_concurrency allows 4 concurrent calls. (b) Any process running in the container toggles the path. Within one sandbox, _snap_locks only serializes write_file, delete_file and GUI_INPUT calls against each other. The pending-approval cap (PENDING_APPROVALS_MAX=20) does not stop the bypass: it only blocks the REQUIRE_APPROVAL branch. Each commit is a full docker commit of the container (sandbox.py:355-356). config.py:44-46 records why the quota exists: commit copies the whole writable layer, and the quota keeps the agent from filling host disk without a human. Snapshot images are freed only when the sandbox is deleted (sandbox.py:327-332). The marginal harm depends on deployment. With AGENTBOX_DISK set (storage_opt, sandbox.py:263-264), the writable layer is bounded and the quota is the only bound on how many copies of that layer are kept, so the bypass multiplies it without limit. With the default empty AGENTBOX_DISK (config.py:41-42), the agent can already grow the writable layer directly through repeated unapproved write_file calls (1 MiB each, config.py:55), so the bypass mainly adds amplification. Local reproduction used the real AgentBox._call_tool/call_tool, Policy.load(default_policy.yaml), AuditLog and ApprovalStore with a fake SandboxManager. Its exists() stats a real file with a modelled 20 ms probe latency, and exec touch has a modelled 20 ms latency. No Docker was used. Results with the sandbox already at quota=2: a control call on a stably existing path returned 202 pending snapshot-quota with 0 commits. Concurrent agent exec `touch /workspace/pN` started 5 ms before, together with, or 5 ms after write_file gave 20/20 write_file calls returning 200 executed with a snapshot commit each, 0 approvals and policy_decision allow (an offset of -10 ms gave 18/20; -15 ms gave 0/20). A real background thread toggling the file every 2-20 ms produced 9 over-quota commits in 40 calls (7 in an earlier run), alongside 20 pending approvals. Parent-live on the real Docker engine (agents/parent-live/artifacts/snapquota-race.json, script agents/parent-live/parent_live_snapquota.py; audited tree 9805d91 in-process, buildpack-deps:noble-curl CLI sandbox, AGENTBOX_SNAPSHOT_QUOTA=2, two manual snapshots already taken): the control overwrite of a stably existing file returned 202 pending with rule snapshot-quota and no commit, while racing an allowlisted exec `touch /workspace/pN` against write_file /workspace/pN gave 18 of 21 unapproved commits (snapshot count 2 -> 20, every winning write 200 executed with 0 new approvals). The race won 3/3 at each of six start offsets from write-first by 20 ms to exec-first by 10 ms, and lost 3/3 only when exec started 20 ms before write_file (then the first probe already sees the file and the call goes to approval).

**root_cause** _call_tool reads the same mutable, agent-controlled container state twice: once in _over_snapshot_quota through _needs_snapshot/sandboxes.exists (service.py:298 -> 248 -> 236), then again in the pre-execution _needs_snapshot (service.py:343). It does not compute one 'snapshot needed' decision and bind both the quota gate and the commit to it. The quota therefore guards only the first probe, and the commit at service.py:345 has no quota check of its own. The serialization in _snap_locks covers only SNAPSHOT_TOOLS, so agent tools outside that set (exec) and processes inside the container can change the probed state between the two reads.

**intended_behavior** Once a sandbox's snapshot_count reaches snapshot_quota, no ALLOW-path tool call may trigger another docker commit without a human approval (config.py:44-46 states the quota exists so an agent cannot fill host disk through commits without a human). The quota decision and the commit must be bound to the same 'snapshot needed' evaluation, or the commit path must re-check the quota itself.

**trace**

- `agentbox/api.py:216` (entrypoint, call_tool route) — POST /sandboxes/{sid}/tools/write_file with the agent token of that sandbox (the only check is p.sandbox_id == sid at api.py:217-218). The call is dispatched to tool_pool and runs box.call_tool (api.py:219-220).
- `agentbox/service.py:283` (propagation, AgentBox.call_tool) — Only SNAPSHOT_TOOLS (write_file/delete_file/GUI_INPUT, service.py:35) take the per-sandbox snap lock. A concurrent exec from the same agent runs unlocked at line 285.
- `agentbox/service.py:298` (propagation, AgentBox._call_tool) — The quota gate is evaluated only for ALLOW decisions (write_file is allowed by default: default_policy.yaml:10). Its boolean only rewrites the decision; nothing is kept for the execution step.
- `agentbox/service.py:248` (propagation, AgentBox._over_snapshot_quota) — Once snapshot_count >= quota, the result is _needs_snapshot(); if the first probe says 'no snapshot', the call stays ALLOW.
- `agentbox/sandbox.py:461` (propagation, SandboxManager.exists) — First probe: untimed docker exec `test -e <path>` as the agent uid inside the agent-controlled container (called from service.py:236).
- `agentbox/service.py:343` (propagation, AgentBox._call_tool) — Second _needs_snapshot evaluation on the ALLOW path. The path now exists, so it returns True; the quota is not re-checked.
- `agentbox/sandbox.py:355` (sink, SandboxManager.snapshot) — docker commit of the whole container (pause=True), reached via service.py:345 -> _snapshot (service.py:253). The image is retained until the sandbox is deleted, and a snapshot row is inserted that pushes snapshot_count further past the quota.

**conditions**

- authentication_level: Only the sandbox's own agent token is needed; both requests (exec touch, write_file) are agent tool calls allowed by the default policy without approval.
- timing_dependency: exec touch must land between the two exists() probes of the same write_file call. On the real engine this held whenever write_file started first or exec led by up to 10 ms (18/18); with exec leading by 20 ms the first probe already saw the file (0/3). tool_concurrency=4 permits the two concurrent calls.
- system_configuration: The quota is the only bound on the number of retained commits. With AGENTBOX_DISK set (storage_opt), each commit can copy up to that writable-layer size and the bypass removes the human gate on how many copies are kept; with the default empty AGENTBOX_DISK the agent can already grow the writable layer directly through unapproved write_file calls, so the bypass is mostly amplification.
- data_state: The sandbox must already be at snapshot_count >= snapshot_quota; below the quota commits are allowed anyway.

**execution.attacker_perspective** An agent holding only its own sandbox's agt_ token, already at the snapshot quota, wants more docker commits without a human. It sends an allowlisted exec `touch /workspace/pN` and a write_file to the same new path at nearly the same time; when the touch lands between the quota probe and the pre-execution probe, the write is allowed and commits a snapshot past the quota.

**execution.instructions**

1. Start the control plane with AGENTBOX_SNAPSHOT_QUOTA=2 and create a CLI sandbox; take two snapshots so snapshot_count == 2.
2. Control: overwrite an existing file with write_file and confirm 202 pending with rule snapshot-quota and no new snapshot.
3. For N=1..21 send the two payloads concurrently with a new path pN, varying the start offset by a few milliseconds.
4. Read snapshot_count (GET /sandboxes/{sid}/snapshots) and the approvals list after each pair; a bypass is write_file 200 executed, snapshot_count +1, and no approval for that request.

**execution.observed_result** Real Docker engine, in-process control plane from the audited tree (agents/parent-live/artifacts/snapquota-race.json): control 202 pending snapshot-quota, snapshots 2 -> 2. Race: 18 of 21 write_file calls returned 200 executed with a new snapshot and 0 new approvals, taking snapshot_count from 2 to 20 at quota 2; 3/3 wins at each offset from write-first 20 ms through exec-first 10 ms, 0/3 at exec-first 20 ms (those went to 202 pending). Phase 3 sandbox harness with modelled 20 ms probes (agents/v11/artifacts/race_probe.out) gave the same shape. The sandbox and every snapshot image were removed afterwards.

**remediation.strategy** Bind the quota gate and the commit to one evaluation and re-check the quota at the commit. In _call_tool, when the pre-execution _needs_snapshot is True and snapshot_count >= snapshot_quota, do not commit: turn the call into the snapshot-quota approval request (or refuse with 409 and let the agent retry) instead of executing. Doing the check inside the per-sandbox snap lock that already serializes write_file/delete_file keeps two writes from both passing it. Add a regression test that toggles the target between the two probes and asserts no commit happens while snapshot_count >= quota.

`agentbox/service.py`:

```python
        assert decision.action == ALLOW
        if self._needs_snapshot(sid, tool, args):
            quota = self.sandboxes.settings.snapshot_quota
            if quota > 0 and self.sandboxes.snapshot_count(sid) >= quota:
                # 상한 확인 뒤 대상이 생겼다 (보안 검수 run-4 v11). 커밋하지 않고 승인으로 돌린다
                raise ServiceError(409, "스냅샷 상한에 도달함. 다시 호출하면 승인 요청으로 처리됨")
            try:
                self._snapshot(sid, tool, f"before {tool} (request {req_id})", {"request": req_id})
            ...
```

</details>

## F8. [낮음] 인증 없는 로그인 실패마다 지울 수 없는 해시 체인 감사 행이 하나씩 쌓인다(속도 제한·집계·보존 없음)

- 지문: `agentbox/web.py:unauthenticated-login-failure-audit-growth`
- 심각도: 가능성 높음 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/web.py:131`(진입점), `agentbox/web.py:136`(전파), `agentbox/service.py:590`(전파), `agentbox/audit.py:180`(도달점)

**설명.** `POST /login`(web.py:130-140)은 인증 없이 받는다. 토큰이 틀리면 `ui_login_failed`를 기록하고(136), `audit.append`가 프로세스 전체 감사 락을 잡고 체인에 한 행을 넣는다. 속도 제한, 중복 제거, 집계, 상한, 정리가 없다. 삭제 트리거와 `verify()`의 id 연속성 검사 때문에 나중에 지울 수도 없다. 전제는 `same_origin`뿐인데, Origin 헤더가 없으면 통과한다.

**근본 원인.** 인증 없는 클라이언트가 속도를 정하는 영구 기록이다. 실패 로그인 경로가 도구 실행을 막는 것과 같은 직렬화된 해시 체인 기록을 쓴다. 속도 제한과 집계가 없고, 만든 행을 보존·압축할 방법도 없다.

**지켜야 할 동작.** 익명 인증 실패는 감사 체인에 닿기 전에 속도를 제한하고 묶어야 한다(예: 출처·구간마다 'T 이후 N회 실패' 한 행). 한 클라이언트가 감사 기록을 마음대로 늘리거나 감사 락을 독차지하면 안 된다.

**재현 관측.**

- 틀린 토큰 POST 1회에 정확히 1행이 늘었다.
- 250회에 250행이 늘었고, 요청당 약 11.5ms였다. 429나 상한은 없었다.
- 동시 클라이언트 6개로 초당 약 270행이 쌓였다.
- 그동안 평범한 에이전트 `tool_request` 기록이 4.6~5.5ms에서 36~40ms로 느려졌다.
- 비 ASCII 토큰은 500(TypeError)을 내고 행을 남기지 않았다. 같은 클라이언트가 시도를 기록에서 숨길 수도 있다.

**성립 조건.** 인증 수준, 시스템 설정, 데이터 상태, 타이밍. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 감사 기록 전에 클라이언트 주소별 토큰 버킷과 전체 상한을 두고, 구간마다 '실패 N회' 요약 한 행만 남긴다. 실패가 있었다는 사실은 버리지 않는다. 감사 저장소에는 체인 검증을 유지하는 보존 방식(서명한 체크포인트와 보관 구간)을 둔다. 자격 증명은 바이트로 비교하거나 비 ASCII를 명시적으로 거절해, 기록되는 400·401이 되게 한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** web.py:130-140 serves POST /login with no principal and no cookie requirement. On a token mismatch it calls box.log_human("ui_login_failed", None, {}) at 136; service.py:590-594 forwards that to audit.append, which takes the single process-wide audit lock, runs BEGIN IMMEDIATE, reads the previous chain hash, inserts a row and commits (audit.py:162-185). Nothing rate-limits, deduplicates, aggregates, caps or prunes these rows: api.py:113 registers _NoFraming as the only middleware, deploy/Caddyfile:4-6 reverse-proxies /login with no rate or body limit, and audit.py contains no DELETE, VACUUM or retention code. Removal is not merely unimplemented but blocked: the audit_no_delete trigger (audit.py:37-38) rejects DELETE and verify() rejects any id gap (audit.py:233-234), so pruning rows later breaks the integrity check the operator relies on. The only precondition is same_origin (web.py:132), which returns True when the Origin header is absent (api.py:131-133), so a plain HTTP client reaches the write. Locally reproduced at the ASGI layer with the real AuditLog/AgentBox/handler: one wrong-token POST added exactly 1 ui_login_failed row, 250 such POSTs added 250 durable rows at ~11.5 ms each, and 6 concurrent clients sustained ~270 rows/s while raising the latency of an ordinary agent tool_request append from ~4.6-5.5 ms to ~36-40 ms. The same handler has the inverse defect: a non-ASCII token makes secrets.compare_digest raise TypeError at web.py:134, so the request returns a bare 500 with 0 rows recorded and the client also chooses which attempts enter the chain.

**root_cause** An unauthenticated, attacker-paced durable write into the append-only security record: the failed-login path uses the same serialized hash-chained append that gates tool executions, with no per-source or global rate limit, no aggregation, and no retention or compaction for the rows it creates - and the append-only triggers plus verify()'s contiguity check leave no legitimate way to remove them afterwards.

**intended_behavior** Anonymous authentication failures should be rate-limited and aggregated before they reach the audit chain (for example one "N failures since T" summary per source per interval), so one unauthenticated client cannot unilaterally grow the operator's security record or monopolize the audit lock every other append and read needs; the audit store should have a documented retention/compaction scheme that keeps chain verifiability (signed checkpoints plus archived segments). A malformed credential should be compared as bytes (or rejected on an ASCII check) so it becomes a recorded 401/400 instead of an unrecorded 500.

**trace**

- `agentbox/web.py:131` (entrypoint, POST /login form handler) — def login(request: Request, token: str = Form(...)) has no principal, session or cookie requirement; the only precondition is the same_origin call at 132, and same_origin (api.py:131-133) returns True when the Origin header is absent.
- `agentbox/web.py:136` (propagation, token mismatch branch) — A wrong token falls through the compare_digest at 134 to box.log_human("ui_login_failed", None, {}) and then renders the error page at 139; a non-ASCII token raises TypeError at 134 before this line and returns 500 with nothing recorded.
- `agentbox/service.py:590` (propagation, log_human -> audit.append) — log_human forwards the event to self.audit.append(actor="human", event=event, sandbox_id=sid, payload=payload) at 592; an AuditWriteError would become a 503, but on success the row is durable in SQLite.
- `agentbox/audit.py:180` (sink, INSERT INTO audit under the process-wide lock) — append() takes self._lock at 162, BEGIN IMMEDIATE at 163, reads the last hash at 165, inserts the row at 179-184 and commits at 185; every other audit append (including tool_request/tool_result) and every human read or verify() waits on the same lock.

**conditions**

- authentication_level: None - a wrong form token and no cookie; no Origin header required.
- system_configuration: The control plane is reachable through the shipped Caddy proxy, and AGENTBOX_HOME/agentbox.db persists across restarts with no pruning path.
- data_state: The audit table is append-only at the database level (audit_no_update/audit_no_delete triggers) and verify() requires contiguous ids, so rows written by an anonymous client are permanent.
- timing_dependency: The serialized append bounds the rate (~86 rows/s from one client, ~270 rows/s with 6 concurrent clients) but never the total number of rows.

**execution.attacker_perspective** An unauthenticated client posts the login form with a wrong token as fast as the server answers, adding one durable audit row and one acquisition of the global audit lock per request, for as long as it likes.

**execution.instructions**

1. In the approved sandbox, set AGENTBOX_HOME to a scratch directory and instantiate the real AuditLog(settings.db_path), Policy.load, ApprovalStore, DesktopControl and AgentBox from the audited tree; register the real web.register handler on a FastAPI app with the same_origin predicate copied verbatim from api.py:131-133. The only stand-in is box.sandboxes (web.register reads box.sandboxes.runtime at registration time), because api.build() calls docker.from_env() at sandbox.py:162 and the sandbox has no Docker socket.
2. Drive POST /login through fastapi.testclient.TestClient with urlencoded bodies, no cookie and no Origin header, and count rows with event='ui_login_failed' in AGENTBOX_HOME/agentbox.db before and after each request.
3. Repeat with a non-ASCII token (token=%C3%BCn%C3%AFcode) and compare status code and row count; then hammer the handler from 6 threads while timing ordinary audit.append calls of the shape the tool path uses and audit.list() reads.

**execution.observed_result** Independent reproduction matched and extended the candidate: 1 wrong-token POST added exactly 1 ui_login_failed row; 250 further wrong-token POSTs added 250 rows at ~11.5 ms per request (~86/s) with no rejection, cap or 429 at any point; 6 concurrent clients reached ~270 rows/s. Latency of a normal agent tool_request audit.append rose from a 4.6-5.5 ms baseline to 36-40 ms while the login flood ran, because both take audit.py's single lock. A non-ASCII token returned 500 (TypeError: comparing strings with non-ASCII characters is not supported) and added 0 rows, so the same client can also keep its attempts out of the chain.

**remediation.strategy** Rate-limit and aggregate failed logins before the audit append: a per-client-address token bucket plus a global cap, recording a compacted 'N failures since T' summary per window instead of one row per attempt (never dropping the fact that failures happened). Give the audit store a retention scheme that preserves chain verifiability (signed checkpoints plus archived segments) so operator disk growth is bounded and auditable. Compare credentials as bytes, or reject non-ASCII input explicitly, so a malformed credential is a recorded 400/401 rather than an unrecorded 500, and keep the 'audit before action' rule intact for tool paths.

`agentbox/web.py`:

```python
    @app.post("/login", include_in_schema=False)
    def login(request: Request, token: str = Form(...)):
        if not same_origin(request.headers):
            raise HTTPException(403, "다른 출처의 요청")
        # 바이트로 비교한다: 비ASCII 문자열은 compare_digest가 TypeError를 내서 500이 되고,
        # 그 실패는 감사 로그에도 안 남아 공격자가 기록 여부를 고를 수 있게 된다.
        given = token.strip().encode("utf-8", "replace")
        if not secrets.compare_digest(given, human_token.encode()):
            # 주소별 초당 몇 건만 즉시 남기고, 나머지는 세었다가 다음 창에 요약 1건으로 남긴다
            if _login_failures.record(request.client.host if request.client else "unknown"):
                try:
                    box.log_human("ui_login_failed", None, {"aggregated": _login_failures.dropped()})
                except ServiceError:
                    pass
            return render(request, "login.html", error="사람 토큰이 아님 (에이전트 토큰으로는 들어갈 수 없습니다)")
        return start_session(request, "/ui", "token")
```

</details>
