# run-5 확정 상세

`findings.json`의 확정 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같다. 항목마다 아래에 영어 레코드 원문을 접어 두었고, 원문이 기준이다. 줄 번호는 감사 기준 `346df29`을 따른다. 확정 건은 소유자 지시로 같은 PR에서 고쳤다(각 항목의 수정 방향 참조).

## F1. [중간] 에이전트 exec 한 번이 요청의 약 45배 크기인 승인 대기 행을 써서, PR #20의 디스크 보호선을 한 번에 넘는다

- 지문: `agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention`
- 심각도: 가능성 중간 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/api.py:274`(진입점), `agentbox/service.py:282`(전파), `agentbox/service.py:311`(전파), `agentbox/service.py:332`(전파), `agentbox/preview.py:125`(전파), `agentbox/approvals.py:56`(도달점)

**설명.** PR #20은 `call_tool` 입구에서 남은 공간을 보는 보호선(`disk_low`)과 끝난 승인 행 줄이기를 넣었다. 그러나 승인 대기 행은 원문 그대로, 크기 제한 없이 쓰였다. 미리보기는 알아보지 못한 셸 조각마다 약 90바이트짜리 한국어 메모를 붙인다. 그래서 2바이트 조각 `x;`를 이어 붙인 명령은 요청의 약 45배 크기 미리보기를 만든다(기본 정책에서 승인 요청으로 간다). 이 행은 WAL 모드 SQLite라 DB와 `-wal`에 두 번 쓰인다. 보호선은 호출 입구에서 한 번만 본다. 13만 바이트 요청 하나가 DB를 6.0MB, WAL을 6.1MB 키웠고, 그 뒤 `disk_low()`가 참이 됐다. 8MiB 본문이면 한 번에 수백 MB가 되어 기본 여유 256MiB를 혼자 넘는다(외삽). 끝난 뒤 줄여도 파일은 줄지 않는다. 디스크가 차면 사람의 결정·삭제가 503으로 막히고, 승인 화면은 행의 메모를 전부 그린다.

**근본 원인.** 보호선이 호출 입구의 한 번 확인뿐이다. 승인 요청 분기의 미리보기(`preview.py:125`)는 메모 수에 상한이 없고, `approvals.create`는 인자와 미리보기를 그대로 저장한다. `bound_payload`는 감사 로그 사본과 끝난 행에만 적용됐다.

**지켜야 할 동작.** 에이전트 요청 하나가 작은 고정 상한 이상의 승인 데이터를 남기지 않는다. 대기 행도 감사 로그와 같은 묶인 모양이어서, 받아들인 호출 하나가 보호선의 여유를 넘지 못한다.

**재현 관측.**

샌드박스에서 실제 정책·미리보기·승인 저장소·감사 코드로 재현했다(가짜 SandboxManager).
- `x;`×65,536(본문 131,097바이트): 202, `disk_low` 거짓→참, DB 4,096→6,004,736바이트(45.8배), WAL 6,089,392바이트.
- 대기 행 인자 131,087바이트, 미리보기 5,832,767바이트(메모 65,536개). 감사 로그 사본은 83,141바이트로 묶였다.
- 만료로 행을 줄여도 DB 파일은 6.0MB→12.1MB로 오히려 커졌다. 승인 화면 조각은 이 행 하나에 7.47MB였다(헌터 측정).

**성립 조건.** 인증 수준, 시스템 설정, 데이터 상태. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 미리보기 메모 수 상한, 대기 행 미리보기에도 `bound_payload`, 행을 쓰기 직전 디스크 보호선 재확인, 에이전트 문자열 인자의 길이 상한(정책 판단 전 413).

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** PR #20 added AgentBox.disk_low(), a free-space pre-check at the top of call_tool, and compaction of finished approval rows. Pending approval rows are still written raw and without a size bound, and the preview is amplified from the agent's command. preview_command emits one fixed Korean note (about 90 bytes) for every shell segment it cannot classify, so a command made of 2-byte 'x;' segments (default policy rule exec-needs-approval) produces a preview about 45x the request. approvals.create stores that preview plus the raw args in the shared SQLite file, which is in WAL mode, so the data is written to both agentbox.db and the -wal file. The guard is evaluated once before the call. Reproduced independently in the sandbox: one 131097-byte agent request, made with 1 MiB of headroom above min_free_bytes, returned 202, grew agentbox.db from 4096 to 6004736 bytes (45.8x) and the -wal file to 6089392 bytes, and disk_low() was True afterwards. The pending row held args of 131087 bytes and a preview of 5832767 bytes (65536 notes), while the audit approval_requested row was bounded to 83141 bytes. Cost scales linearly: policy.decide took about 80 microseconds per segment (0.31 s at 4096 segments, 5.27 s at 65536) and preview_command about 4 microseconds per segment, with a stable preview-to-command size ratio. A body at the 8 MiB AGENTBOX_MAX_BODY cap would therefore take roughly 5-6 minutes of CPU in a tool_pool thread and write on the order of 366 MiB of row data plus a similar amount of WAL, which exceeds the 256 MiB default margin on its own. That 8 MiB figure is extrapolated, not run. Each sandbox can run 4 such calls concurrently (tool_concurrency), and because the slow decide step runs after the single pre-check, concurrent calls all pass it. Up to 20 pending rows are allowed per sandbox. Expiry compaction shrinks the row (16533/83045 bytes) but not the file: the database grew from 6.0 to 12.1 MB with 2890 free pages and nothing runs VACUUM. When the volume fills, human audit-logged writes fail closed (log_human 503, decide claim 503, expire_stale stops), and the human approval fragment renders every note of the pending row (7.47 MB of HTML for this one row). This is the part of the run-4 N2 root cause (agent-grown approval rows without an effective bound) that PR #20 did not cover. Note: the finding is a per-call overshoot of the guard, not unbounded sustained growth. Once free space drops below the margin, further agent calls are refused with 507.

**root_cause** The disk guard is only a threshold check at call entry (service.py:282). The REQUIRE_APPROVAL branch then calls _preview (service.py:332), and preview_command appends one note per unrecognised segment with no count bound (preview.py:125). The 200-item cap at preview.py:127-128 applies only to 'affected'. approvals.create (approvals.py:56-57) stores json.dumps(args) and json.dumps(preview) unbounded. bound_payload is applied only to the audit copy (AuditLog.append) and to finished rows (_finish, service.py:406-411), never when the pending row is created. The agent request body is capped only by the global 8 MiB AGENTBOX_MAX_BODY, and there is no per-argument size limit before policy and preview.

**intended_behavior** No single agent request can make the control plane persist more than a small, fixed bound of approval data. Pending rows hold the same bounded shape as the audit log (capped args and a capped preview with a bounded notes list), so the 256 MiB guard margin cannot be crossed by one admitted call.

**trace**

- `agentbox/api.py:274` (entrypoint, call_tool route (POST /sandboxes/{sid}/tools/{tool})) — An agent token posts {"args": {"command": "x;x;..."}}. The ToolCall args dict has no per-value cap, and _BodyLimit allows up to AGENTBOX_MAX_BODY (8 MiB).
- `agentbox/service.py:282` (propagation, AgentBox.call_tool) — disk_low() is evaluated once, at entry. Free space is still above min_free_bytes, so the call is admitted.
- `agentbox/service.py:311` (propagation, AgentBox._call_tool) — policy.decide returns exec-needs-approval, because 'x' is not in the read-only allowlist (default_policy.yaml, rule exec-needs-approval). Reproduced: decision=exec-needs-approval.
- `agentbox/service.py:332` (propagation, AgentBox._call_tool) — _preview calls sandboxes.preview, which calls preview_command on the raw command. On exception, the fallback preview copies the raw command (service.py:334).
- `agentbox/preview.py:125` (propagation, preview_command) — One note is appended per unclassified segment with no count bound: 65536 notes for 65536 'x;' segments.
- `agentbox/approvals.py:56` (sink, ApprovalStore.create) — json.dumps(args) and json.dumps(preview) are inserted raw into the shared SQLite file, which is in WAL mode, so the bytes are written to both the database and the WAL.

**conditions**

- authentication_level: Requires an agent token for a running sandbox, the lowest-trust principal. The threat model assumes it may be prompt-injected.
- system_configuration: Default policy (or any policy that sends an exec to require_approval) and AGENTBOX_MIN_FREE greater than 0. The body must fit AGENTBOX_MAX_BODY (8 MiB default). A larger body costs about 80 microseconds of policy CPU per 2-byte segment.
- data_state: Fewer than PENDING_APPROVALS_MAX (20) pending approvals for the sandbox, and free space above min_free_bytes when the call starts.

**execution.attacker_perspective** A prompt-injected agent holding only its own sandbox's agent token calls the exec tool with a long command made of trivial unrecognised segments.

**execution.instructions**

1. In tools/sbx (no network, no Docker, 512 MiB, 120 s), build AgentBox with the real AuditLog, ApprovalStore, DesktopControl and default_policy.yaml, plus a fake SandboxManager whose preview() calls the real preview_command with empty glob and walk callbacks.
2. Set settings.min_free_bytes = shutil.disk_usage(home).free - 1 MiB so that disk_low() is False.
3. Call box.call_tool('sb_x', 'exec', {'command': 'x;'*65536}, actor='agent') once, then measure agentbox.db and agentbox.db-wal, the approvals row lengths, disk_low() and the audit row sizes.
4. Time policy.decide and preview_command for n = 4096..65536 segments to confirm linear scaling.

**execution.observed_result** Independent re-run: decision=exec-needs-approval, call_tool status 202, disk_low before=False and after=True, agentbox.db 4096 -> 6004736 bytes (45.8x the 131097-byte body), -wal 6089392 bytes, pending row args 131087 bytes and preview 5832767 bytes (65536 notes), audit approval_requested payload only 83141 bytes. Scaling run: policy.decide 0.31/0.69/1.26/2.45/5.27 s at 4096/8192/16384/32768/65536 segments and preview_command 0.02-0.26 s, so the cost is linear and an 8 MiB body is feasible, taking minutes of CPU. The expiry-compaction file growth (6.0 to 12.1 MB) and the 7.47 MB HTML fragment come from the hunter's run (agents/h-approvals/artifacts/h.out). The jinja2 rendering step was not reproduced because the module is unavailable under python -I in the sandbox. Filling a real disk and the 8 MiB case were not run.

**remediation.strategy** Bound pending rows at creation. (1) Reject agent string args above a fixed size (for example LOGGED_ARGS_MAX) with 413 before policy and preview, which also removes the policy.decide CPU cost. (2) In preview_command, cap the notes (keep the first 50 plus one 'and N more segments' summary). (3) Store bound-shaped args/preview in approvals.create, or keep the raw args elsewhere with a hard cap. (4) Re-check disk_low() immediately before approvals.create and treat sqlite3.Error from create or _finish as 503. (5) Optionally run PRAGMA wal_checkpoint(TRUNCATE) and VACUUM after prune and expiry so that compaction returns space.

`agentbox/preview.py`:

```python
NOTES_MAX = 50
...
    if len(notes) > NOTES_MAX:
        extra = len(notes) - NOTES_MAX
        notes = notes[:NOTES_MAX] + [f"... 외 {extra}개 조각의 영향도 자동 계산하지 못함. 명령 원문을 확인할 것."]
    return {"command": command, "cwd": WORKSPACE, "affected": affected, "notes": notes}
```

`agentbox/service.py`:

```python
            preview = bound_payload(preview)
            if actor == "agent" and self.disk_low():
                raise ServiceError(507, "컨트롤 플레인 디스크의 남은 공간이 부족해 승인 요청을 만들지 않음.")
            apr = self.approvals.create(sandbox_id=sid, tool=tool, args=args, ...)
```

</details>

## F2. [낮음] 화면 웹소켓 처리기가 이벤트 루프에서 SQLite·감사 잠금을 기다려, 연결 하나에 모든 HTTP 요청이 멈춘다

- 지문: `agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop`
- 심각도: 가능성 낮음 · 영향 낮음 · 종합 **낮음**. 신뢰도: medium
- 경로: `agentbox/api.py:409`(진입점), `agentbox/api.py:411`(전파), `agentbox/desktop.py:152`(전파), `agentbox/desktop_ws.py:20`(전파), `agentbox/desktop_ws.py:21`(전파), `agentbox/audit.py:294`(도달점)

**설명.** async 라우트 `/sandboxes/{sid}/desktop/ws`와 `desktop_ws.relay`가 세션 조회, vnc 명령 준비(SQLite+Docker), 연결 감사 기록, 입력마다의 `touch()`, 30초마다의 세션 재확인, 끊을 때의 감사 기록을 이벤트 루프에서 동기로 부른다. 다른 연결이 DB 쓰기 잠금을 쥔 동안(정리 명령의 BEGIN IMMEDIATE 등) 또는 다른 스레드가 감사·화면 잠금을 쥔 동안, 화면 연결·끊기 하나가 사람의 승인·삭제와 `/healthz`를 포함한 모든 요청을 최대 5초 멈춘다. 화면 링크 세션이나 자동 재연결하는 화면 탭이 이를 되풀이할 수 있다. 공격자가 긴 잠금 자체를 만들 수는 없고, 잠금이 있는 동안 이벤트를 일으킬 수 있다.

**근본 원인.** `desktop_ws`와 `relay`가 막히는 호출을 스레드로 보내지 않는다. `DesktopControl`은 메모리 잠금을 쥔 채 SQLite를 써서, 이벤트 루프가 그 SQLite 대기까지 물려받는다.

**지켜야 할 동작.** 이벤트 루프는 SQLite, I/O 동안 쥔 잠금, Docker를 기다리지 않는다. 느린 DB는 그것이 필요한 요청만 늦춘다.

**재현 관측.**

샌드박스에서 실제 앱(가짜 Docker)으로 재현했다. 기준 `/healthz` 0.0초. 쓰기 잠금 중 링크 세션 연결: `/healthz` 4.71초, 연결은 5.02초 뒤 1011로 닫힘. 화면 세션 생성이 쓰기 잠금을 기다리는 동안 아무 쿠키 연결: 4.41초. 감사 잠금 4초 중 링크 세션 연결: 3.51초.

**성립 조건.** 인증 수준, 타이밍, 데이터 상태. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 세션 확인·vnc 명령 준비·연결/끊기 기록·세션 재확인을 스레드에서 한다. `DesktopControl`은 메모리 상태와 SQLite를 다른 잠금으로 지켜, 입력마다 부르는 `touch`·`lease`가 SQLite를 기다리지 않게 한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The async route /sandboxes/{sid}/desktop/ws (api.py:408-418) and desktop_ws.relay make synchronous SQLite, threading.Lock and Docker SDK calls directly on the asyncio event loop. These are the session lookup, vnc_command (_rec plus containers.get), the log_human audit write, add_conn, the per-message touch() in control mode, the 30 s session re-check and the log_best_effort audit write on disconnect. While another SQLite connection holds the write lock (for example retention.prune's BEGIN IMMEDIATE, run by the host operator) or a worker holds AuditLog._lock, one authenticated desktop WS connect or disconnect freezes the whole control plane for up to the 5 s default sqlite busy timeout or the remaining lock hold. That covers every HTTP route, including human approvals and deletes, agent tool responses and /healthz. A desktop-link session scoped to one sandbox, or a desktop page that auto-reconnects, can repeat the stall while the condition lasts. An unauthenticated upgrade with a junk cookie stalls the loop only in a narrower case: a human desktop write (login, ticket, takeover or handback) is itself waiting on the SQLite write lock while holding DesktopControl._lock, and the loop then waits on that lock in session_scope. This undoes the design intent at api.py:158-160, which keeps blocking tool work off the human API's executor. The attacker cannot create the long lock hold, only trigger the WS event while one exists.

**root_cause** desktop_ws (api.py:409-418) and relay (desktop_ws.py:20-21,41,57,72,91) call blocking functions without run_in_threadpool. The calls are DesktopControl.session_scope (desktop.py:152-160), AgentBox.log_human and log_best_effort, which reach AuditLog.append (BEGIN IMMEDIATE under AuditLog._lock, default 5 s busy timeout; audit.py:293-294), SandboxManager._rec and containers.get (sandbox.py:185-186,230), and DesktopControl.touch and add_conn. DesktopControl also holds its in-memory threading.Lock across SQLite writes (desktop.py:135-139, plus issue_ticket, redeem, take and release), so the event loop inherits any SQLite write wait that a worker thread is in.

**intended_behavior** The event loop never waits on SQLite, on threading locks held across I/O, or on the Docker daemon. A slow or locked database, or a slow audit read, should delay only the request that needs it and never unrelated HTTP and WebSocket traffic for other sandboxes.

**trace**

- `agentbox/api.py:409` (entrypoint, desktop_ws) — Async WebSocket route; the session cookie comes from the upgrade request, so any desktop-link holder (or any cookie value, for the narrow unauthenticated case) reaches it.
- `agentbox/api.py:411` (propagation, desktop_ws) — box.desktop.session(cookie, sid) is called synchronously on the event loop.
- `agentbox/desktop.py:152` (propagation, DesktopControl.session_scope) — Takes the threading.Lock _lock, which worker threads hold across SQLite writes (new_session at desktop.py:135-139, take, release). It blocks the loop thread while it waits.
- `agentbox/desktop_ws.py:20` (propagation, relay) — vnc_command runs on the loop: _rec takes SandboxManager._lock plus a SQLite read (sandbox.py:185-186), then containers.get makes a blocking Docker HTTP call (sandbox.py:230).
- `agentbox/desktop_ws.py:21` (propagation, relay) — box.log_human (service.py:658-662) runs on the loop and calls AuditLog.append.
- `agentbox/audit.py:294` (sink, AuditLog.append) — Under AuditLog._lock, BEGIN IMMEDIATE waits up to the default 5 s sqlite busy timeout for the write lock. The whole event loop is blocked for the wait, then the connect fails with close code 1011.

**conditions**

- authentication_level: For the 5 s audit-write stall: a valid desktop-link session (scope one sandbox) or a full UI session. For the DesktopControl._lock stall: no valid session is needed (any cookie value reaches session_scope), but see the timing condition.
- timing_dependency: A concurrent long holder must exist: retention.prune's BEGIN IMMEDIATE on the same DB (operator maintenance), a worker inside AuditLog._lock (verify or recent over a large table), or a human desktop write that is waiting on the SQLite write lock while holding DesktopControl._lock. The requester cannot create the hold itself.
- data_state: The stall is bounded by the 5 s default sqlite busy timeout for each write attempt, or by the remaining audit-lock hold, which grows with the number of audit rows (measured 0.77-0.84 s for verify() over 100k rows). Docker daemon latency in containers.get was not measured.

**execution.attacker_perspective** A holder of a desktop link (scoped human session), or just an open desktop tab that auto-reconnects 1.5 s after a server close, connects to the desktop WebSocket while another SQLite connection holds the write lock or a worker holds the audit lock.

**execution.instructions**

1. Ran in the approved sandbox (no network, no Docker, uid 65534) with AGENTBOX_HOME=/scratch/home, AGENTBOX_DOCKER_CLI=/bin/false and AGENTBOX_MIN_FREE=0 against the audited tree at 346df29.
2. In each scenario a holder thread keeps a contention in place: a second sqlite3 connection in BEGIN IMMEDIATE for 7 s, a worker inside AuditLog._lock for 4 s, or BEGIN IMMEDIATE plus a worker calling box.desktop.new_session().
3. Open TestClient.websocket_connect('/sandboxes/sb_x/desktop/ws?mode=view') with the link-session cookie, a junk cookie or no cookie, then 0.3 s later time GET /healthz on the same app.

**execution.observed_result** Reproduced independently. Baseline healthz 0.0 s. Link-session WS under the SQLite write lock: healthz 4.71 s and WS closed 1011 after 5.02 s. Junk or no cookie under the same write lock: 0.0 s. Junk cookie while new_session waited on the write lock (holding DesktopControl._lock): healthz 4.41 s. Link-session WS while AuditLog._lock was held 4 s: healthz 3.51 s. Junk cookie under the audit lock: 0.0 s. audit.verify() over 100k rows in a loop: healthz 0.2 s (a short stall).

**remediation.strategy** Move every blocking call in desktop_ws and relay off the event loop with run_in_threadpool, or the dedicated pool for audit writes. Stop holding DesktopControl._lock across SQLite I/O by guarding the DB with a separate lock, so touch(), lease() and add_conn() never wait on a database. Add a regression test: while a second connection holds BEGIN IMMEDIATE, or a thread holds AuditLog._lock, a desktop WS connect must leave GET /healthz latency under 0.5 s.

`agentbox/api.py`:

```python
    @app.websocket("/sandboxes/{sid}/desktop/ws")
    async def desktop_ws(ws: WebSocket, sid: str, mode: str = "view"):
        cookie = ws.cookies.get(D.COOKIE)
        session = await run_in_threadpool(box.desktop.session, cookie, sid)
        if not session or not same_origin(ws.headers) or mode not in ("view", "control"):
            await ws.close(code=4401)
            return
        if not await run_in_threadpool(box.desktop.may_connect, sid, session, mode):
            await ws.close(code=4403)
            return
        await relay(ws, box, sid, session, mode, cookie)
```

`agentbox/desktop_ws.py`:

```python
    try:
        argv = await run_in_threadpool(box.sandboxes.vnc_command, sid, mode == "view")
        await run_in_threadpool(box.log_human, "desktop_connect", sid, {"session": session, "mode": mode})
    except (SandboxError, ServiceError):
        await ws.close(code=1011)
        return
    # also: await run_in_threadpool for box.desktop.add_conn / touch / session in session_watch,
    # and run the log_best_effort call in finally on a worker thread instead of inline
```

`agentbox/desktop.py`:

```python
# keep self._lock for the in-memory dicts only; guard self._db with a separate self._db_lock,
# and never take self._db_lock while holding self._lock, so touch()/lease()/add_conn() never wait on SQLite
```

</details>

## F3. [낮음] 최대 8MiB의 에이전트 exec 명령이 호출마다 GIL을 쥔 정책 파싱을 수 분씩 일으켜 컨트롤 플레인을 느리게 한다

- 지문: `agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap`
- 심각도: 가능성 중간 · 영향 낮음 · 종합 **낮음**. 신뢰도: medium
- 경로: `agentbox/api.py:274`(진입점), `agentbox/api.py:277`(전파), `agentbox/service.py:288`(전파), `agentbox/service.py:311`(전파), `agentbox/policy.py:211`(전파), `agentbox/policy.py:61`(도달점)

**설명.** 에이전트는 `x;x;x;…` 같은 명령을 본문 상한 8MiB까지 보낼 수 있고, 정책 판단 전에 명령 길이 상한이 없다. 기본 정책의 첫 규칙이 `command_names`→`_words`를 부르는데, `_words`는 셸 구분 문자가 든 토큰마다(맨 `;`도) `shlex`를 새로 만들고 깊이 한도까지 되풀이한다. 토큰당 약 40µs, 선형이라 128KiB에 약 5초, 8MiB면 약 5분(외삽)이다. 일은 공유 32스레드 풀에서 GIL을 쥐고 돌며, 에이전트 하나가 4개를 동시에 돌릴 수 있고, 승인 대기 상한보다 먼저 일어난다. 같은 프로세스의 대리 이벤트 루프가 중앙값 약 4배, 최대 30배 이상 느려졌다(멈춤은 아님).

**근본 원인.** 정책 판단에 입력 크기 상한이 없다(service.py:311 앞). `_words`(policy.py:40-62)가 다시 쪼개도 같은 토큰까지 매번 새 shlex로 다시 렉싱한다.

**지켜야 할 동작.** 작은 고정 상한을 넘는 에이전트 인자는 정책 판단·미리보기 전에 거절된다. `_words`는 다시 렉싱해도 같은 토큰을 다시 보지 않아, 판단이 밀리초 단위로 끝난다.

**재현 관측.**

샌드박스에서 기본 정책으로 측정: `x;`×n 16/32/64/128KiB → 0.76/1.20/2.39/5.54초, 선형. 대리 이벤트 루프(메인 스레드): 평소 중앙값 1.6ms·최대 1.9ms, 판단 1개 6.9/12.2ms, 4개 7.4/60.0ms. 8MiB 수치는 외삽이다.

**성립 조건.** 인증 수준, 시스템 설정. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 에이전트 문자열 인자(write_file 본문 제외) 16KiB 상한(정책 판단 전 413). `_words`는 다시 렉싱해도 결과가 같은 토큰(구분자만 있는 토큰, 공백·구분자·따옴표·역슬래시가 없는 토큰)만 건너뛴다. 탐지는 예전과 같다(무작위 10만 개 비교).

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** An agent token can POST /sandboxes/{sid}/tools/exec with a command made of shell-punctuation tokens (for example 'x;x;x;...') up to the 8 MiB AGENTBOX_MAX_BODY. No per-command or per-argument length cap exists before Policy.decide. With the default policy, the first rule (rm-curl-needs-approval) calls command_names, which calls _words. _words builds a new shlex.shlex for every token that contains a shell punctuation character, including each bare ';'. That costs about 40 us per token and is linear: 0.76/1.20/2.39/5.54 s for 16/32/64/128 KiB in this verifier's rerun, so roughly 300 s of CPU for one 8 MiB call (extrapolated, not run). The work runs on the shared 32-thread tool_pool and holds the GIL. One agent can keep 4 such calls running (tool_concurrency). The evaluation happens before the pending-approval cap, so that cap does not stop it. A stand-in asyncio loop on the main thread slowed from 1.6 ms median / 1.9 ms max (idle) to 6.9/12.2 ms with 1 decide thread and 7.4/60 ms with 4 decide threads. This is degradation of the shared control plane (human API, other sandboxes) for as long as the agent re-issues calls, not a freeze.

**root_cause** Policy evaluation has no input-size bound. AgentBox._call_tool passes args['command'] of any length to Policy.decide (service.py:311). The only limit is the 8 MiB HTTP body cap. _words (policy.py:40-62) re-lexes every token that contains whitespace or a shell punctuation character with a fresh shlex.shlex instance (policy.py:45, 60-61), even a token that is only ';'. shlex construction is expensive, so cost is about 40 us per punctuation token, and an 8 MiB command holds about 4M such tokens.

**intended_behavior** An agent-supplied command or argument longer than a small fixed bound (for example 64 KiB) is rejected (400/413) or sent straight to REQUIRE_APPROVAL with a fixed 'too long to analyse' preview, before Policy.decide and preview run. _words does not re-lex tokens made only of punctuation, so evaluation costs at most milliseconds and human requests keep their normal latency.

**trace**

- `agentbox/api.py:274` (entrypoint, call_tool route) — An agent token posts {"args":{"command":"x;"*N}}. ToolCall.args is an unbounded dict (api.py:54-55), limited only by the _BodyLimit middleware at 8 MiB (config.py:65).
- `agentbox/api.py:277` (propagation, call_tool route) — Dispatched to the shared 32-thread tool_pool (api.py:160) via run_in_executor (api.py:277-278). A client disconnect does not cancel the running job.
- `agentbox/service.py:288` (propagation, AgentBox.call_tool) — Admits up to tool_concurrency (default 4, config.py:53) concurrent calls per sandbox (service.py:286-290), with no size check on args.
- `agentbox/service.py:311` (propagation, AgentBox._call_tool) — policy.decide(tool, args) runs with the raw args after the tool_request audit row and before the pending-approval cap (service.py:326).
- `agentbox/policy.py:211` (propagation, Policy.decide) — The first default rule (rm-curl-needs-approval, default_policy.yaml:11-17) has match.commands, so decide calls command_names(cmd) on the whole command, then _raw_hits.
- `agentbox/policy.py:61` (sink, _words) — Each token containing a punctuation char (every ';') is recursively re-lexed with a new shlex.shlex instance (policy.py:45) while holding the GIL, about 40 us per token.

**conditions**

- authentication_level: Requires a sandbox agent token, the lowest-trust principal, which the threat model assumes can be prompt-injected.
- system_configuration: Default AGENTBOX_MAX_BODY (8 MiB), the default policy with an exec 'commands' rule (rm-curl-needs-approval), and the default tool_concurrency of 4. A policy with no exec commands rule would skip command_names.

**execution.attacker_perspective** A prompt-injected agent holding its own sandbox's agent token repeatedly sends exec tool calls whose command is a long run of 'x;' tokens. Each call ends as an approval request (or a 429 from the pending cap), but only after Policy.decide has consumed GIL-holding CPU in proportion to the command length. Up to 4 calls per sandbox run at once.

**execution.instructions**

1. In the sandbox (no network, uid 65534, 1 CPU), load the default policy with agentbox.policy.Policy.load and time Policy.decide('exec', {'command': 'x;'*n}) for n = 8192, 16384, 32768, 65536 (16-128 KiB).
2. In the same process run an asyncio probe on the main thread (30 iterations of a 20000-step Python loop plus await asyncio.sleep(0.001)) alone, with 1 thread, and with 4 threads each running decide on a 32 KiB 'x;' command. Record median and max iteration latency.

**execution.observed_result** Verifier rerun, decide('x;'*n): 16 KiB 0.757 s, 32 KiB 1.204 s, 64 KiB 2.392 s, 128 KiB 5.539 s, all returning require_approval via rule exec-needs-approval; growth is linear. Probe (32 KiB command per thread): idle median 1.6 ms / max 1.9 ms; 1 decide thread 6.9 / 12.2 ms; 4 decide threads 7.4 / 60.0 ms. This matches the hunter's figures (4.85 s at 128 KiB, 8.6 / 88.8 ms with 4 threads) within run-to-run variance. The 8 MiB figure of about 300 s is a linear extrapolation and was not run, and no live uvicorn server was measured.

**remediation.strategy** Bound the input before any parsing. In AgentBox._call_tool, before the tool_request audit row and policy.decide, refuse an exec command or any string argument over a fixed TOOL_ARG_MAX (for example 64 KiB, excluding write_file content which has its own size handling) with 413 and a tool_blocked audit row, or route it straight to REQUIRE_APPROVAL with a fixed 'too long to analyse' preview that skips command_names and preview_command. Also in _words, do not re-lex tokens made only of punctuation; recurse only on tokens that contain whitespace, '$(' or a backtick. Add a regression test asserting decide on a 64 KiB 'x;' command finishes in under about 100 ms and that a 1 MiB command is rejected or approval-routed without calling command_names.

`agentbox/service.py`:

```python
TOOL_ARG_MAX = 64 * 1024
...
    def _call_tool(self, sid, tool, args, actor):
        if tool not in TOOLS:
            raise ServiceError(404, ...)
        self.sandboxes.get(sid)
        if any(isinstance(v, str) and len(v) > TOOL_ARG_MAX for k, v in args.items() if k != "content"):
            self.log_best_effort(sid, tool, "tool_blocked", {"reason": "argument_too_long", "limit": TOOL_ARG_MAX})
            raise ServiceError(413, f"tool argument too long (max {TOOL_ARG_MAX})")
        ...
```

`agentbox/policy.py`:

```python
    for t in tokens:
        if not t:
            continue
        cleaned = ...
        out.extend(cleaned.split())
        if all(c in _SHELL_PUNCT for c in t):
            continue  # pure separator tokens are not re-lexed
        if any(c.isspace() for c in t) or any(c in _SHELL_PUNCT for c in t):
            out.extend(_words(t, depth + 1))
```

</details>

## F4. [낮음] 승인 미리보기가 rm 피연산자마다 제한 시간 없는 docker exec를 두 번씩, 횟수 상한 없이 돌린다

- 지문: `agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound`
- 심각도: 가능성 중간 · 영향 낮음 · 종합 **낮음**. 신뢰도: medium
- 경로: `agentbox/api.py:274`(진입점), `agentbox/service.py:332`(전파), `agentbox/sandbox.py:586`(전파), `agentbox/preview.py:89`(전파), `agentbox/sandbox.py:572`(도달점)

**설명.** 승인이 필요한 exec 명령에 rm 조각이 있으면 미리보기가 피연산자마다 `expand`, `-r`이면 일치마다 `walk`를 부른다. 각각 제한 시간 없는 `docker exec`다. 표시 상한 200은 모든 exec가 끝난 뒤 목록만 자른다. 피연산자 수 상한은 본문 8MiB뿐이다. 그래서 작은 요청 하나가 공유 도구 스레드를 피연산자 수에 비례해(exec 1회 약 80ms) 승인 요청이 만들어지기 전까지 붙잡는다. 승인 대기 상한은 미리보기 전에 확인돼 막지 못한다. 다른 샌드박스의 요청이 느려지는 것은 관측되지 않았다.

**근본 원인.** `preview_command`에 exec 횟수·전체 시간 상한이나 표가 찬 뒤의 중단이 없고, `_expand`·`_walk`가 `_timed` 없이 exec한다.

**지켜야 할 동작.** 미리보기는 작은 고정 횟수와 시간 안에서만 컨테이너를 확인하고, 넘으면 '미리보기 불완전'이라고 알리고 사람에게 넘긴다.

**재현 관측.**

실제 Docker 엔진에서 부모가 측정했다(`agents/parent-live/artifacts/preview_exec.json`). 피연산자 50개: 202까지 8.05초, exec_start 99회. 200개: 30.75초, 399회(exec 1회 77~81ms). 다른 샌드박스의 허용된 `ls`는 느려지지 않았다. 64KiB·8MiB 수치는 외삽이다.

**성립 조건.** 인증 수준, 데이터 상태, 환경 의존. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 미리보기의 컨테이너 확인은 모두 합쳐 40회까지, 각 10초 제한. 같은 피연산자는 한 번만. 넘으면 계산하지 않았다고 알린다. 인자 길이 상한(16KiB)도 함께 묶는다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** For an agent exec command that needs approval and contains an rm segment, preview_command calls expand(op) once per operand and, with -r, walk(m, limit) once per match. Each call is a synchronous docker exec_run in SandboxManager._expand/_walk with no container-side timeout. The display limit (200) truncates only the 'affected' list after every exec has run. Neither the API nor the service caps the operand count; the only bound is the 8 MiB body cap. One tool_pool thread is therefore held for a time proportional to the operand count (about 80 ms per exec, 2 execs per operand) before the 202 is returned. The pending-approval cap (service.py:326) is checked before the preview, so it does not throttle this. The parent-live run on the real Docker engine measured 399 exec_start events and 30.75 s to the 202 for a 200-operand command (about 1.6 KiB). Cost is linear: 50 operands took 8.05 s and 99 execs. Extrapolated, a 64 KiB command (32765 operands) holds the thread for about 87 minutes, and an 8 MiB command for days. This is a worker-occupancy and amplification problem. The live run saw no measurable delay of an allowed exec on a second sandbox (median 0.081-0.083 s against a 0.074-0.086 s baseline), so a Docker-daemon-wide slowdown is not established. The realistic impact is that a hostile agent pins its per-sandbox concurrency slots (4) and the same number of the shared 32 tool_pool threads for as long as it likes, from a single small request.

**root_cause** preview_command loops over every rm operand and every glob match and calls the container callbacks with no call budget, total deadline, or early stop once 'limit' affected entries exist. _expand and _walk use plain c.exec_run without the _timed wrapper used by the manifest and read execs, so a single exec also has no container-side time bound. Neither call_tool nor _call_tool caps the operand count or the command length.

**intended_behavior** Building the approval preview should cost a small bounded number of container execs and a bounded amount of time, then degrade to a note such as 'preview truncated, check the command text' and hand the approval to the human. A hostile command should not be able to hold a shared tool worker for an unbounded time before any approval exists.

**trace**

- `agentbox/api.py:274` (entrypoint, call_tool route (POST /sandboxes/{sid}/tools/{tool})) — An agent token posts {"args":{"command":"rm -r d d d ..."}}, bounded only by the 8 MiB body cap. The route runs box.call_tool on the shared 32-thread tool_pool (api.py:160, 277-278). A client disconnect does not cancel the executor job.
- `agentbox/service.py:332` (propagation, AgentBox._call_tool) — policy.decide (line 311) returns REQUIRE_APPROVAL (rm-curl-needs-approval, default_policy.yaml:12). After the pending cap check (line 326), self._preview (line 332, defined at 224-226) calls sandboxes.preview synchronously, before approvals.create. The per-sandbox concurrency limit in call_tool (lines 286-290) allows 4 such calls at once.
- `agentbox/sandbox.py:586` (propagation, SandboxManager.preview) — preview_command is called with lambdas bound to _expand and _walk on the live container.
- `agentbox/preview.py:89` (propagation, preview_command) — expand(op) runs for every operand (line 89). For every match with -r, walk(m, limit) runs (line 96). There is no budget, and the limit is applied only to the displayed list at lines 126-128.
- `agentbox/sandbox.py:572` (sink, SandboxManager._expand / _walk) — Each call is c.exec_run(['sh','-c',...], user=AGENT_UID) with no _timed wrapper or timeout (_expand at 572, _walk at 577). That is one docker exec_create/start/inspect round trip per operand and per match, and the thread blocks until each returns.

**conditions**

- authentication_level: A valid agent token for the sandbox (the lowest-trust network principal in the threat model, assumed prompt-injected).
- data_state: The sandbox is running and has fewer than 20 pending approvals. The command must be classified REQUIRE_APPROVAL by the default policy, for example an rm segment with the operands repeated. The operand 'd' needs to exist (an allowed 'mkdir d' creates it) for walk to run per operand.
- environmental_dependency: The impact on other principals depends on tool_pool saturation (32 threads, 4 per sandbox). One hostile sandbox pins at most 4 threads, so starving other sandboxes needs several hostile sandboxes. The human API runs on the Starlette threadpool, not tool_pool.

**execution.attacker_perspective** A prompt-injected agent holding its own sandbox's agent token and using the normal tool API.

**execution.instructions**

1. In a disposable loopback control plane (dummy tokens, default policy, one runc sandbox from ubuntu:24.04), have the agent run the allowed 'mkdir d'.
2. Send the exec call with command 'rm -r ' followed by N copies of 'd'. Time the request until the 202 and count exec_start events with docker events.
3. Repeat with N=50 and N=200 and compare. Do not run large inputs; extrapolate linearly.

**execution.observed_result** Parent-live run on the real Docker engine: N=50 took 8.05 s to the 202 with 99 exec_start events, and N=200 took 30.75 s with 399 events, about 77-81 ms per exec and 2 execs per operand. The response time is linear in the operand count and the thread is held for the whole time. Another sandbox's allowed 'ls' showed no measurable delay in that run. Larger sizes (64 KiB, 8 MiB) were not run, and the durations quoted for them are linear extrapolations.

**remediation.strategy** Bound the preview work in preview_command. Cap the total number of expand and walk calls (for example 20-50) and the operand count. Stop once 'limit' affected entries exist. Deduplicate repeated operands and matches. Add an overall deadline, and on exceeding any bound append a note that the preview is incomplete and hand the approval to the human. Also use the _timed wrapper (or exec_run with a timeout) for _expand and _walk. Optionally reject or truncate exec commands over a few KiB before policy and preview.

`agentbox/preview.py`:

```python
MAX_CALLS = 40
# inside preview_command: calls = 0; deadline = time.monotonic() + 10
# before each expand(op) / walk(m, limit):
#   if calls >= MAX_CALLS or time.monotonic() > deadline or len(affected) >= limit:
#       notes.append('operand/match count exceeds the preview budget; remaining items not checked')
#       break
#   calls += 1
```

`agentbox/sandbox.py`:

```python
# use c.exec_run(_timed(_READ_TIMEOUT, "sh", "-c", script, "_", pattern), user=AGENT_UID, demux=True) in _expand and _walk, treating exit 124/137 as a preview failure note
```

</details>

## F5. [낮음] 정리 명령이 반영(COMMIT) 직후 중단되면, 이미 지운 감사 행의 유일한 사본인 아카이브를 지운다

- 지문: `agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt`
- 심각도: 가능성 낮음 · 영향 중간 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/cli.py:319`(진입점), `agentbox/retention.py:104`(전파), `agentbox/retention.py:118`(전파), `agentbox/retention.py:126`(전파), `agentbox/retention.py:128`(전파), `agentbox/retention.py:131`(도달점)

**설명.** `retention.prune`은 아카이브를 쓴 뒤 한 트랜잭션에서 행을 지우고 아카이브 sha256을 담은 기준점을 남긴다. 안쪽 처리기는 어떤 예외에도 ROLLBACK하고, 바깥 처리기는 어떤 예외에도 아카이브를 지운다. 둘 다 COMMIT이 끝났는지 보지 않는다. fsync로 오래 걸리는 COMMIT 중에 Ctrl-C가 오면 COMMIT이 끝난 직후 KeyboardInterrupt가 나고, ROLLBACK이 'no transaction is active'로 실패하고, 바깥 처리기가 아카이브를 지운다. DB는 1..N행을 그 아카이브로 옮겼다고 말하지만 아카이브는 없다. `verify()`는 계속 통과하고 `verify_archives`는 다시는 통과하지 못한다.

**근본 원인.** 아카이브 정리(retention.py:130-131)가 '트랜잭션이 반영되지 않았을 때'가 아니라 '예외가 났을 때' 돈다. 안쪽 ROLLBACK도 트랜잭션이 이미 끝났는지 보지 않는다.

**지켜야 할 동작.** 아카이브는 정리가 반영되지 않았을 때만 지운다. 기준점이 이 아카이브를 가리키면 어떤 예외가 와도 남긴다.

**재현 관측.**

샌드박스에서 COMMIT 직후 SIGINT를 내는 연결로 재현했다. 예외는 OperationalError(바탕 KeyboardInterrupt), 아카이브 없음, 감사 행 6~8과 기준점(last_id 5) 남음, `verify()` ok·pruned_through 5, `verify_archives([archive])`는 FileNotFoundError. 실제 비동기 SIGINT를 실제 20,000행 COMMIT 중에 보내도 5번 모두 같은 처리기 경로를 탔다(헌터 h2).

**성립 조건.** 인증 수준, 타이밍, 데이터 상태. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 트랜잭션이 남아 있을 때만 ROLLBACK한다. 바깥에서는 이 아카이브를 가리키는 기준점이 있는지 보고 없을 때만 지우며, 확인하지 못하면 남긴다. 아카이브를 쓰다 실패하면 쓰다 만 파일을 지운다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** retention.prune writes the archive, then deletes the audit and approval rows and records an audit_anchor holding the archive's sha256, all in one transaction. The inner handler issues ROLLBACK on any exception, and the outer handler unlinks the archive on any BaseException. Neither handler checks whether COMMIT already succeeded. If a KeyboardInterrupt surfaces right after COMMIT returns (Ctrl-C during the fsync-bound COMMIT), the inner ROLLBACK raises OperationalError('cannot rollback - no transaction is active'). The outer handler then deletes the archive. The database says rows 1..N were pruned into an archive with a recorded sha256, and that archive no longer exists. verify() still reports ok with 'pruned through #N'. verify_archives can no longer pass, and a re-run finds nothing to prune. The pruned audit history and its tamper evidence are lost, which contradicts the invariant that a failed prune leaves the database and archive consistent.

**root_cause** The archive cleanup at retention.py:130-131 runs on any exception rather than only when the prune transaction did not commit. The inner handler (retention.py:127-129) runs ROLLBACK unconditionally, even when the transaction has already committed at retention.py:126. Any exception that surfaces after COMMIT therefore both masks itself with a ROLLBACK error and triggers the unlink of the archive that the durable anchor row refers to.

**intended_behavior** The archive is removed only if the prune transaction did not commit. Once the anchor row referencing the archive's sha256 is durable, the archive must be kept whatever exception follows. The failure should be reported as 'pruned; archive kept at <path>'. ROLLBACK should be issued only while a transaction is active.

**trace**

- `agentbox/cli.py:319` (entrypoint, cmd_prune) — Host operator runs `agentbox prune --before ... --archive ...`. It calls retention.prune on Settings().db_path and catches only ValueError, FileExistsError and RuntimeError (cli.py:323-324).
- `agentbox/retention.py:104` (propagation, prune) — The archive is written, fsynced and hashed before the transaction starts.
- `agentbox/retention.py:118` (propagation, prune) — Inside BEGIN IMMEDIATE, audit rows are deleted and an audit_anchor row with the archive name and sha256 is inserted.
- `agentbox/retention.py:126` (propagation, prune) — COMMIT makes the deletion and anchor durable. A SIGINT arriving during this call is raised as KeyboardInterrupt right after it returns, still inside the inner try.
- `agentbox/retention.py:128` (propagation, prune inner except) — Unconditional ROLLBACK raises OperationalError('cannot rollback - no transaction is active'), chained on the KeyboardInterrupt.
- `agentbox/retention.py:131` (sink, prune outer except) — archive.unlink deletes the only copy of the rows the committed anchor says were archived.

**conditions**

- authentication_level: Host operator running the prune CLI with direct DB file access. No remote or agent principal is involved.
- timing_dependency: SIGINT (Ctrl-C or a supervisor sending SIGINT) must arrive while COMMIT executes or in the few bytecodes after it inside the inner try. COMMIT of a large prune is fsync-bound, so the window is real for the large prunes the command is meant for.
- data_state: At least one audit or terminal approval row is older than the cutoff, so prune reaches the transaction.

**execution.attacker_perspective** No adversary is needed. This is an operator interrupt of a command whose interrupted-prune handling is supposed to be safe. The effect is permanent loss of the archived audit rows and their tamper evidence for the pruned range.

**execution.instructions**

1. Run tools/sbx v-prune /usr/bin/python3.13 /scratch/p.py (no network, read-only /target, uid 65534).
2. Read the exception, whether the archive exists, the audit/anchor rows, and the verify() and verify_archives() results.
3. The hunter's artifacts agents/h-retention/artifacts/h.out and h2.out show the same with the full harness. h2 uses a real asynchronous SIGINT during a real 20k-row COMMIT and hit the inner except in 5 of 5 attempts.

**execution.observed_result** Independent run (repeated by the final verifier with the same shim): prune raised OperationalError('cannot rollback - no transaction is active') with __context__ KeyboardInterrupt. The archive no longer exists. The audit table holds 3 rows starting at id 6, with anchor (seq 1, last_id 5, 'x.jsonl.gz'). verify() returned ok=True, pruned_through=5. verify_archives([archive]) raised FileNotFoundError. Hunter's h2.out confirms a real asynchronous SIGINT during a real COMMIT reaches the inner except with the 20000 rows committed.

**remediation.strategy** Make archive cleanup depend on commit state, not on whether an exception was raised. Roll back only while conn.in_transaction is true. In the outer handler, check whether an audit_anchor row with this archive's name and sha256 exists, and unlink only if it does not. If the check itself fails, keep the archive. Report a post-commit interruption as 'pruned; archive kept at <path>' rather than a raw OperationalError. Optionally fsync the archive's parent directory after creating it. Add a regression test where a Connection factory raises KeyboardInterrupt after a successful COMMIT, and assert the archive remains and verify_archives([archive]) passes.

`agentbox/retention.py`:

```python
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                ...  # unchanged body
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        except BaseException:
            committed = True   # unknown state: never destroy a possibly referenced archive
            try:
                committed = conn.execute("SELECT 1 FROM audit_anchor WHERE archive_sha256 = ? AND archive = ?",
                                         (sha, archive.name)).fetchone() is not None
            except sqlite3.Error:
                pass
            if not committed:
                archive.unlink(missing_ok=True)
            raise
```

</details>

## F6. [낮음] 사람이 화면을 인수한 동안 에이전트 GUI 구간이 열려, 사람이 띄운 프로세스를 멈추고 사람의 편집을 에이전트 변경으로 남긴다

- 지문: `agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease`
- 심각도: 가능성 낮음 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/api.py:273`(진입점), `agentbox/gui_bursts.py:61`(전파), `agentbox/service.py:367`(전파), `agentbox/service.py:582`(전파), `agentbox/service.py:268`(전파), `agentbox/service.py:143`(전파), `agentbox/gui_bursts.py:154`(전파), `agentbox/gui_state.py:53`(전파), `agentbox/sandbox_desktop.py:92`(도달점)

**설명.** `AgentBox._snapshot`은 `gui_lock` 없이, 인수 여부도 보지 않고 GUI 구간을 닫고 연다. 인수 중에 GUI 입력 승인을 결정하거나(`decide`), 에이전트 클릭의 입력 전 `docker commit` 중에 사람이 인수하면(`call_tool`), 인수 중에 잡은 기준으로 구간이 열린다. 입력은 423이나 실패로 끝나지만 구간은 남는다. 그 구간이 쉬어 닫힐 때(에이전트의 아무 도구 호출이나 `GET /approvals/{aid}`로 시점을 고를 수 있다) 인수 중에 사람이 띄운 셸·작업이 `kill -KILL`되고, 사람의 `/workspace` 편집이 에이전트 구간의 `gui_changes`로 남는다. 인수가 구간을 먼저 닫는 설계 의도(service.py:582)를 우회한다.

**근본 원인.** `_snapshot`(service.py:261-276)의 구간 열기가 인수와 같은 잠금으로 직렬화되지 않고 인수 여부를 보지 않는다. 인수 확인은 커밋 전 `needs_snapshot`에만 있고 `decide`에는 없다. 423·실패 처리기가 방금 연 구간을 치우지 않는다.

**지켜야 할 동작.** 사람이 화면을 쥐고 있거나 쥐려는 동안에는 에이전트 GUI 구간(기준, 멈추기, 변경 귀속)이 존재하지 않는다.

**재현 관측.**

실제 Docker와 `agentbox-desktop:0.1`에서 부모가 재현했다(`agents/parent-live/artifacts/gui_lease_a.json`).
- 클릭을 승인 대상으로 둔 정책에서 인수 → 에이전트 클릭 202 → 사람이 인수 중 승인 → `failed`, 구간은 열린 채 남음.
- 인수 중에 사람 몫으로 `setsid sleep 600`(pid 400)을 띄우고 쉬는 시간이 지난 뒤 정리 호출 → 인수가 유지된 채 `gui_processes_stopped`(reason idle)로 pid 400이 멈춤.
- 샌드박스 재현(가짜 Docker): 경쟁이 없을 때는 멈춘 것 없음, 커밋 중 인수(b)와 승인(a) 경로는 사람 셸·작업 [201, 202]를 멈추고 사람 파일을 에이전트 변경으로 기록.

**성립 조건.** 인증 수준, 시스템 설정, 사용자 상호작용, 타이밍. 조건별 설명은 아래 원문의 `conditions`에 있다.

**수정 방향.** 구간은 인수와 같은 `gui_lock` 아래에서, 인수·인수 대기가 없을 때만 연다(있으면 열지 않고 423). 인수 중에 결정한 GUI 입력 승인은 스냅샷 없이 실패로 끝낸다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** AgentBox._snapshot closes and opens an agent GUI burst without taking gui_lock and without checking the takeover lease. If an approved GUI click/type/key is decided while a lease is held, or if an agent click/type/key whose pre-input docker commit overlaps POST /desktop/takeover, a new burst is installed with a baseline taken mid-takeover. _run_tool then raises HumanControl (call_tool returns 423, decide marks the approval failed) but nothing discards the burst. When close_idle runs, or the next agent burst closes it after handback, _stop_strays SIGKILLs as the desktop user every uid-1001 process the human started after that baseline in a session absent from it (terminal shells and jobs started from them). _finish also records the human's /workspace edits as agent gui_changes under the agent burst's snapshot_id. Takeover closes the burst at service.py:582 precisely so that human activity stays out of agent bursts, and this path bypasses that. The agent can choose when the kill happens, because any agent tool call or GET /approvals/{aid} runs close_idle. Path (a) is demonstrated against the real Docker engine and desktop image. Path (b) rests on source plus a local deterministic schedule: the race window is the docker commit duration, which was not timed live, and the agent cannot force a takeover into it. Impact is bounded: lost human background work (windowed apps are kept) and misattributed audit rows, not agent escalation.

**root_cause** Burst open/close in _snapshot (service.py:261-276) is not serialized with takeover (gui_lock) and is not conditioned on the lease. GuiBursts.needs_snapshot (gui_bursts.py:61) checks the lease only before a multi-second commit, and decide (service.py:467) does not check it at all. The HumanControl handlers in call_tool (service.py:373-381) and decide (service.py:477-480) leave the burst that _snapshot just opened in _gui_burst. A baseline taken during the lease is later used for stray kill and change attribution.

**intended_behavior** No agent GUI burst (baseline, later stray kill, gui_changes attribution) exists while a human takeover lease is held. Takeover closes the agent burst under gui_lock (service.py:582) so that human processes and edits are never judged against an agent baseline, and every later burst open is serialized against the lease.

**trace**

- `agentbox/api.py:273` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — The agent token calls click/type/key (api.py:278 calls box.call_tool with actor=agent). A pending GUI approval is decided via POST /approvals/{aid} (api.py:308) or POST /ui/approvals/{aid}/{decision} (web.py:242), both reaching AgentBox.decide.
- `agentbox/gui_bursts.py:61` (propagation, GuiBursts.needs_snapshot) — The lease and takeover_pending check happens only here, before the docker commit. With no lease yet it returns True and the commit starts.
- `agentbox/service.py:367` (propagation, AgentBox._call_tool) — The allow path calls _snapshot without gui_lock. decide calls _snapshot at service.py:467 with no lease check at all.
- `agentbox/service.py:582` (propagation, AgentBox.takeover) — Takeover takes gui_lock, which is free because _snapshot does not hold it. It closes the burst (none open yet) and installs the lease at service.py:584.
- `agentbox/service.py:268` (propagation, AgentBox._snapshot) — After the commit returns, bursts.open records a baseline of desktop-user pids and a /workspace manifest taken while the lease is held (gui_bursts.py:73-87).
- `agentbox/service.py:143` (propagation, AgentBox._run_tool) — _check_control raises HumanControl. call_tool returns 423 (service.py:373-381) and decide marks the approval failed (service.py:477-480). The burst stays in _gui_burst and no input time is marked (mark_input is never reached), so it already counts as idle.
- `agentbox/gui_bursts.py:154` (propagation, GuiBursts.close_idle) — Run from any call_tool (service.py:285) or expire_stale (service.py:424, reached by GET /approvals/{aid}, api.py:288-290). It submits close() of the mid-lease burst while the lease is still held. Alternatively _snapshot's close('next_burst') (service.py:263) closes it after handback.
- `agentbox/gui_state.py:53` (propagation, _new_processes) — Human-started desktop-user processes in sessions absent from the mid-lease baseline are classified as strays (line 78). Windowed ones go to kept.
- `agentbox/sandbox_desktop.py:92` (sink, SandboxManager.kill_processes) — kill -KILL of the human's processes as the desktop user (via GuiBursts._stop_strays, gui_bursts.py:95). _finish (gui_bursts.py:147) logs the human's /workspace edits as agent gui_changes.

**conditions**

- authentication_level: Agent token for its own desktop sandbox (lowest-trust network principal). Path (a) also needs the human to take over and decide the approval.
- system_configuration: Desktop-template sandbox with gui_snapshot_interval > 0 (default). Path (a) needs a GUI click/type/key to be gated by policy or by the snapshot quota so a pending approval exists. Path (b) works under the default policy, which allows GUI tools.
- user_interaction: Path (a): a human takes over the desktop and approves, or is approved on their behalf from the UI, a pending GUI approval while the lease is held. Path (b): a human takeover starts inside the agent's docker commit.
- timing_dependency: Path (b) needs the takeover to land inside the pre-input docker commit window. Path (a) is deterministic. The human must also start a non-windowed or new-session desktop-user process after the baseline, such as a terminal shell or a setsid/nohup job, before the burst closes.

**execution.attacker_perspective** Prompt-injected agent holding the sandbox's agent token. It places or waits for a GUI click/type/key, which is sent so that it ends up as a pending approval or its docker commit overlaps a takeover, and later makes any tool call or GET /approvals/{aid} to trigger close_idle.

**execution.instructions**

1. Create a desktop sandbox with a policy rule gating click behind approval.
2. Human takes over: POST /sandboxes/{sid}/desktop/takeover.
3. Agent sends click and receives 202 with an approval_id.
4. Human approves during the lease. The approval ends status failed (HumanControl) after a snapshot row is logged, and the burst stays open with a baseline taken during the lease.
5. Human starts a job in a new session, for example setsid sleep 600 as the desktop user or a terminal opened through noVNC.
6. After the idle window, the agent calls any tool or GET /approvals/{aid}. While the lease is still held, the audit log gets gui_processes_stopped (reason idle) listing the human's pid, and the process is gone.
7. Path (b): the same end state is reached when the agent's click commit overlaps a takeover (click returns 423, burst left open). Handing back and having the agent click again closes it with reason next_burst.

**execution.observed_result** Real Docker plus agentbox-desktop:0.1 (parent-live, path a): the burst was opened during the lease. The human's setsid sleep 600 (pid 400) was killed by the idle close with the lease still held and the burst closed, and gui_processes_stopped was audited. Independent local rerun (fake Docker-facing SandboxManager, real AgentBox, GuiBursts, gui_state, DesktopControl and ApprovalStore) via tools/sbx: the control with no race killed []. Path (b) with close during the lease killed [201, 202]. Path (b) with the close via next_burst after handback killed [201, 202]. Path (a) decide-under-lease killed [201, 202] with the lease held. The windowed xfce4-terminal was kept, and the human's file was logged as agent gui_changes under snap_1.

**remediation.strategy** Never let a burst exist while the human holds or is about to hold the screen. Serialize _snapshot's close, commit and open with the same gui_lock that takeover uses. Re-check lease(sid), is_stale and _takeover_pending after the commit and before bursts.open. If the lease or a pending takeover is present, skip opening, or discard the snapshot's burst. Also discard or close the burst without stray kill when HumanControl is raised in call_tool and decide. Make decide check the lease before snapshotting. As defense in depth, have _finish skip _stop_strays and gui_changes for a burst whose open time overlapped a lease, and reject close or kill while desktop.lease(sid) is set.

`agentbox/service.py`:

```python
# in _snapshot, after the commit and before bursts.open, with self.desktop.gui_lock(sid) held around close+open:
if tool in GUI_INPUT:
    with self.desktop.gui_lock(sid):
        if self.desktop.lease(sid) or self._takeover_pending(sid):
            self.bursts.reset_timers(sid)
            raise HumanControl(self.desktop.lease(sid) or Lease(sid, self._takeover_pending(sid)))
        self.bursts.mark_snapshot(sid)
        opened = self.bursts.open(sid, snap['id'])
# and in call_tool/decide HumanControl handlers: self.bursts.close_discard(sid)  # drop burst without stray kill
```

</details>
