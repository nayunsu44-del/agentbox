# run-6 확정 상세

`findings.json`의 확정(`confirmed`) 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같으며, 항목마다 아래에 영어 레코드 원문(기준)을 접어 두었다. 줄 번호는 감사 기준 `530b29e`을 따른다. 보고 이후 확정 3건과 검증 필요 3건 모두 수정 완료되었다.

## F1. [중간] 감사 테이블에 sandbox_id 인덱스가 없고 verify()가 전체 테이블을 fetchall()로 읽어, 테이블이 커지면 AuditLog._lock 경합과 메모리 급증을 일으킨다

- 지문: `agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory`
- 심각도: 가능성 중간 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/templates/sandbox.html:19`(진입점), `agentbox/web.py:293`(전파), `agentbox/audit.py:325`(전파), `agentbox/audit.py:293`(도달점)

**설명.** `audit` 테이블 스키마(`audit.py:17-27`)에는 `sandbox_id` 인덱스가 없다. 그런데 샌드박스 웹 화면(`templates/sandbox.html:19`)이 3초마다 폴링하는 `GET /ui/audit`는 `AuditLog.recent(sandbox_id=..., limit=400)`(`web.py:293`)를 부르고, `recent()`(`audit.py:325-334`)는 전역 `AuditLog._lock`을 잡은 채 인덱스 없는 `SELECT COUNT(*) FROM audit WHERE sandbox_id = ?`와 `SELECT ... WHERE sandbox_id = ? ORDER BY id DESC LIMIT ?`를 실행한다. 에이전트가 90일 보관 기간 동안 일상적인 도구 호출·승인 미리보기(행당 최대 128KiB)로 수천~수만 행을 쌓으면, SQLite 페이지 크기(4KiB) 특성상 행마다 리프·오버플로 페이지가 생겨 3초마다 전체 테이블 스캔이 `_lock` 아래에서 돈다. 또한 `AuditLog.verify()`(`audit.py:336-350`)는 `_lock`을 잡은 채 `SELECT ... FROM audit ORDER BY id`의 `.fetchall()`로 전체 행과 페이로드를 한꺼번에 파이썬 메모리에 올리고 해시를 다시 계산한다. 그동안 모든 도구 기록과 실패 시 닫히는(fail-closed) 사람의 `log_human` 호출이 `AuditLog._lock`에서 멈춘다.

**근본 원인.** `audit` 테이블에 `sandbox_id` 인덱스가 없고, `AuditLog.recent()`·`verify()`·`list()`가 추가(append)와 같은 프로세스 전역 `AuditLog._lock`을 잡은 채 전체 스캔·전체 행 `fetchall()`을 수행한다.

**지켜야 할 동작.** `recent()`는 `audit(sandbox_id, id)` 인덱스로 해당 샌드박스의 행만 빠르게 읽어야 하며, `verify()`는 `fetchall()`로 전체 테이블을 한 번에 메모리에 올리거나 긴 시간 동안 추가용 `_lock`을 붙잡지 않고 배치(스트리밍)나 별도 읽기 연결(WAL)로 검증해야 한다.

**재현 관측.**

512MiB 샌드박스에서 약 25.2KiB 페이로드 1,200행(DB 30.49MiB)으로 헌터(`agents/h-locks-ws/artifacts/bench_realistic.out`)와 3단계 검증자(`agents/v-audit-lock/artifacts/v.out`)가 각각 측정했다.
- 3단계 독립 검증에서 인덱스 없는 `recent('sb_target', limit=25)` 평균 잠금 점유 시간은 **175.15ms**였고, `audit(sandbox_id)` 인덱스를 추가하면 **28.86ms**(6.07배 단축)로 줄었다(헌터 측정은 `recent('sb_other', limit=25)` 113.31ms).
- 유효한 해시 체인 전체를 검증하는 `verify()`는 `AuditLog._lock`을 **5,628.31ms(5.63초)** 동안 잡고 최고 **58.64MiB** 힙 메모리를 썼다.
- 10,000행(약 200MiB DB)으로 외삽하면 `verify()`는 약 **46.9초** 동안 `_lock`을 잡고 약 **488.6MiB** 메모리를 쓰며, 3초마다 도는 웹 UI 폴링은 폴링마다 약 **1.46초**(3초 주기의 48% 이상) 동안 `_lock`을 점유한다.

**성립 조건.** 데이터 상태, 사용자 상호작용. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** `SCHEMA`에 `CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id, id)`를 추가하고, `AuditLog.verify()`는 `fetchmany()`로 나누어 읽거나 WAL 읽기 전용 연결을 써서 전체 테이블 적재와 긴 `_lock` 점유를 없앤다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The audit table schema defines no index on sandbox_id, yet GET /ui/audit (polled every 3 seconds by the sandbox UI) invokes AuditLog.recent(), which executes unindexed 'SELECT COUNT(*) FROM audit WHERE sandbox_id = ?' and 'SELECT ... WHERE sandbox_id = ?' queries under the global in-process AuditLog._lock. When an agent grows the table with realistic tool call payloads and previews (up to 128 KiB each), these queries must scan every leaf and overflow page. Furthermore, AuditLog.verify() executes 'SELECT ... FROM audit ORDER BY id' and calls .fetchall() under AuditLog._lock, holding the lock while loading all rows into Python memory at once (~488 MiB for 10,000 rows). Because AuditLog.append() (used by all tool logging and fail-closed log_human operations) serializes on AuditLog._lock, these operations block all human and agent actions for seconds, and verify() risks container OOM termination.

**root_cause** AuditLog._lock is a coarse-grained process-wide lock held across long-running database read operations. The audit table lacks an index on sandbox_id, forcing full table scans on frequent UI polling (every 3s), and AuditLog.verify() unconditionally fetches all rows across the table's entire history into memory under the same lock rather than streaming, chunking, or querying via a non-blocking read connection in WAL mode.

**intended_behavior** UI polling via recent() should be satisfied rapidly using an index on audit(sandbox_id) without scanning unrelated overflow pages. Verification in verify() should stream or paginate rows using fetchmany() outside the append lock, and should not hold the primary write lock across full-table queries.

**trace**

- `agentbox/templates/sandbox.html:19` (entrypoint, sandbox.html) — Operator viewing sandbox page triggers automatic polling of GET /ui/audit?sandbox_id={sid} every 3 seconds via htmx
- `agentbox/web.py:293` (propagation, audit_frag) — audit_frag invokes box.audit.recent(sandbox_id=sandbox_id, limit=400)
- `agentbox/audit.py:325` (propagation, AuditLog.recent) — AuditLog.recent acquires self._lock and executes unindexed SELECT COUNT(*) and SELECT ... WHERE sandbox_id = ? scanning every leaf and overflow page
- `agentbox/audit.py:293` (sink, AuditLog.append) — Every concurrent AuditLog.append call, including fail-closed log_human operator actions and agent tool calls, blocks on with self._lock

**conditions**

- data_state: The audit table has accumulated thousands of rows containing realistic tool payloads and approval previews (16-32 KiB each) within the 90-day retention window
- user_interaction: A human operator opens the web UI sandbox view (triggering 3s polling) or clicks verify chain

**execution.attacker_perspective** An unprivileged agent generating ordinary tool executions (e.g. exec, write_file) with 16-25 KiB arguments or previews populates the audit table up to tens of thousands of rows. When a human administrator views the sandbox UI (which polls /ui/audit every 3s) or triggers /ui/verify, the unindexed table scan and full table fetchall hold the global AuditLog._lock for seconds at a time and allocate hundreds of megabytes of memory, degrading control-plane responsiveness and blocking all tool logging and human admin actions.

**execution.instructions**

1. Create an AuditLog database with 1,200 rows containing realistic ~25 KiB tool call/preview payloads (~30.5 MiB database size) with valid hash chain.
2. Invoke AuditLog.recent('sb_target', limit=25) to measure unindexed leaf/overflow page scan duration under self._lock.
3. Invoke AuditLog.verify() to measure lock hold time and peak heap memory allocation during self.conn.execute(...).fetchall() under self._lock.
4. Compare against an indexed table (CREATE INDEX audit_sandbox_id ON audit(sandbox_id)) to verify contention reduction.

**execution.observed_result** In an isolated 512 MiB sandbox with 1,200 rows of 25.2 KiB payloads (30.49 MiB DB), unindexed recent('sb_target', limit=25) held AuditLog._lock for an average of 175.15ms (reduced to 28.86ms with an index on sandbox_id, a 6.07x speedup). Full table verify() on the valid chain held AuditLog._lock for 5628.31ms (5.63s) with a peak heap memory allocation of 58.64 MiB. Extrapolated to 10,000 rows (~200 MiB table), verify() holds AuditLog._lock for ~46.9s while consuming ~488.6 MiB of memory (approaching 512 MiB container limits), and 3-second UI polling holds the lock for ~1.46s per poll (occupying over 48% of total available time), blocking all concurrent audit.append and log_human calls.

**remediation.strategy** 1. Add an index on audit(sandbox_id) in SCHEMA (CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id)) so that recent() queries for a specific sandbox only read relevant rows rather than scanning the entire table and all overflow pages.
2. In AuditLog.verify(), avoid holding self._lock across the entire fetchall() or iterate through rows in bounded batches (or fetch only necessary columns such as id, ts, prev_hash, hash, payload with fetchmany) outside the lock, or run verification queries on a separate read connection under SQLite WAL mode without blocking the in-process append lock.

`agentbox/audit.py`:

```python
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    sandbox_id  TEXT,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    tool        TEXT,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id);

```

</details>

## F2. [중간] 복원 중 열린 옛 컨테이너의 GUI 구간을 GuiBursts.covers()가 구분하지 못해, 복원된 컨테이너에서 실행된 에이전트 프로세스가 정리·기록에서 빠진다

- 지문: `agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore`
- 심각도: 가능성 중간 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/service.py:306`(진입점), `agentbox/service.py:267`(전파), `agentbox/gui_bursts.py:76`(전파), `agentbox/service.py:148`(전파), `agentbox/gui_bursts.py:136`(도달점)

**설명.** `GuiBursts.covers(sid)`(`gui_bursts.py:68-71`)는 `sid in self._gui_burst`만 볼 뿐, 열린 구간의 `container_id`가 지금 샌드박스의 `container_id`와 같은지 보지 않는다. 또한 `restore_sandbox`(`service.py:573-581`)는 `sandboxes.restore` 전에 `end_desktop`(`bursts.end`)을 한 번 부르고, 복원이 끝난 뒤에는 `bursts.reset_timers(sid)`만 부른다(`_gui_burst[sid]`를 비우지 않는다). 에이전트의 GUI 도구 호출이 복원 전 컨테이너 C1의 `sandboxes.snapshot` 커밋을 끝내고 `end_desktop` 직후에 `bursts.open`을 돌리면, `_gui_burst[sid]`에는 `container_id = C1`인 구간이 열린다. 이어서 `sandboxes.restore`가 컨테이너를 C2로 바꾸고 `reset_timers`가 끝나도 `_gui_burst[sid]`는 그대로 남는다. 그 호출(또는 뒤이은 GUI 입력)이 `_run_tool`에 들어가면 `covers(sid)`가 `True`를 돌려주어 새 컨테이너 C2에서 C1 구간 아래로 GUI 입력이 실행된다. 나중에 이 구간이 닫힐 때 `_finish`(`gui_bursts.py:131-136`)는 `C2 != C1`(`replaced = True`)을 보고 `gui_burst_close_failed`만 남긴 채 `_stop_strays`와 `diff_manifest`를 건너뛴다. 그 결과 C2에서 에이전트가 띄운 백그라운드 프로세스는 죽지 않고 살아남아 다음 구간의 기준(baseline) PID에 들어가 영구히 면제되며, 파일 변경도 `gui_changes`에 남지 않는다.

**근본 원인.** 1) `GuiBursts.covers(sid)`(`gui_bursts.py:71`)가 `self._gui_burst[sid]['container_id'] == self.sandboxes.get(sid)['container_id']`를 확인하지 않는다.
2) `restore_sandbox`(`service.py:578`)가 `sandboxes.restore` 뒤에 `bursts.end(sid, ...)` 대신 `bursts.reset_timers(sid)`만 호출하고, `_snapshot`(`service.py:267-279`)과 `restore_sandbox`가 같은 잠금을 공유하지 않아 복원 도중 옛 컨테이너 기준으로 열린 구간이 복원 뒤에도 살아남는다.

**지켜야 할 동작.** `GuiBursts.covers(sid)`는 열린 구간의 `container_id`가 현재 샌드박스의 `container_id`와 일치할 때만 `True`를 돌려주어야 하며, `restore_sandbox`는 컨테이너가 바뀐 뒤에도 옛 컨테이너의 구간이 남아 있지 않도록 닫아야 한다.

**재현 관측.**

샌드박스(`agents/h-gui-burst/artifacts/h.out`)와 실제 일회용 Docker 컨테이너(`agents/parent-live/artifacts/gui_burst_restore_live.out`)에서 모두 재현했다.
- C1에서 구간을 연 뒤 `sb.restore(sid, snap_id)`로 C2로 복원하고 `bursts.reset_timers(sid)`를 호출해도 `bursts.covers(sid)`는 `True`다.
- C2에서 백그라운드 프로세스(`sleep 300`)를 띄우고 파일을 바꾼 뒤 `bursts.close(sid, 'idle')`을 부르면 `gui_burst_close_failed`(`컨테이너가 바뀌어 비교하지 않음 (복원)`)만 남고 `sleep 300`은 죽지 않고 살아남으며 `gui_changes`도 기록되지 않는다.

**성립 조건.** 인증 수준, 타이밍. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** `GuiBursts.covers(sid)`에서 열린 구간의 `container_id`를 현재 `sandboxes.get(sid)['container_id']`와 비교하고, `restore_sandbox`가 `sandboxes.restore` 뒤에도(또는 `gui_lock`/`_snap_locks`와 직렬화하여) 옛 컨테이너로 열린 구간을 정리한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** GuiBursts.covers (gui_bursts.py:68-71) checks only whether the sandbox ID exists in self._gui_burst without verifying that the burst's recorded container_id matches the sandbox's current container_id from sandboxes.get(sid). When an agent GUI input initiates a burst snapshot concurrently with an administrative restore_sandbox operation, restore_sandbox's end_desktop call runs before bursts.open creates the new burst entry. bursts.open records the pre-restore container C1, but sandboxes.restore then replaces the active container with C2. Because covers() checks only 'sid in self._gui_burst', the agent's GUI tool call executes on the restored container C2 under C1's baseline. When the burst subsequently closes, _finish detects the container mismatch, aborts change diffing, and logs gui_burst_close_failed without invoking _stop_strays, allowing any background processes spawned by the agent on C2 to persist unmonitored and join future burst baselines.

**root_cause** GuiBursts.covers (gui_bursts.py:68-71) only evaluates 'self.sandboxes.settings.gui_snapshot_interval <= 0 or sid in self._gui_burst' without binding the burst to the current container identity (self.sandboxes.get(sid)['container_id']), and restore_sandbox (service.py:573-581) does not call bursts.end() after replacing the container in sandboxes.restore().

**intended_behavior** GuiBursts.covers(sid) must verify that the recorded burst['container_id'] matches self.sandboxes.get(sid)['container_id']. If the container has changed, covers() must return False, causing _run_tool (service.py:148-152) to raise SandboxError and reject the execution. In addition, restore_sandbox() must call bursts.end(sid, 'sandbox_restored') after completing sandboxes.restore() to clear any bursts opened during the restore window.

**trace**

- `agentbox/service.py:306` (entrypoint, AgentBox.call_tool) — Agent dispatches a GUI input tool call (e.g. click, type, key) on a desktop sandbox while an administrative restore_sandbox operation is in flight or pending.
- `agentbox/service.py:267` (propagation, AgentBox._snapshot) — _snapshot closes any existing burst (line 266) and begins committing the current container C1. Concurrently, restore_sandbox (service.py:574-577) runs end_desktop (which finds _gui_burst empty and does not clear the upcoming burst) and enters sandboxes.restore to replace C1 with C2.
- `agentbox/gui_bursts.py:76` (propagation, GuiBursts.open) — _snapshot completes the commit of C1 and invokes bursts.open(sid, snap['id']). bursts.open records container_id C1 into self._gui_burst[sid] before sandboxes.restore completes updating the active container to C2 in the database.
- `agentbox/service.py:148` (propagation, AgentBox._run_tool) — _run_tool executes under gui_lock and checks self.bursts.covers(sid). Because covers() only checks 'sid in self._gui_burst' and does not compare burst['container_id'] to sandboxes.get(sid)['container_id'], it returns True despite the active container now being C2.
- `agentbox/gui_bursts.py:136` (sink, GuiBursts._finish) — The GUI tool executes on C2, allowing the agent to launch rogue background processes. When the burst closes, _finish checks replaced = self.sandboxes.get(sid)['container_id'] != burst.get('container_id'). Because C2 != C1, replaced is True, so _finish logs gui_burst_close_failed and returns immediately without running _stop_strays or diff_manifest. The agent's background processes survive on C2 and silently join the baseline of the next burst.

**conditions**

- authentication_level: Agent token with authorization to call GUI input tool endpoints (click, type, key) on a sandbox with the desktop template.
- timing_dependency: An agent GUI input tool call executing _snapshot races against restore_sandbox such that bursts.open runs after restore_sandbox's end_desktop call but before the active container update.

**execution.attacker_perspective** An untrusted agent invokes GUI tool calls on its sandbox while the human administrator or control plane restores the sandbox from a snapshot.

**execution.instructions**

1. Run the sandbox test script scratch/verify.py using tools/sbx.py.
2. Thread t1 calls box.call_tool('sb1', 'click', {'x': 5, 'y': 5}), entering _snapshot on container C1.
3. Thread t2 calls box.restore_sandbox('sb1', 'snap_0'), executing end_desktop and entering sandboxes.restore.
4. Thread t1 completes snapshot commit and invokes bursts.open, recording C1 in _gui_burst['sb1'].
5. Thread t2 finishes restore, updating the database active container to C2.
6. Thread t1 calls _run_tool, where bursts.covers('sb1') evaluates to True because it checks only 'sid in _gui_burst'.
7. The click executes on container C2, spawning a background process (pid 999).
8. Upon burst closure (idle or next tool), _finish detects container replacement (C2 != C1), logs gui_burst_close_failed, and returns without killing rogue processes.
9. The subsequent burst baseline on C2 includes pid 999 as an authorized process.

**execution.observed_result** Tool executed with status 200 on container C2 under a burst with container_id C1. bursts.covers('sb1') returned True. On burst closure, zero processes were killed, gui_burst_close_failed was logged with '컨테이너가 바뀌어 비교하지 않음 (복원)', and rogue process 999 successfully joined the baseline of the next burst on C2. Live container run confirmed stray process 'sleep 300' survived burst close on C2.

**remediation.strategy** Modify GuiBursts.covers(sid) to verify that burst.get('container_id') == self.sandboxes.get(sid)['container_id']. If the container ID does not match, return False so _run_tool rejects the execution with SandboxError. In addition, call self.bursts.end(sid, 'sandbox_restored') in restore_sandbox() after sandboxes.restore() completes.

`agentbox/gui_bursts.py`:

```python
    def covers(self, sid: str) -> bool:
        """지금 GUI 입력을 실행해도 열린 구간이 그 변경을 받는지. gui_lock을 잡은 채로 부른다.
        스냅샷 판단은 잠금 전에 하므로, 잠금을 기다리는 사이 인수·반환으로 구간이 닫히면 여기서 걸러진다."""
        if self.sandboxes.settings.gui_snapshot_interval <= 0:
            return True
        burst = self._gui_burst.get(sid)
        if not burst:
            return False
        try:
            return burst.get("container_id") == self.sandboxes.get(sid)["container_id"]
        except Exception:
            return False

```

</details>

## F3. [낮음] 승인 영향 미리보기가 중괄호({a,b})와 틸드(~) 확장을 계산하지 못해 실제 삭제될 파일을 '현재 존재하지 않음'으로 잘못 표시한다

- 지문: `agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets`
- 심각도: 가능성 낮음 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/api.py:305`(진입점), `agentbox/service.py:354`(전파), `agentbox/sandbox.py:595`(전파), `agentbox/preview.py:109`(전파), `agentbox/sandbox.py:578`(전파), `agentbox/preview.py:111`(전파), `agentbox/templates/_approvals.html:14`(전파), `agentbox/sandbox.py:425`(도달점)

**설명.** 사람이 승인할 때 보는 영향 미리보기 카드는 `preview_command`(`preview.py:70-160`)가 명령을 `shlex`로 쪼갠 뒤 컨테이너의 `_expand`(`sandbox.py:578-585`)로 넘겨 만든다. 그런데 `_expand`는 컨테이너의 `/bin/sh`(dash)에서 위치 인자 `$1`로 패턴을 평가한다. POSIX dash는 중괄호 확장(`{a,b}.txt`, `{1..10}`)을 지원하지 않고, 변수(`$1`) 안의 틸드(`~/file`)도 확장하지 않는다. 그 결과 `[ -e "$p" ]`가 거짓이 되어 빈 목록이 돌아오고, `preview_command`(`preview.py:110-111`)는 이를 `{'path': op, 'effect': '삭제 시도 (현재 존재하지 않음)'}`으로 표시하며 주의 메모(`notes`)도 붙이지 않는다(`preview.py:88`은 `$`, `` ` ``, `<(`, `eval `만 검사한다). 사람이 '현재 존재하지 않음'이라는 카드를 믿고 승인하면, 실제 실행(`sandbox.py:425`)은 `/bin/bash`로 돌아 중괄호·틸드를 확장하고 실제 파일을 삭제한다.

**근본 원인.** 미리보기 경로 확장(`_expand`, `/bin/sh`)과 실제 실행 셸(`exec`, `/bin/bash`)의 확장 규칙이 다른데, `preview_command`가 `{`나 `~`가 들어간 피연산자에 대해 경고를 남기지 않고 빈 확장 결과를 곧바로 '현재 존재하지 않음'으로 단정한다.

**지켜야 할 동작.** 승인 미리보기는 실행 셸(`/bin/bash`)과 같은 확장 규칙으로 대상 파일을 계산하거나, 자동 계산이 지원하지 않는 셸 확장(`{`, `~` 등)이 있으면 `notes`에 자동 계산이 정확하지 않다는 경고를 띄워 사람이 명령 원문을 확인하게 해야 한다.

**재현 관측.**

샌드박스(`agents/h-preview-argcap/artifacts/h.out`)와 실제 일회용 Docker 컨테이너(`agents/parent-live/artifacts/preview_brace_tilde_live.out`)에서 모두 확인했다.
- `/workspace/a.txt`, `/workspace/b.txt`, `/home/agent/tilde_target.txt`가 있을 때 `sb.preview(sid, 'rm {a,b}.txt')`와 `sb.preview(sid, 'rm ~/tilde_target.txt')`는 모두 `effect: '삭제 시도 (현재 존재하지 않음)'`, `notes: []`를 돌려준다.
- 같은 명령을 `sb.exec`로 실행하면 `exit_code=0`으로 세 파일이 모두 삭제된다.

**성립 조건.** 인증 수준, 사용자 상호작용, 데이터 상태, 시스템 설정. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** `preview.py:88`의 치환·확장 경고 검사에 `{`와 `~`를 추가하거나(또는 피연산자에 `{`·`~`가 있을 때 미확장 경고), `_expand`를 실행과 같은 `/bin/bash` 기반으로 맞춘다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The human approval preview card computes file impact by tokenizing the command with shlex and passing operands to container callbacks (_expand and _walk). In sandbox.py:_expand, the pattern is evaluated in container /bin/sh (dash), where positional parameter evaluation does not undergo brace expansion (e.g. {a,b}.txt) or tilde expansion (~/file). When _expand tests existence via [ -e "$p" ], no file literally named "{a,b}.txt" or "/workspace/~/file" exists, returning an empty match list. preview_command (preview.py:110-111) maps this to {'path': op, 'effect': '삭제 시도 (현재 존재하지 않음)'} and appends no warning note. When the human approves the action believing the target does not exist, sandbox.py:425 executes the command via /bin/bash, which performs full brace and tilde expansion and deletes the real files.

**root_cause** The preview command parsing and container path expansion logic diverges from the execution shell. preview_command in preview.py tokenizes commands with POSIX shlex and delegates expansion to _expand, which invokes /bin/sh (dash) with positional argument $1. POSIX dash does not support brace expansion and does not expand tildes within variable expansions, returning empty matches for {a,b} and ~ operands. Furthermore, preview.py:88 warns only on $, `, <(, and eval, failing to flag brace or tilde characters. The system erroneously asserts that targets do not exist rather than warning that shell expansion could not be calculated.

**intended_behavior** Approval impact preview should either execute expansion using the same shell (bash) and environment as execution, or detect shell-specific expansion constructs such as { and ~ and add an explicit warning note (notes) that the exact affected files could not be computed automatically, prompting the operator to inspect the raw command before approval.

**trace**

- `agentbox/api.py:305` (entrypoint, call_tool route (POST /sandboxes/{sid}/tools/{tool})) — Agent submits an exec tool request with rm command using brace or tilde expansion under its own sandbox token.
- `agentbox/service.py:354` (propagation, AgentBox._call_tool) — Policy routes destructive command to require_approval and invokes _preview.
- `agentbox/sandbox.py:595` (propagation, SandboxManager.preview) — Delegates to preview_command with container callbacks _expand and _walk.
- `agentbox/preview.py:109` (propagation, preview_command) — Iterates over rm operands and invokes expand(op) for brace/tilde pattern.
- `agentbox/sandbox.py:578` (propagation, SandboxManager._expand) — Runs /bin/sh (dash) script where $1 does not undergo brace or tilde expansion, returning empty match list.
- `agentbox/preview.py:111` (propagation, preview_command) — Appends '삭제 시도 (현재 존재하지 않음)' to affected list; line 88 checks only $, `, <(, and eval, so notes remains empty.
- `agentbox/templates/_approvals.html:14` (propagation, _approvals.html template) — Operator sees approval card listing target as '현재 존재하지 않음' with no warning note and no del deletion styling.
- `agentbox/sandbox.py:425` (sink, SandboxManager.exec) — Upon human approval, command executes via /bin/bash where brace and tilde expansions occur, deleting the existing files.

**conditions**

- authentication_level: A valid agent token for the sandbox (assumed prompt-injected) capable of submitting exec tool requests.
- user_interaction: Human operator approves the pending exec request relying on the inaccurate system-computed impact card showing nonexistent targets.
- data_state: Target files exist in /workspace (e.g. a.txt, b.txt) or agent home directory, and command specifies them using shell brace expansion or tilde expansion.
- system_configuration: Default policy routes exec commands containing rm to require_approval.

**execution.attacker_perspective** Prompt-injected agent submits exec tool call POST /sandboxes/{sid}/tools/exec with command 'rm {a,b}.txt' or 'rm ~/target.txt' where target files exist in /workspace or home directory.

**execution.instructions**

1. Create existing files 'a.txt' and 'b.txt' in /workspace.
2. Run preview_command('rm {a,b}.txt', 200, expand, walk) with container _expand callback.
3. Observe affected table: [{'path': '{a,b}.txt', 'effect': '삭제 시도 (현재 존재하지 않음)'}] with notes: [].
4. Execute command via /bin/bash as done in SandboxManager.exec and observe that 'a.txt' and 'b.txt' are deleted.

**execution.observed_result** Preview reported affected: [{'path': '{a,b}.txt', 'effect': '삭제 시도 (현재 존재하지 않음)'}] with notes: []. Bash execution deleted both a.txt and b.txt, confirming the approval preview misreports real deletion targets as nonexistent without any warning.

**remediation.strategy** In preview.py:88, include '{' and '~' in the check for shell substitution/expansion constructs, and warn the operator that shell-specific expansion cannot be automatically calculated so the command text must be inspected manually before approval.

`agentbox/preview.py`:

```python
    if any(s in command for s in ("$", "`", "<(", "eval ", "{", "~")):
        notes.append("변수·명령 치환이나 중괄호·틸드 확장이 있어 실제로 무엇이 실행될지 자동 계산이 정확하지 않을 수 있음. 명령 원문을 확인할 것.")
```

</details>
