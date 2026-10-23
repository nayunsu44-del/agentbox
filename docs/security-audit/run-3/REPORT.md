# agentbox 보안 감사 보고서 (run-3)

## 1. 실행 조건과 범위

**이번 감사는 미완료 상태(부분 패스)다.** `findings.json`의 확정·검증 필요 레코드는 모두 3단계 검증과 5단계 재검증을 거쳤다. 보고서를 처음 쓴 뒤 소유자가 예산을 80으로 올려 4차 헌팅을 돌렸고, 그 후보들도 3단계와 5단계를 마쳤다. 4차 뒤 비평(critic-3)이 새 단위 3개를 제안했지만, 남은 예산(3)으로는 헌팅과 검증을 다 할 수 없어 보류했다(`budget_exhausted`). 최종 비평(final-clean critic)도 돌지 않았다. **그래서 커버리지가 깨끗하다고 주장하지 않는다.**

1. **4차 헌팅.** 보류됐던 단위 3개를 헌팅했고, 세 단위 모두 후보를 하나씩 냈다. 세 건 모두 3단계와 5단계를 거쳐 **확정 low**가 됐다(v17, v18, v19, 3절).
   - 5단계 검증자 셋(Sonnet)은 모두 verified를 냈다. 다만 셋 다 도구 호출이 5~6회로 짧았다.
   - 그래서 주된 근거는 3단계 검증과 부모의 실측이다. v19는 parent-live `l12`가 근거이고, v17은 3단계 검증자의 sandbox 실행 결과가 근거다.
2. **부모가 실측한 후보(v16)는 3단계에서 기각했다.** exec가 끝난 뒤 남는 백그라운드 프로세스가 pid 한도를 채운다는 후보였다. 동작 자체는 재현됐다. 하지만 영향이 에이전트 자기 샌드박스 안에 그치고, 사람이 복원으로 완전히 복구할 수 있다(l11). 이 기각 레코드는 `findings.json`에 넣었다.
3. **critic-3이 제안하고 보류한 단위 3개.** 장부에 `deferred`로 남겼다.
   - **인증 전 요청이 하는 일:** 본문 버퍼링과 multipart 임시 파일, noVNC 추출의 Docker 작업, 로그인 실패 때마다 남는 감사 행
   - **GUI 구간 상태의 경쟁:** 이 상태는 도구 스레드와 사람 요청 스레드가 함께 바꾼다. 구간 열기와 유휴 닫기의 순서가 문제이고, 승인 경로(`decide`)가 같은 불변식을 지키는지도 봐야 한다.
   - **디스크나 SQLite가 압박받을 때:** 감사 읽기 경로가 잠금을 오래 쥐는지, 실패했을 때 기록이 사라지거나 승인 상태가 걸려 남는지

| 항목 | 값 |
|---|---|
| 대상 | `nayunsu44-del/agentbox` @ `0e4b958` (`main`의 `8e4db9e`와 `agentbox/`, `images/`, `deploy/`, `tests/`가 같음) |
| 프로필 | `standard`, 범위 = 저장소 전체 |
| 실행 정책 | **sandboxed-source-and-local-only** |
| 예산 | 처음에 부모가 제안한 40개. 소유자가 50, 60, 63, 80으로 올렸다. **77개 사용**(내역은 아래). 이 중 4개는 결과를 내기 전에 멈췄다(사용량 한도 3, 컨테이너 재시작 1) |
| 이전 감사 사용 | run-1(`7fc501f`) 장부와 run-2 실측 결과. 이전 확정 9건은 모두 수정돼 소스가 바뀌었으므로 다시 검증하는 단위로 넣었다(`prior_confirmed_changed_source` 8, `prior_covered_changed_source` 6). 소스가 같아 그대로 넘어온 확정은 없다. run-1에서 기각한 주장 1건(desktop 티켓의 범위)은 소스가 바뀌어 다시 확인했다 |
| `findings.json` | 18건: 확정 11 (high 1 · medium 5 · low 5), 검증 필요 5, 기각 2. `validate-findings.cjs` **PASS** |
| 커버리지 장부 | 29개 단위: covered 8 · candidate 18 · deferred 3 · blocked 0. `validate-coverage-ledger.cjs` **PASS** |

**에이전트 사용 내역(77개).**

| 단계 | 개수 | 내역 |
|---|---|---|
| 정찰 | 4 | |
| 헌터 | 13 | 1차 11, 2차 2 |
| 비평 | 2 | 1차 뒤 1, 2차 뒤 1 |
| 3단계 검증 | 26 | 이전 세션 결과 소실 1, 완료 4, 사용량 한도로 중단 8, 재개 세션 11, 형식 오류로 다시 돌림 2 |
| 5단계 레코드 검증 | 13 | Sonnet |
| 5단계 재확인 | 4 | Opus. 판정이 올라가거나 근거가 크게 바뀐 교체안 대상 |
| 4차 헌팅 이후 | 8 | 헌터 3, 3단계 검증 4(v16 기각 · v17 · 멈춤 2), 4차 뒤 비평 1(멈춤). 모두 Opus |
| 재개 세션 | 7 | 3단계 v18·v19 2, critic-3 2(한 번은 컨테이너 재시작으로 끊김), 5단계 v17~v19 3. 모두 Sonnet |

**실행 경계.**
- **대상 코드를 직접 돌린 경우:** 대상 코드는 부모의 `sbx` 래퍼 안에서만 돌렸다. 네트워크 없음, 루트 파일 시스템 읽기 전용, 대상과 `/usr`는 읽기 전용, 쓰기는 `agents/<id>/scratch`에만 허용했다. uid 65534, 모든 권한 제거, 512 MiB, CPU 1개, pid 64개, 120초 제한이다. 5단계에서는 이후 수정이 섞이지 않도록 감사 대상 소스(`8e4db9e`)를 붙인 `sbx5`를 썼다.
- **실제 Docker가 필요한 경우:** 부모가 이 일회용 클라우드 컨테이너 안에서 가짜 토큰으로, 루프백에서만 돌렸다. 장부에는 `parent-live`로 표시했다. 배포된 서비스, 외부 서비스, 공유 시스템에는 아무것도 보내지 않았다.
- **산출물 승격:** sandbox에서 나온 파일은 부모 쪽 `promote.py`로만 보존 위치에 옮겼다.

## 2. 보안 상태 요약

agentbox의 핵심 통제는 이전 감사 뒤 단단해졌다.
- exec 허용 목록과 `#`·`>` 판정
- 사람 전용 라우트와 세션 범위
- 원자적 승인
- 실패하면 막히는 감사 해시 체인
- 64 KB 출력 상한과 분리된 도구 스레드 풀

이번에 다시 검증한 이전 확정 단위들은 수정이 유지되고 있었다. 이번 확정 건은 대부분 **사람의 감독 장치를 흐리게 하는 문제**다. 감독 장치가 사람이 보는 화면, 감사 기록, 사람의 개입 수단 중 어디인지에 따라 나누면 이렇다.

- **사람이 보는 화면:**
  - 웹 승인 카드가 유니코드 방향 제어 문자로 다른 명령처럼 보인다(v13).
  - 감사 타임라인이 5000번째 행에서 멈춘다(v02).
  - `agentbox agent` 출력이 제어 문자를 그대로 낸다(v03).
  - 승인 카드의 영향 표가 `rm`과 섞인 다른 명령 조각을 경고 없이 빠뜨린다(v17).
- **감사 기록:**
  - 지울 수 없는 감사 로그에 크기 제한 없이 큰 행이 쌓인다(v08).
  - GUI 구간 기록이 복원과 일시정지 때 사라진다(v12).
  - GUI 터미널로 `/home/desktop`의 autostart에 써 둔 것이 기록에 남지 않는다. 스냅샷에 들어갔다가 복원한 뒤 uid 1001로 다시 실행된다(v19).
- **사람의 개입 수단:**
  - 한 샌드박스의 X가 멈추면, 다른 샌드박스의 도구 호출과 사람의 승인·감사 요청이 제한 시간 없이 막힌다(v11, high).
  - 토큰을 바꿔도 예전 브라우저 세션이 살아 있다(v05).
  - 원본 폴더 겹침 검사를 별칭으로 우회하면 사람 토큰이 에이전트에게 넘어간다(v06, 운영자 실수가 필요해 low).
- **호스트 자원:** 승인 요청마다 화면 캡처 PNG가 호스트에 남고 지워지지 않는다. 승인 대기 수에도 상한이 없다(v18).

GUI 도구는 설계상 승인을 거치지 않는다(N-1). 이를 보완하는 장치(구간 스냅샷, `gui_changes`, 정리 kill)에 남은 빈틈은 검증 필요로 넘겼다(v09, v10, v15).

## 3. 확정 결과

| 심각도 | ID | 제목 | 경계 | 관찰 결과 (한 줄) | 수정 |
|---|---|---|---|---|---|
| **high** | v11 | 유휴 GUI 구간 닫기가 남의 샌드박스 스레드와 사람 승인·감사 스레드에서 제한 시간 없는 docker exec로 돎 | 에이전트(샌드박스 B) → 다른 샌드박스와 사람의 가용성 | B의 Xvfb를 멈추자 A의 `list_dir`가 20초 넘게 막혔고, Xvfb를 재개한 뒤 0.3초 만에 돌아옴(parent-live l2) | `c1f88da` |
| **medium** | v02 | UI·CLI 감사 타임라인이 가장 오래된 5000행에서 멈춤 | 에이전트 → 사람의 감사 확인 | 5012행에서 UI는 4601~5000번만 보였고 하단에는 "최근 400개"라고 표시. CLI는 1~5000번만 출력 | `3587c9c` |
| **medium** | v05 | 사람 토큰을 바꿔도 기존 브라우저 세션이 12시간 유지 | 예전 운영자 → 관리자 UI | 토큰 교체와 재시작 뒤 옛 토큰은 401인데, 옛 쿠키로는 승인 거절이 실행돼 감사에 남음 | `3587c9c` |
| **medium** | v08 | 도구 인자가 크기 제한 없이 지울 수 없는 감사 로그에 기록 | 에이전트 → 공유 감사 DB | 3 MiB 인자가 그대로 한 행이 됨. UPDATE·DELETE는 트리거가 막고, verify·list가 전부 다시 읽음 | `e63922c` |
| **medium** | v12 | 복원·일시정지 때 GUI 구간의 정리 kill과 `gui_changes` 기록이 사라짐 | 에이전트 → GUI 보완 장치(N-1) | 복원 뒤 남은 백그라운드 프로세스가 죽지 않았고 `gui_changes`도 없었음. 낡은 기준으로는 새 데스크톱의 프로세스를 죽이기도 함 | `c1f88da` |
| **medium** | v13 | 웹 승인 카드가 exec 명령의 유니코드 방향 제어 문자를 그대로 표시 | 에이전트 → 사람의 승인 판단 | Chromium에서 `; python3 /workspace/job.py ;`가 앞의 `echo` 따옴표 안에 든 것처럼 보임(parent-live l5) | `c1f88da` |
| **low** | v03 | `agentbox agent`가 파일 내용·파일 이름·모델 출력을 제어 문자 그대로 터미널에 출력 | 문서·파일 작성자 → 운영자 터미널 기록 | pyte 화면에서 `→ read_file(...)` 줄이 지워지고 가짜 `[사용자]` 줄이 나타남 | `28fd4c9` |
| **low** | v06 | `source_dir` 겹침 검사가 파일 시스템 실체가 아니라 경로 문자열을 비교 | 운영자 실수 → 사람 토큰이 에이전트에게 노출 | 바인드 마운트 별칭은 받아들여졌고, 에이전트의 `read_file`이 진짜 사람 토큰을 돌려줌. 원래 경로는 거부됨(parent-live l8) | `152b8e4`, 남은 틈은 `28fd4c9` |
| **low** | v17 | 승인 카드 영향 표가 `rm`/`curl`이 아닌 조각을 빼고, `rm`이 있으면 "계산 못 함" 경고도 사라짐 | 에이전트 → 사람의 승인 판단 | `rm a; mv important.db /tmp/gone`의 영향이 `a 삭제` 한 줄, 경고 없음. `mv`만 단독이면 경고가 나옴(v17 sbx 실행) | `e0add14` |
| **low** | v18 | 승인 요청마다 호스트에 캡처 PNG가 남고 지워지지 않으며, 승인 대기 수에 상한이 없음 | 에이전트 → 호스트 디스크 | 대기 30건에 PNG 30개. 거절 1건과 만료 29건 뒤에도 30개가 모두 남음(v18 sbx 실행, 화면은 stub) | `e0add14` |
| **low** | v19 | GUI로 `/home/desktop/.config/autostart`에 쓴 파일이 `gui_changes`에 없고, 스냅샷을 거쳐 복원 뒤 uid 1001로 다시 실행됨 | 에이전트 → GUI 보완 장치와 복원 지점 | 에이전트 GUI 도구만으로 쓰고, 사람이 스냅샷·복원하자 `/workspace/PROOF_autostart.txt`(내용 1001)가 생김(parent-live l12) | `e0add14` |

medium 이상 6건의 전체 경로, 근거, 재현, 수정 방향은 [`FINDINGS-DETAIL.md`](FINDINGS-DETAIL.md)에 레코드 그대로 옮겼다. 아래에는 건별로 요약한다.

### 3.1 [high] v11 — 유휴 GUI 구간 닫기가 다른 호출자 스레드에서 제한 시간 없이 돎
- **위치:**
  - `agentbox/service.py:273`: `call_tool`이 샌드박스별 동시 실행 검사(275-278)보다 먼저 `close_idle_gui_bursts()`를 부른다.
  - `service.py:254-256`: 모든 샌드박스의 구간을 돈다.
  - `service.py:373`: `expire_stale`. GET/POST approvals와 decide에서 불린다.
  - `api.py:258`: GET /audit.
  - 실행 지점: `sandbox.py:684/690-691`(xdotool), `499`(find), `697`(kill). 모두 `exec_run`이고 제한 시간이 없다.
- **낮은 신뢰 주체:** 자기 데스크톱 샌드박스 B를 가진 프롬프트 주입 에이전트. 피해자는 다른 샌드박스의 에이전트와 사람 운영자다.
- **재현:**
  - parent-live `l2_cross`: B의 구간이 유휴인 상태에서 B의 Xvfb를 멈추면, A의 `list_dir`가 20초 넘게 돌아오지 않는다.
  - parent-live `l10`: 같은 조건에서 150초가 지나도 막혀 있었다. docker 클라이언트 쪽 상한도 없다.
  - `h-pool` stub: B의 닫기 작업이 A의 스레드와 사람의 `expire_stale` 스레드에서 돌고, B의 `_busy`는 0으로 남는다.
- **영향:** 한 컨테이너가 응답하지 않으면, 상관없는 샌드박스의 도구 호출과 사람의 승인 결정·감사 조회가 무기한 막힌다. 구간은 닫기 전에 목록에서 빠지므로, 막힌 구간 하나가 호출자 스레드 하나를 계속 잡아 둔다.
- **우선순위 근거:** 에이전트 혼자 일으킬 수 있다. Xvfb가 uid 1001이라 GUI 터미널에서 멈출 수 있다(N-1 경로). 그리고 사람의 감독 경로까지 막힌다.
- **가장 작은 수정:**
  - 구간 닫기와 GUI 경로의 모든 docker exec에 컨테이너 쪽 `timeout -k`를 씌운다. exec, read_file, outbox_read는 이미 그렇게 한다.
  - 구간 닫기를 호출자 스레드에서 떼어 별도 백그라운드 작업으로 옮기거나, 해당 샌드박스의 예산에서 쓰게 한다.
- **수정:** `c1f88da`.
  - 화면(X)과 구간 기록에 쓰는 exec(`_x`, `desktop_processes`, `kill_processes`, `workspace_manifest`)를 모두 컨테이너 쪽 `timeout -k`로 감쌌다. 기본 15초이고, `type`은 글자 수만큼 늘린다. 시간이 초과되면 반쯤 받은 결과를 쓰지 않고 실패로 돌린다.
  - 유휴 구간 닫기는 전용 스레드 4개(`agentbox-burst`)에서 돈다. 도구 호출, 승인 조회, `expire_stale`은 닫기를 넣기만 하고 바로 돌아간다. 감사 로그 조회는 최대 5초까지 기다린다.
  - 회귀 테스트: `tests/test_m2_unit.py::test_idle_burst_close_does_not_run_on_caller_thread`, `test_gui_execs_have_a_container_side_deadline`, `tests/test_m2_acceptance.py::test_frozen_display_does_not_hold_tools_or_takeover`. 마지막 테스트는 실제 데스크톱에서 Xvfb를 멈추고 돌린다.

### 3.2 [medium] v02 — 감사 타임라인이 오래된 5000행에서 멈춤
- **위치:** `audit.py:190-197`(`ORDER BY id LIMIT`), `web.py:262-263`(`rows[-400:]`, `total=len(rows)`), `cli.py`의 `cmd_audit`(limit=5000, `after_id` 없음).
- **주체:** 에이전트 토큰. 승인 없이 행을 만들 수 있다. 예를 들어 `approval_forbidden`은 요청 1번에 1행, `list_dir`는 호출 1번에 3행이다.
- **결과:** 5000행을 넘기면 그 뒤의 `tool_request`, `snapshot`, `gui_processes_stopped`, `gui_changes`가 사람 화면에 나오지 않는다. 그런데 하단에는 여전히 "최근 400개"라고 표시된다.
- **수정:** `3587c9c`. `AuditLog.recent()`로 최신 400건과 실제 총계를 보여 주고, CLI는 `after_id`로 끝까지 읽는다. 검증 화면은 한 줄 조회로 바꿨다.

### 3.3 [medium] v05 — 토큰을 바꿔도 브라우저 세션이 유지됨
- **위치:** `desktop.py:35-37`(세션에 토큰 계보 열 없음), `91-93`, `133-145`, `127-131`(한 번에 하나만 지움).
- **주체:** 교체 전에 받은 `'*'` 세션 쿠키를 가진 사람. 예를 들면 예전 운영자다.
- **결과:** 토큰 교체와 재시작 뒤 옛 토큰은 401이다. 하지만 옛 쿠키로는 `/ui/*`가 200을 돌려주고, 승인 결정도 실행됐다.
- **수정:** `3587c9c`. 세션과 티켓에 사람 토큰 지문(PBKDF2)을 저장한다. 토큰을 바꾸고 재시작하면 예전 세션과 티켓이 전부 무효가 된다. 지문 열이 없던 DB의 세션은 한 번 모두 버린다.

### 3.4 [medium] v08 — 도구 인자가 크기 제한 없이 감사에 남음
- **위치:** `service.py:131-137`(`_logged_args`), `297-298`(정책 판단 전에 기록), `audit.py:176`(INSERT), `audit.py:35-38`(UPDATE·DELETE 금지 트리거).
- **결과:** 3 MiB짜리 인자 한 번이 지울 수 없는 행 하나가 된다. `verify()`와 `/ui/verify`가 전부 다시 읽는다.
- **수정:** `e63922c`. JSON 64 KiB가 넘으면 앞 16 KiB와 크기·sha256만 남긴다.
  - 5단계 검증자가 원래 레코드의 수정안 결함을 찾았다. 수정안은 `write_file` 분기에서 먼저 반환하기 때문에, `write_file`에 큰 추가 키를 넣으면 제한을 비켜 갔다. 이에 맞춰 수정 방향을 고쳤다.
  - 커밋한 수정은 내용 제거를 먼저 하고 크기 제한을 그 뒤에 걸기 때문에, 이 경우도 막는다.

### 3.5 [medium] v12 — 복원·일시정지 때 GUI 구간 상태가 사라짐
- **위치:**
  - `service.py:529-537`(`end_desktop`): 구간은 닫지만 `_gui_input_at`과 `_gui_snap_at`을 남긴다.
  - `service.py:195-197`: 그 때문에 새 구간이 열리지 않는다.
  - `api.py:166-176`: pause와 resume가 구간 상태를 건드리지 않는다.
  - `service.py:232`: 정리하기 전에 구간을 버린다.
- **결과:**
  - 복원 뒤 GUI 입력이 스냅샷도, 구간도 만들지 않는다. 그동안 남은 백그라운드 프로세스는 죽지 않고 `gui_changes`도 남지 않는다.
  - 일시정지 중에 유휴로 닫히면 구간이 사라진다.
  - 옛 컨테이너의 기준으로 닫으면 새 컨테이너의 uid 1001 프로세스를 전부 죽인다.
- **수정:** `c1f88da`.
  - 일시정지 전에 구간을 닫고, 일시정지·재개·복원·삭제 때 구간 타이머를 지운다(`end_gui_burst`, `reset_gui_timers`). 그래서 바로 다음 GUI 입력이 스냅샷을 뜨고 새 구간을 연다.
  - 구간에 `container_id`를 기록한다. 컨테이너가 바뀐 구간은 아무것도 죽이지 않는다.
  - 정리나 비교에 실패하면 `gui_burst_close_failed`를 남긴다. 실패한 구간을 조용히 버리지 않는다.
  - 회귀 테스트: `tests/test_m2_acceptance.py::test_gui_burst_restarts_after_pause_and_restore`, `tests/test_m2_unit.py::test_lifecycle_change_resets_gui_burst_timers`, `test_burst_from_replaced_container_kills_nothing`, `test_failed_burst_close_is_logged_not_dropped_silently`.

### 3.6 [medium] v13 — 웹 승인 카드의 방향 제어 문자
- **위치:**
  - `templates/_approvals.html:8`: HTML 이스케이프만 한다.
  - 터미널은 `cli._safe`(`cli.py:34-39`, `196-199`)로 막는데, 웹 쪽에는 같은 필터가 없다.
- **주체:** 프롬프트 주입 에이전트. 허용 목록에 없는 프로그램을 승인 받으려 한다.
- **결과:** U+2067/U+2069로 명령의 표시 순서를 바꾸면, 사람이 보는 카드는 무해한 `echo`처럼 보인다. 그런데 승인하면 `python3 /workspace/job.py`가 실행된다. 확인은 parent-live Chromium(`l5_card.png`)으로 했다.
- **수정:** `c1f88da`.
  - 웹 템플릿 환경에 `finalize`를 걸었다. 그래서 모든 `{{ }}` 출력에서 `cli._UNSAFE`와 같은 문자(C0·DEL·C1, bidi 제어)가 `\u2067` 같은 보이는 이스케이프로 바뀐다. 줄바꿈과 탭은 그대로 둔다.
  - 템플릿마다 필터를 다는 방식이 아니어서, 새 템플릿이나 필드에서 빠뜨릴 수 없다.
  - 회귀 테스트: `tests/test_m3_acceptance.py::test_web_approval_neutralises_bidi_controls`. 승인 화면과 감사 화면을 함께 본다.

### 3.7 [low] v03 — `agentbox agent` 터미널 출력의 제어 문자
- **위치:** `cli.py:353-361`(`cmd_agent.log`), `agent.py:116-126`(read_file·list_dir 결과를 그대로 넘김).
- **주체:** agentbox 자격 증명 없이, 운영자가 넘긴 폴더 안의 문서나 파일 이름을 고를 수 있는 사람.
- **결과:** 운영자 터미널 기록에서 도구 호출 줄이 지워지고 가짜 `[사용자]` 줄이 생긴다(pyte 화면 기준).
  - 승인은 `_safe`를 쓰는 `agentbox approve`로 하고 감사 기록은 정확하므로, 영향은 화면 표시에 그친다(low).
  - 클립보드(OSC 52)와 실제 터미널 에뮬레이터에서의 동작은 시험하지 않았다.
- **수정:** `28fd4c9`. `cmd_agent.log`가 찍는 모델 글과 도구 결과에 줄마다 `_safe`를 건다. 줄바꿈만 남는다. 회귀 테스트: `tests/test_unit.py::test_agent_log_neutralises_container_output`.

### 3.8 [low] v06 — `source_dir` 겹침 검사를 별칭으로 우회
- **위치:** `sandbox.py:398`(`resolve()`는 철자를 유지), `403-404`(문자열 비교), `421-422`(root가 `cp -a`로 복사하고 chown).
- **주체:** 원본 폴더를 정하는 것은 사람 운영자뿐이다. 에이전트는 결과만 받는다.
- **결과:** parent-live `l8`. 프로젝트 폴더를 바인드 마운트한 별칭(같은 inode, 심볼릭 링크 아님)은 받아들여졌고, 에이전트의 `read_file /workspace/data/human_token`이 진짜 사람 토큰을 돌려줬다. 원래 경로는 거부됐다. 대소문자를 구분하지 않는 WSL2 drvfs의 다른 철자도 그럴듯한 경로지만, 관찰하지는 못했다.
- **심각도:** 영향은 high(사람 권한 전체)지만, 운영자의 드문 실수가 있어야 해서 likelihood가 low다. 그래서 overall은 low다.
  - 이 레코드는 3단계에서 검증 필요였다. 5단계에서 l8을 근거로 확정으로 올렸고, 다른 검증자가 재확인했다.
- **수정:** `152b8e4`(`os.path.samefile`로 조상까지 비교). 재확인 검증자가 남은 틈을 하나 지적했다. 원본 폴더 *안쪽에* 데이터 폴더가 마운트돼 있으면, 이 수정으로도 `cp -a`가 그것을 복사한다.
  - `28fd4c9`에서 원본 폴더를 `NonRecursive` 바인드로 붙이게 바꿨다. 그래서 안쪽 마운트는 컨테이너에 보이지 않는다.
  - 처음 고려한 `cp -ax`는 막지 못했다. 같은 디스크의 바인드 마운트는 장치 번호가 같기 때문이다. 이것은 테스트로 확인했다.
  - 회귀 테스트: `tests/test_m4_acceptance.py::test_nested_mount_under_source_not_copied`. 실제 중첩 바인드 마운트로 돌린다.

### 3.9 [low] v17 — 승인 카드 영향 표가 조각을 빠뜨림
- **위치:** `sandbox.py`의 `preview`. `rm`과 `curl`만 계산하고, "계산 못 함" 경고는 표가 통째로 비었을 때만 붙인다.
- **주체:** 프롬프트 주입 에이전트. 혼자서는 못 하는 삭제나 이름 바꾸기를 사람의 승인으로 실행하게 하려 한다.
- **결과:** `rm`이 하나라도 있는 복합 명령에서는 다른 조각(`mv`, `find -delete`)이 표에도, 경고에도 나오지 않는다. 그런 조각만 단독으로 내면 경고가 나온다. 명령 원문은 표 위에 그대로 보이고, 실행 전에 AP-2 스냅샷도 뜨므로 low다.
- **수정:** `e0add14`. `rm`·`curl`이 아닌 조각마다 "자동 계산하지 못함" 경고를 단다. `sudo`처럼 감싸는 명령이면 안쪽 조각을 본다. 회귀 테스트: `tests/test_m4_acceptance.py::test_preview_flags_every_unmodeled_segment`.

### 3.10 [low] v18 — 승인 캡처 PNG가 쌓임
- **위치:** `service.py`의 `_call_tool`이 데스크톱 샌드박스의 승인 요청마다 `captures/<id>.png`를 쓴다. 이 파일을 지우는 경로가 없고, 대기 수에도 상한이 없다.
- **결과:** 에이전트가 승인이 필요한 호출을 반복하면 호스트 디스크가 조금씩 찬다. 거절·만료되거나 샌드박스를 지워도 파일이 남는다. 운영자가 파일을 지우면 복구되므로 low다.
- **수정:** `e0add14`.
  - 캡처는 결정·만료·샌드박스 삭제 때 지운다. 감사 로그에는 sha256과 크기가 남는다.
  - 승인 대기는 샌드박스마다 20개까지다. 넘으면 429를 주고 `tool_blocked`(`too_many_pending_approvals`)를 남긴다.
  - 회귀 테스트: `tests/test_m3_acceptance.py::test_approval_captures_reclaimed_and_pending_capped`.

### 3.11 [low] v19 — 화면 계정 홈에 써 둔 autostart가 복원 뒤 다시 실행됨
- **위치:**
  - `workspace_manifest`는 `/workspace`만 보고, 정리 kill은 프로세스만 멈춘다.
  - `docker commit`은 `/home/desktop`까지 담는다.
  - 복원하면 `agentbox-desktop-start`가 `startxfce4`를 uid 1001로 다시 띄운다.
- **결과:** parent-live `l12`. 에이전트가 GUI 도구만으로 터미널을 열어 `~/.config/autostart/t.desktop`을 썼다. 감사 기록에는 그 흔적이 없었다. 사람이 스냅샷을 뜨고 복원하자, 그 명령이 구간 밖에서 uid 1001로 실행됐다. GUI 입력은 설계상 승인을 거치지 않고(N-1) 컨테이너 경계도 넘지 않으므로 low다.
- **수정:** `e0add14`.
  - 데스크톱 이미지가 화면 계정 홈의 처음 상태를 root 소유로 보관한다. 컨테이너가 시작할 때마다(만들기·복원) `/home/desktop`을 그 상태로 되돌린다.
  - 회귀 테스트: `tests/test_m2_acceptance.py::test_desktop_home_reset_on_restore`. autostart와 `.bashrc`를 함께 본다. 이전 이미지에서는 실패하는 것을 확인했다.

## 4. 검증 필요 (확정 아님, 심각도 없음)

전체 내용은 [`NEEDS-VALIDATION.md`](NEEDS-VALIDATION.md)에 있다.

| 순위 | ID | 제목 | 경로 | 막혀 있는 사실 | 로컬 다음 단계 | 운영자 관찰 |
|---|---|---|---|---|---|---|
| 1 | v10 | X가 멈추면 GUI 도구가 `gui_lock`을 쥔 채 무기한 → 사람의 화면 인수가 막힘 | `api.py:205` → `service.py:106` → `sandbox.py:684` → `service.py:464` | 에이전트가 자기 GUI 호출만으로 X를 멈출 수 있는가. l10은 docker exec(uid 1001)로 대신 멈췄음. 막히는 시간에 상한이 없다는 점은 l10이 보여 줌 | 에이전트 토큰의 `key`/`type`만으로 터미널을 열어 `kill -STOP`을 보내고, 화면 인수가 60초 안에 돌아오는지 측정 | (로컬 계획만 적용) |
| 2 | v09 | GUI 구간을 열 때 수집이 실패해도 성공으로 처리(빈 기준, 기록 없음) | `api.py:205` → `service.py:339` → `264` → `sandbox.py:501` → `service.py:212` | 에이전트만의 순서로, 실제 GUI 변경이 있는데도 `gui_changes`가 틀리거나 아예 없는 끝 상태가 되는가. l9에서는 부하가 풀리지 않아 닫기 기록 자체가 없었음 | 부하를 풀거나 여유를 남긴 상태에서 GUI로만 변경하고 `gui_changes`를 확인. 대조군은 added=1 | 배포 설정값(pids, exec timeout, GUI idle)으로 사람의 타임라인에 기준 손실 표시가 나오는지 확인 |
| 3 | v15 | `gui_strays`가 창 소유(클라이언트가 정하는 `_NET_WM_PID` 포함)로 정리 대상에서 뺌 | `service.py:215` → `sandbox.py:690` → `sandbox.py:221` | 실제 이미지에서 GUI 입력만으로, 구간 시작 세션에 창이 있는(또는 새 창 앱의 자식인) 프로세스를 남길 수 있는가 | 구간 중 파일 관리자에서 스크립트를 실행하고, 구간이 닫힌 뒤에도 `/workspace/_v15_probe`의 mtime이 계속 바뀌는지 확인 | 배포 이미지에서 같은 탐침으로 세션 ID와 창 PID 동작을 확인 |
| 4 | v14 | 쿠키 인증 UI에 frame-ancestors/X-Frame-Options가 없음 → 같은 사이트 출처가 framing해 클릭 한 번으로 승인 | `web.py:181` → … → `service.py:415` | 배포에 공격자가 영향을 줄 수 있는 같은 사이트 출처(같은 루프백 호스트의 다른 포트, 형제 서브도메인)가 있는가. Firefox와 WebKit 동작 | Firefox와 WebKit에서 l3 재현 반복, 수정 후 회귀 확인 | 배포의 같은 사이트 출처 목록 확인 |
| 5 | v01 | `same_origin`이 scheme을 비교하지 않음 | `web.py:203` → `api.py:119` → `api.py:110` → `web.py:209` | schemeful same-site가 없는 운영자 브라우저가 있는가(Chromium 141은 쿠키를 보내지 않았음, l4). HSTS와 경로상 공격자가 범위에 드는가 | Firefox와 WebKit에서 http→https 교차 scheme POST 시험 | 운영 호스트의 HSTS(또는 preload) 여부와 운영자 브라우저 종류 확인 |

이 브랜치에서 판정과 상관없이 먼저 막아 둔 것이 세 건 있다. 감사 대상 소스는 바뀌지 않았고, 판정도 그대로 needs_validation이다.

- **v10 (`c1f88da`):** GUI exec에 컨테이너 쪽 제한 시간이 걸린다. 인수와 반환은 `gui_lock`을 최대 30초까지만 기다리고, 넘으면 503을 준다. 인수를 기다리는 동안과 그 뒤 60초 동안은 에이전트의 GUI 도구를 새로 돌리지 않는다(423). 그래서 다시 누르면 인수된다. 테스트: `tests/test_m2_unit.py::test_takeover_waits_bounded_and_stops_new_agent_gui_calls`, `tests/test_m2_acceptance.py::test_frozen_display_does_not_hold_tools_or_takeover`.
- **v09 (`c1f88da`, 일부):** 파일 목록과 프로세스 목록 exec의 종료 코드를 확인한다. 기준을 못 읽으면 빈 기준으로 구간을 열지 않고 `gui_burst_open_failed`를 남긴다. 닫기에 실패하면 `gui_burst_close_failed`를 남긴다. 테스트: `tests/test_m2_unit.py::test_failed_burst_baseline_is_logged`.
  - 병합 뒤 후속 변경에서 fail-closed로 바꿨다. 기준을 못 읽으면 그 GUI 입력은 실행하지 않고 503을 준다. 다음 입력이 다시 스냅샷을 뜨고 구간을 연다. 테스트: `tests/test_m2_unit.py::test_gui_input_refused_when_burst_baseline_unreadable`, `tests/test_m2_acceptance.py::test_gui_input_refused_without_burst_baseline`.
- **v14 (`28fd4c9`):** 모든 HTTP 응답에 `X-Frame-Options: SAMEORIGIN`과 `Content-Security-Policy: frame-ancestors 'self'`를 붙인다. 같은 출처의 데스크톱 iframe은 그대로 된다. 테스트: `tests/test_m4_acceptance.py::test_ui_refuses_framing`.

## 5. 보강 메모와 좋은 패턴

**소스에서 확인된 좋은 패턴(발견 사항 아님):**
- 감사 행은 에이전트가 고치거나 지우거나 순서를 바꿀 수 없다. 기록 경로가 하나뿐이고 UPDATE·DELETE 트리거가 막는다.
- 에이전트가 넣은 JSON으로 `verify()`가 거짓 손상을 보고하게 만들 수 없다.
- 에이전트가 넣은 문자열이 다른 이벤트나 행으로 보이지 않는다. UI는 autoescape, CLI는 `_safe`를 쓴다.
- `mask_text`는 에이전트 입력에 대해 선형 시간으로 돈다.
- 데스크톱 WebSocket은 교차 출처 핸드셰이크, 다른 샌드박스의 쿠키, 리스(lease) 없는 제어를 거부한다. 보기 연결로는 입력할 수 없다.
- 로그아웃하거나 세션이 만료되면 화면 연결이 끊기고 리스가 반환된다.
- run-1에서 기각한 주장을 다시 확인했다. 샌드박스 범위 티켓으로 만든 세션은 `'*'` 세션처럼 행동할 수 없다.
- 로그인 CSRF나 티켓 교환으로 피해자를 공격자 세션에 묶을 수 없다. Host나 forwarded 헤더로 자격 증명을 다른 곳으로 보낼 수 없다.
- 이전 확정 건의 수정이 유지되고 있다. 다시 검증한 단위 중 approvals, write/delete/GUI 스냅샷, 파일 도구는 covered다.

**보강 메모(지금 경계를 넘는 경로는 없음, 심층 방어):**
- 모든 컨테이너 exec에 제한 시간을 둔다.
  - `exists`/`is_dir`, preview의 `_expand`/`_walk`, screenshot에 상한이 없다.
  - 클라이언트가 연결을 끊어도 `tool_pool` 작업이 취소되지 않는다.
- 정책:
  - 프로그램 이름을 basename으로 줄인다(`./ls`도 허용됨).
  - YAML의 `true`/`false`가 불리언으로 읽혀 실제로는 허용 목록에 없다.
  - `file -C`와 `touch -d`를 허용한다.
  - 승인 preview가 만든 시점 기준이라 실행 전에 낡을 수 있다.
- 감사:
  - `mask_text`가 놓치는 형식이 있다. URL 인코딩, 전각 문자, `hf_`/`npm_` 토큰, 단어 문자 바로 뒤의 `agt_`/`hum_`이다.
  - 500자에서 자른 뒤에 가린다.
  - 키 없는 SHA-256 체인이다. 체인 끝을 외부에 두거나 HMAC을 쓴다.
  - `append`가 `AuditWriteError`가 아닌 예외를 그대로 내보낸다.
- 세션:
  - `hs_` 공개 ID가 32비트이고 UNIQUE 제약이 없다.
  - 루프백 plain http 모드의 쿠키는 Secure가 아니고 포트별로 나뉘지 않는다.
  - 티켓을 GET으로 교환한다.
  - 세션당 데스크톱 WebSocket 수에 상한이 없다.
- 웹:
  - 같은 사이트의 Origin 없는 GET에 부작용이 있다(`file_exported`, `audit_verified`).
  - `/login`에 속도 제한이 없다.
  - TrustedHost 설정과 HSTS가 없다.
  - `capture.png`에 `nosniff`가 없다.
  - `cli._safe`가 U+061C를 놓친다.
- 배포:
  - `create_app()` 팩토리를 쓰면 `bind_problem`, TLS, runtime 검사를 건너뛴다.
  - `AGENTBOX_TRUSTED_PROXIES`의 기본값이 `*`이다.
  - `AGENTBOX_BEHIND_TLS_PROXY=1`이 환경에 있으면 평문 바인드 거부가 조용히 꺼진다.
  - `/healthz`가 이미지, 템플릿, runtime을 노출한다.
  - noVNC 클라이언트를 인증 없이 제공한다.
- 기타:
  - `GET /sandboxes/{sid}`가 호스트의 `source_dir` 절대 경로를 에이전트에게 준다.
  - `agentbox agent`가 LLM 키를 plain http 주소에도 보낸다.
  - `outbox_read`가 크기 검사 전에 최대 50 MiB를 버퍼에 담는다.
  - 일시정지된 샌드박스도 스냅샷을 만든다.
  - `restore`와 `delete`가 `gui_lock`/`_snap_locks`를 잡지 않는다.

**참고(기각 2건):** v16(`agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion`)은 위 1절에 적었다. 나머지 1건은 다음과 같다. `agentbox/cli.py:runtime_problem:runc-alias-io.containerd.runc.v2-bypasses-exposed-runc-guard`는 동작 자체는 재현됐다. 하지만 runtime을 고르는 사람은 운영자뿐이라 신뢰 경계를 넘지 않는다. 다음 감사가 같은 주장을 반복하지 않도록 기록으로 남긴다.

## 6. 커버리지 요약

- **장부 29개 단위:** covered 8, candidate 18, deferred 3, blocked 0, out_of_scope 0.
  - candidate 18개는 모두 `findings.json` 레코드와 연결된다.
  - deferred 3개는 critic-3이 제안하고 예산 때문에 보류한 단위다(1절).
- **동반 지침:** RESOURCE-EXHAUSTION, AI-AND-LLM, WEB-PROTOCOL-AND-AUTH, CLIENT-SIDE, DESKTOP-MOBILE-AND-LOCAL-IPC, CLOUD-AND-DEPLOYMENT, DATA-ISOLATION-AND-LIFECYCLE.
- **이유를 적고 뺀 지침:**
  - MEMORY-SAFETY: 네이티브 코드가 없음
  - SUPPLY-CHAIN: 배포·서명 경로가 없고 CI는 테스트만 돌림
  - PROTOCOLS: HTTP/WS/MCP stdio 외의 broker나 RPC가 없음
- **비평:**
  - 1차 뒤 비평(critic-1)과 2차 뒤 비평(critic-2)이 돌았다. critic-2가 제안한 단위 3개는 4차 헌팅에서 맡았다.
  - 4차 뒤 비평(critic-3)은 새 단위 3개를 내며 `stop: false`라고 했다. 그 단위들을 헌팅하지 못했고 최종 비평도 돌지 않았다. **그래서 깨끗한 커버리지를 주장하지 않는다.**
  - critic-3은 부모가 실측한 후보(v16)를 해결된 것으로 보았다.
- **다음 감사에서 할 일:**
  - 보류한 단위 3개의 헌팅과 검증, 그다음 최종 비평
  - 검증 필요 5건의 로컬 계획
  - 이번 수정(`c1f88da`, `28fd4c9`, `e0add14`)이 바꾼 소스를 다시 검증하는 단위
