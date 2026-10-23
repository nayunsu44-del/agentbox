# agentbox 리팩토링 플랜 (구조 정리만, 동작 그대로)

## Context
run-3 감사와 수정이 main에 들어갔다(PR #8 `5decb11`, #9 `f497c86`). 이제 다음 감사(run-4)보다 코드 구조 정리를 먼저 한다.

수정하면서 같은 보안 로직을 두 군데씩 고쳐야 하는 일이 반복됐다.
- 복원·삭제 흐름이 `api.py`와 `web.py`에 따로 있어서, v12와 v18을 고칠 때 양쪽을 모두 고쳤다.
- 제어 문자 정규식도 `cli.py`와 `web.py`에 각각 있다.
- 파일 크기: `sandbox.py`는 927줄로 컨테이너 수명, 파일 도구, GUI 도구, 미리보기가 한 클래스에 있다. `service.py`는 685줄이고 GUI 구간 기록(약 200줄)이 승인·인수 로직과 섞여 있다.

목표는 **동작을 하나도 바꾸지 않고** 중복을 없애고 파일을 책임별로 나누는 것이다. 그러면 run-4 검증 단위도 깔끔하게 나뉜다.

소유자 결정:
- 공개 API, 응답 형식, 설정, 감사 이벤트 이름은 그대로 둔다.
- 단계마다 작은 PR을 따로 올린다.

## 원칙 (모든 PR 공통)
- 테스트의 단언은 그대로 둔다. 다음 두 경우만 기계적으로 고친다.
  - 테스트가 직접 건드리는 내부 이름이 옮겨 가면 그 경로를 고친다. 예: `box._gui_burst`, `box._burst_pool`, `SandboxManager._x`, `from agentbox.sandbox import gui_strays`.
  - 그 외 테스트 코드는 고치지 않는다.
- 각 PR 전후로 아래 세 가지를 저장해 두고 비교해 바꾼 게 없음을 확인한다(검증 절).
  - 라우트 목록
  - 감사 이벤트 이름 목록
  - 공개 메서드 목록
- 주석 밀도와 한국어 주석 스타일은 주변 코드에 맞춘다.

## PR 1. 중복 제거 (위험 낮음, 가장 먼저)
1. **샌드박스 수명 주기 흐름을 `AgentBox`로 옮기기** (`agentbox/service.py`)
   - 새 메서드: `pause_sandbox`, `resume_sandbox`, `snapshot_sandbox`, `restore_sandbox`, `delete_sandbox`.
     - 모두 `session: str | None`을 받고, 감사 payload에 session을 넣는 방식은 지금과 같게 한다.
     - 순서도 그대로 옮긴다. 예: 복원은 `log_human` → `end_desktop` → `sandboxes.restore` → `reset_gui_timers` → `log_human("restored")`. 삭제는 `end_desktop` → `delete` → `drop_captures`.
   - `api.py`의 pause·resume·snapshots·restore·delete 라우트와 `web.py`의 take_snapshot·restore·delete 라우트가 이 메서드를 부르게 한다.
   - `guard`의 에러 변환 방식은 지금처럼 라우트 쪽에 둔다.
2. **표시용 제어 문자 처리 하나로 합치기**
   - 새 파일 `agentbox/display.py`에 `UNSAFE` 패턴과 `escape_controls(s, keep_newlines: bool)`을 둔다.
   - `cli._safe`는 `keep_newlines=False`, `web._shown`은 `True`로 이 함수를 쓴다.
   - 두 이름은 남겨서 호출하는 곳을 바꾸지 않는다.
3. **컨테이너 쪽 시간 제한 argv 헬퍼** (`agentbox/sandbox.py`)
   - `_timed(seconds, *argv, kill_after=2)`를 만들어 `["timeout", "-k", ...]`를 직접 쓰는 7곳을 바꾼다.
   - exec는 `kill_after=5`를 유지한다.
4. **라우트에서 쓰는 내부 메서드를 공개 이름으로**
   - `box._safe_log`는 `api.py`·`web.py`에서 3곳이 쓴다.
   - 공개 이름 `log_best_effort`로 바꾸고 `_safe_log` 호출은 모두 교체한다.

**진행: PR #11.** 구현하면서 정한 것은 두 가지다.
- 감사 payload의 session은 JSON API와 웹 UI가 원래 달랐다. JSON API는 항목을 넣지 않고, 웹 UI는 None이어도 넣는다. 그래서 `session`의 기본값을 `_NO_SESSION` 표지로 두어 둘 다 그대로 남겼다.
- 라우트가 `box.*_sandbox(...)` 호출 전체를 `guard`로 감싼다. 그래서 감사 기록 실패가 처리되지 않은 500 대신 503이 되고, pause·resume 뒤 `sandboxes.get`의 `SandboxError`는 400이 된다. 실패 경로만 바뀌고, 소유자가 승인했다. README의 API 표에 반영했다.

## PR 2. `service.py`에서 GUI 구간 분리
- 새 파일 `agentbox/gui_bursts.py`에 `class GuiBursts`를 만든다.
  - 옮길 상태: `_gui_input_at`, `_gui_snap_at`, `_gui_burst`, `_burst_locks`, `_burst_pool`, `_closing`.
  - 옮길 메서드: `needs_snapshot`, `open`, `close`, `_finish`, `_stop_strays`, `close_idle`, `close_failed`, `end`, `reset_timers`, `mark_input`, `shutdown`. 각각 지금의 `_gui_needs_snapshot`, `_open_gui_burst`, `_close_gui_burst`, `_finish_gui_burst`, `_stop_gui_strays`, `close_idle_gui_bursts`, `_burst_close_failed`, `end_gui_burst`, `reset_gui_timers`에서 온다.
  - 의존성: `SandboxManager`, 기록 함수(`log_best_effort`), 설정, 그리고 "인수 대기 중인지" 묻는 콜백(`_takeover_pending`)을 주입받는다.
- `AgentBox`에는 `self.bursts = GuiBursts(...)` 하나만 남긴다.
  - `_snapshot`, `_run_tool`, `takeover`, `_handback_locked`, `end_desktop`, `call_tool`, `expire_stale`가 `self.bursts`를 부르게 바꾼다.
  - 인수·반환(`takeover`, `handback`, `_gui_locked`, `_takeover_wanted`)은 사람의 제어라서 `AgentBox`에 남긴다.
- `api.py`·`web.py`의 `close_idle_gui_bursts(wait=...)` 호출은 `box.bursts.close_idle(...)`로 바꾼다.
- 테스트: `box._gui_*`, `box._burst_pool`, `box._closing` 참조를 `box.bursts.*`로 기계적으로 바꾼다. 주로 `tests/test_m2_unit.py`, `tests/test_m2_acceptance.py`에 있다.
- 결과로 `service.py`는 약 450줄이 된다.

**진행.** 구현하면서 플랜과 달라진 것은 다음과 같다.
- `GuiBursts`는 `DesktopControl`과 `AgentBox._busy_lock`도 주입받는다.
  - `needs_snapshot`이 화면 임대 상태(`desktop.lease`·`is_stale`)를 본다.
  - 닫기 잠금은 같은 잠금 객체를 써야 잠금 순서가 그대로다.
- `mark_snapshot`과 `forget_input`을 더했다. `_snapshot`과 `_handback_locked`가 시각을 직접 쓰던 곳이다.
- `AgentBox`의 공개 메서드 `close_idle_gui_bursts`, `end_gui_burst`, `reset_gui_timers`는 `bursts.*`로 옮겨서 없어졌다. 다른 호출하는 곳은 없다.
- `service.py`는 601줄이다. PR 1의 수명 주기 메서드와 승인·파일 코드가 남아서 예상(약 450줄)보다 길다.

## PR 3. `sandbox.py` 분리 (공개 메서드는 그대로)
- **`agentbox/gui_state.py`**: 순수 함수를 옮긴다.
  - 대상: `_parse_manifest`, `diff_manifest`, `_parse_ps`, `gui_strays`, `DESKTOP_UID`.
  - `sandbox.py`는 이것들을 import해서 쓴다.
- **`agentbox/preview.py`**: 명령 해석을 옮긴다.
  - 대상: `_split_segments`, `_WRAPPERS`, `_short_seg`, 그리고 `preview`의 rm·curl 해석 부분.
  - 컨테이너 조회(`_expand`, `_walk`)는 함수 인자로 받는다. `SandboxManager.preview`는 그것을 넘겨주는 얇은 메서드로 남는다.
  - `policy.py`가 쓰는 명령 해석과 겹치는지도 확인한다. 겹치면 공유하되, 판정 결과가 같은지 테스트로 보장한다.
- **데스크톱 GUI 도구를 mixin으로**: `agentbox/sandbox_desktop.py`에 `class DesktopTools`를 만들고 `SandboxManager(DesktopTools)`로 섞는다.
  - 대상: `_desktop`, `_x`, `desktop_processes`, `kill_processes`, `_wait_display`, `geometry`, `screenshot`, `click`, `type_text`, `key`, `vnc_command`, `extract_novnc`.
  - 호출하는 곳(`sb.screenshot(...)` 등)은 바뀌지 않는다.
- 테스트의 `from agentbox.sandbox import gui_strays, _parse_manifest, diff_manifest, DESKTOP_UID, _parse_outbox`는 새 위치로 바꾼다.
- 결과로 `sandbox.py`는 약 550줄이 된다(수명, 스냅샷, 파일 도구, 결과함).

## PR 4. 화면 웹소켓 중계 분리
- `api.py`의 `desktop_ws`(94줄, RFB 중계와 연결 기록)를 `agentbox/desktop_ws.py`의 함수로 옮긴다.
- `api.py`는 라우트 등록과 인증만 맡는다.
- 이 PR은 이것만 담는다.

## 하지 않는 것
- `agent.ToolClient`(동기)와 `mcp_server._wait_approval`(비동기)의 승인 대기는 합치지 않는다. 동기·비동기라 합치면 코드가 오히려 는다.
- 테스트 파일 재배치(m2/m3/m4를 영역별로 나누기)는 소유자가 범위에서 뺐다.
- 동작 변경, 새 기능, 성능 개선은 하지 않는다.

## 검증 (각 PR)
1. **기준선 저장:** 브랜치를 시작할 때 스크래치패드에 아래 세 가지를 저장한다.
   - `python -c "from agentbox.api import build; ..."`로 출력한 라우트(경로, 메서드) 목록
   - `grep -oh 'event="[a-z_]*"\|"[a-z_]*", {' agentbox/*.py`로 뽑은 감사 이벤트 이름 목록
   - `inspect`로 뽑은 `AgentBox`·`SandboxManager`의 공개 메서드 시그니처
2. **동일성 확인:** PR이 끝나면 같은 명령으로 다시 뽑아 diff한다. 차이가 없어야 한다. PR 1의 새 메서드와 PR 2의 `bursts`처럼 의도한 추가만 허용한다.
3. **전체 테스트:** `timeout 590 python -m pytest -q -rs -p no:cacheprovider tests/`로 실제 Docker와 데스크톱 이미지를 써서 233개 통과, 건너뜀 0을 확인한다. 이미지는 `docker build -t agentbox-desktop:0.1 images/desktop`로 만든다.
4. **CI:** unit은 3.11·3.13, acceptance는 건너뜀 0이어야 한다. 초록이 되면 소유자가 병합한다.
5. **diff 점검:** 옮긴 코드가 글자 그대로인지 `git diff --color-moved=zebra`로 본다. 옮기면서 로직이 바뀐 줄이 없어야 한다.

## 진행 순서와 브랜치
- 순서는 PR 1 → 2 → 3 → 4다. PR 2와 3은 PR 1의 `log_best_effort`에 기댄다.
- 브랜치는 그 세션의 지정 브랜치를 main에서 다시 시작해 PR 1부터 쓴다. PR 1은 `ccr-e5de0397-31ksj8`에서 했다.
- 앞 PR이 병합되면 같은 브랜치를 main에서 다시 시작해 다음 PR을 만든다.
- 각 PR은 draft로 올리고 CI를 지켜본다.
