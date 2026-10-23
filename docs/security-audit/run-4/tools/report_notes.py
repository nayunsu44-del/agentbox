"""Hand-written REPORT.md sections that cannot be derived from findings.json or the ledger."""

FINAL_CRITIC = ("- 최종 비평(`critic-2`, Opus, 50번째 호출)은 `stop: false`였다. 새 미할당 경계 1개를 냈다(위 세 번째 항목). 예산이 다 떨어져 이것도 `deferred`로 넣었다. "
                "따라서 이 run은 **깨끗한 커버리지를 주장하지 않는다.** 이 비평이 제안한 공격 유형 블록(`Race conditions in shared state`)은 스킬에 없어서 부모가 자유 서술로 적었다. "
                "critic-2는 run-3 단서 3개(구간 열기 실패 무기록, `gui_lock`을 쥔 채 시간 제한 없는 X exec, 프레임 허용 UI)가 현재 소스에서 해소됐다고 판단했다.")

DEFERRED_KO = {
    "Race and check-then-act on security-control state: GUI burst opened by decide/_snapshot or call_tool while a human takeover lease is held":
        "(critic-2 제안) 사람이 화면을 인수한 동안 열리는 에이전트 GUI 구간. 승인된 GUI 입력의 `decide`나, 인수와 겹친 `call_tool` 스냅샷이 `gui_lock`과 리스 확인 없이 구간을 연다(service.py:250-265, 412). 그 구간이 리스 기간 내내 남아, 뒤이은 `close_idle`이 사람이 띄운 프로세스를 죽이고 사람의 편집을 에이전트 `gui_changes`로 기록할 수 있는지(service.py:514의 설계 불변식).",
    "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation":
        "데스크톱 WebSocket(`/sandboxes/{sid}/desktop/ws`) 업그레이드 경로. async 핸들러가 `ws.accept()` 전에 SQLite(세션·리스)와 Docker SDK를 동기로 불러 이벤트 루프를 막는지(api.py, desktop_ws.py).",
    "DATA-ISOLATION-AND-LIFECYCLE.md#Retention and queued-work overrun":
        "승인 테이블. 승인이 필요한 호출마다 원본 인자와 미리보기를 마스킹·상한 없이 저장하고, 샌드박스를 지운 뒤에도 남는지(approvals.py, service.py).",
}

DEVIATIONS = [
    "검토 세션(리눅스)이 1차 결과를 다시 보고 아래 문제를 찾았다. 고칠 수 있는 것은 고쳤고, 고칠 수 없는 것은 여기에 공개한다.",
    "",
    "**검토에서 고친 것**",
    "",
    "- **후보 v11이 판정 없이 빠져 있었다.** 스냅샷 쿼터 TOCTOU 후보는 검증자 결과가 없었지만, 장부에는 후보로 남아 있었다. 1차 보고서는 이 건을 언급하지 않았다. 검토 때 다음 순서로 처리했다.",
    "  1. v11(Opus)이 검증 필요로 판정했다.",
    "  2. r13(Sonnet)이 그 레코드를 확인했다.",
    "  3. 부모가 실제 Docker에서 재현했다(21번 중 18번 뚫림).",
    "  4. 부모가 확정으로 올린 대체 레코드를 새 검증자 r14(Opus)가 확인했다. 확정, 심각도 낮음이다.",
    "- **critic-1이 제안한 2단위가 장부에 없었다.** 장부에 `deferred`로 넣었다. critic-1의 원래 출력은 남지 않아 1차 보고서의 요약과 소스로 단위를 다시 만들었다(장부 `x_source`).",
    "- **최종 비평을 예산이 남았는데 돌리지 않았다.** 검토 때 마지막 호출로 돌렸다(`critic-2`). 새 경계 1개가 나와 `deferred`로 넣었다.",
    "- **`run_status: \"complete_with_deferred_units\"`는 스킬에 없는 값이었다.** 보류 단위가 남은 부분 감사이므로 `incomplete`로 고쳤다.",
    "- **승인 카드 단위에 잘못된 검사가 들어가 있었다.**",
    "  - 원인: `tools/oneoff/_fix.py`가 h-policy의 `raw.txt`를 덮어쓰고, 단위를 순서대로 짝지었다. 그래서 승인 카드 단위에 승인 결정 단위의 검사가 들어갔다. `_fix_card_unit.py`는 그 단위를 손으로 후보로 바꿨다.",
    "  - 검토 때 그 검사를 헌터의 실제 산출물 `h_prev.out` 근거로 바로잡았다(장부 `x_parent_note`).",
    "  - 다만 h-policy 승인 결정·exec 두 단위의 결과 문장은 부모가 쓴 것이고, 원본은 남아 있지 않다.",
    "- **장부의 3단계 검사에 필수 필드가 없었다.** `apply.py`가 `invariant`·`result`를 쓰지 않았고, trace 경로를 `path` 키로 찾았다(레코드는 `file`). 둘 다 고쳤다. 1차 때는 `fix_schema.py`로 나중에 메웠다.",
    "- **보고서가 영어 원문 그대로였고, 일부 칸이 잘려 있었다.** 한국어로 다시 썼다(`tools/ko_text.py`, `tools/gen6.py`).",
    "  - '대표 경로'가 알파벳순 첫 파일이라 거의 다 `api.py`였다. 지문의 파일로 바꿨다.",
    "  - 'run-3 확정 9건'은 run-1·2 목록이었다. run-3 기준으로 바로잡았다.",
    "",
    "**고칠 수 없어 공개하는 것**",
    "",
    "- **헌터 결과 옮겨 적기.** 1차 기록은 h-policy, h-queue, h-gui-race, h-preauth를 부모가 옮겨 적었다고 했다. 하지만 `raw.txt`가 남은 것은 h-policy, h-queue, h-gui-race, h-pool이다. 그 넷의 `result.json`은 부모가 쓴 것이다.",
    "- **v06은 지시문 없이 돌았다.** 형제 지시문으로 계약을 재구성했고, 그 사실을 결과에 적었다. 승인 카드 영향 표 건(확정)이 이 검증자의 판정이다. 5단계에서는 다른 검증자가 레코드를 따로 확인했다.",
    "- **r03·r09의 '비물질 수정'은 검증할 수 없다.** 두 5단계 검증자가 `replace`를 내며 비물질이라고 밝혔고, 두 번째 검증자 없이 반영됐다. 그 결과 파일은 스크래치에만 있었고 저장소에 남지 않았다.",
    "- **5단계 검증 중 일부는 짧았다.** 예를 들어 r13은 도구 호출 6회였다.",
    "- **v05가 범위 밖 쓰기 지시를 받았다고 보고했다.** 자기 턴에 그런 지시가 들어왔고 거부했다고 적었다. 스크래치 밖에 쓴 것은 없었다.",
    "- **Windows 호스트에서는 256 MiB loop 스크래치를 쓸 수 없었다.** promote 크기 상한과 `cap_scratch`로 대신했다. 그쪽 검사기는 node:22-alpine 컨테이너에서 돌렸다. 검토 세션에서 리눅스로 두 검사기를 직접 다시 돌렸고 모두 통과했다.",
    "- **예산:** 상한 50을 모두 썼다.",
    "  - 1차: 정찰 4, 헌터 13, 사후 비평 1, 3단계 13(v11 포함, 결과 없음), 5단계 12, 재시도 3",
    "  - 검토 보완: v11 재실행, r13, r14, 최종 비평",
]

LIVE_SUMMARY = [
    "**run 뒤 부모 실측 (에이전트 예산 밖).** 소유자 요청으로 검증 필요 5건을 실제 Docker, 데스크톱 이미지, Chromium 141로 직접 확인했다. 스크립트와 결과는 `agents/parent-live/`에 있다. 판정은 바꾸지 않았다. 바꾸려면 새 검증자가 필요한데, 예산 50을 이미 다 썼다.",
    "",
    "| ID | 실측 결과 | 판정에 주는 의미 |",
    "|---|---|---|",
    "| N1 | Chromium은 cross-scheme POST에 세션 쿠키를 보내지 않았다. 그래도 `/logout` 응답이 쿠키를 지워 강제 로그아웃은 됐다. | Chromium에서는 강제 로그아웃(낮음)만 성립한다. Firefox·WebKit은 미확인. |",
    "| N2 | 에이전트 하나가 11 MB 볼륨을 19초에 채웠다. 그 뒤 모든 샌드박스의 도구 호출, 사람의 스냅샷·삭제가 503이 됐고, 승인 결정은 처리되지 않은 예외(500)가 됐다. 실행이 끝난 호출 3개의 결과 기록이 빠졌다. | 저장소 쪽 막힌 지점이 모두 풀렸다. 남은 것은 실제 볼륨 크기뿐이다. 확정 후보다. |",
    "| N3 | 파일 20만 개에서 `list_dir` 34 MiB, outbox 90 MiB, 미리보기 65 MiB가 늘었다. 스크린숏 `/dev/zero`는 15초 제한으로 78 MiB에서 끊겼다. | 증가는 실제이지만 선형이고 제한 시간으로 묶인다. 해를 끼치려면 큰 규모가 필요하다. 낮음이나 하드닝 쪽이다. |",
    "| N4 | 이미지의 python3·libX11로 `_NET_WM_PID`를 위조했다. 단축키로 기준 세션에 띄운 데몬이 실제 정리에서 살아남아 계속 썼다. 위조 창을 빼면 정리 목록에 들어갔다. | 막힌 지점 세 개가 모두 풀렸다. 확정 후보다. |",
    "| N5 | ALM 두 개 사이의 `>`가 승인 카드에 `<`로 그려졌다. bash는 쓰기(출력 리디렉션)를 했다. | Chromium에서 카드가 다른 명령처럼 읽힌다. 확정 후보다. |",
]
