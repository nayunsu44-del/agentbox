"""Hardening notes for the run-7 report (parent summary of hunter `hardening` lists and parent-live observations)."""

HARDENING = [
    "`_expand`의 틸드 처리(`7dbda9e` F3): dash가 `${1#~/}`의 `~/`를 먼저 펼쳐 접두가 떼어지지 않아, 있는 `~/tilde_target.txt`도 `[]`가 된다(parent-live `recon_leads_live.out`). 미리보기 카드에는 경고 문구가 나오므로 F3의 불변식은 지켜진다. 틸드 펼치기 자체는 동작하지 않는다.",
    "`agent.py`의 `call_text`가 `with_notice`로 감싼 뒤 20,000자에서 자르기 때문에, 큰 지시 파일에서는 닫는 경계 줄이 빠진다. MCP 서버는 남긴다. 무작위 값을 흉내 낼 수 없어 우회는 아니다. 자르기를 감싸기 전에 하면 두 경로가 같아진다.",
    "읽기는 링크를 풀지 않는다(`mark_read`는 요청 경로만 본다). `notes.md -> CLAUDE.md`로 읽으면 알림이 붙지 않고, README가 권하는 `read_file` 차단 규칙도 우회된다. 이름으로만 판단한다는 알려진 한계 안이지만, 쓰기 쪽은 링크를 푸므로 비대칭이다.",
    "`scan()`의 10초 상한은 항목마다만 본다. 느리거나 멈춘 마운트에서 `os.scandir()`를 여는 호출 하나가 막히면 끊지 못한다. 사람 전용 생성 요청이고 에이전트 도구 풀과는 분리되어 있다.",
    "`_found_payload`의 경로 길이 512는 글자 수라, 여러 바이트 글자 경로 200개면 기록 상한에 걸려 목록이 빠진다(개수와 '잘림' 표시는 남는다).",
    "`clean_name`은 C0·DEL만 막고 C1 제어 문자(U+0080~U+009F)는 받는다.",
    "`Policy`는 `version`을 읽지 않는다. 지시 파일 규칙이 없는 v3 정책도 경고 없이 올라간다. `match.instruction_files` 규칙은 같은 규칙의 `commands` 등을 조용히 무시한다.",
    "`_preview`도 `resolve()` 실패를 삼켜, 그때 승인 카드에 '링크를 따라간 실제 대상' 줄이 빠진다. '실제 대상을 풀지 못함'으로 보이는 것이 낫다.",
    "`screenshot`의 `[ ! -L ]` 확인과 `head -c` 사이에 데스크톱 계정이 파일을 바꿀 틈이 있다. 크기 상한과 PNG 서명 확인으로 영향은 묶인다. `_exec_head`의 대체 경로(`client.api`가 없을 때)는 출력 전체를 받는다(실제 docker SDK에서는 쓰이지 않음).",
    "IF-1 뒤 `_preview`가 `realpath` exec를 한 번 더 하므로, 승인 요청의 `disk_low` 재확인 전 지연이 조금 늘었다. 순서는 그대로다.",
]
