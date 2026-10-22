# 보안 감사 핸드오프 (agentbox)

다른 세션이 이어받기 위한 요약. 전체 근거는 `docs/security-audit/run-1/` 참고.

## 한눈에 보기

- **무엇:** Cloudflare `security-audit` 스킬(6단계 워크플로)을 agentbox 전체에 적용한 1차 감사(run-1).
- **대상 커밋:** 감사 기준 `7fc501f`. 이후 수정 커밋은 아래 브랜치에.
- **브랜치:** `ccr-53433386-ji3dh4` (origin에 푸시됨).
- **결과:** 확정 3건(High/Medium/Low) — **모두 패치 완료**. needs_validation 5건 — **미완(런타임 검증 필요)**. 기각 1건.
- **이 세션의 제약:** OS 샌드박스·Docker 데몬 없음, 일부 파이썬 의존성(`fastapi`/`docker`/`httpx`) 없음 → 대상 코드 실행 불가. 그래서 소스 + 순수함수 하네스로만 검증했고, 런타임 사실이 필요한 5건은 needs_validation으로 남겼다.

## 커밋 이력 (이 브랜치)

| 커밋 | 내용 |
|---|---|
| `6432d20` | High(정책 주석 우회 차단) + Medium(결과함 목록 파싱 견고화) + 회귀 테스트 |
| `7f84f61` | Low(`_DEVNULL` `>&<숫자>파일` 리다이렉트 우회 차단) + 회귀 테스트 |

두 커밋 모두 `tests/test_unit.py`에 회귀 테스트를 추가했고, **오프라인 단위 테스트 51개 통과**를 확인했다(아래 "오프라인 테스트 돌리기" 참고). Docker 필요한 수용 테스트는 이 환경에서 못 돌렸다.

## 확정 3건 — 패치 완료 (근거: run-1/FINDINGS-DETAIL.md, REPORT.md §3)

1. **[High] 따옴표 `#` 주석으로 exec 허용 목록 우회** — `agentbox/policy.py`
   - `ls #'<줄바꿈>숨긴명령<줄바꿈>#'` 꼴에서 정책은 `{ls}`만 보고 allow를 냈지만 bash는 숨긴 명령을 승인·스냅샷 없이 실행했다.
   - 수정: `has_bash_comment()` 추가 → 따옴표 밖 단어-시작 `#`이 있으면 `simple_programs`가 `None`(승인)을 돌려준다.
2. **[Medium] 컨테이너가 정한 결과함 파일 이름이 목록 파싱을 깨뜨림** — `agentbox/sandbox.py`
   - `outbox_list`의 무가드 `int()/float()`가 이름의 탭·줄바꿈에 HTTP 500 / 가짜 행 주입을 허용했다.
   - 수정: `find ... -printf '%s\t%T@\t%f\0'`(NUL 구분, 이름 맨 뒤) + 순수함수 `_parse_outbox()`에서 try/except.
3. **[Low] `_DEVNULL`이 `>&<숫자>파일` 리다이렉트를 벗겨 `>` 승인 게이트 우회** — `agentbox/policy.py`
   - `echo DATA >&2evil`이 allow로 통과해 파일 `2evil`을 승인·스냅샷 없이 썼다.
   - 수정: 정규식에 부정형 전방탐색 `(?![\w./-])` 추가. 진짜 `/dev/null` 버리기·`N>&M` fd 복제만 벗겨낸다.

세 건의 공통 뿌리: **정책 렉서(`commenters=""`)와 실제 bash 실행의 해석 불일치**, 그리고 **믿을 수 없는 컨테이너 출력**.

## 남은 일 — needs_validation 5건 (근거: run-1/NEEDS-VALIDATION.md)

Docker/데스크톱 이미지가 있는 환경에서 실제 실행으로 확인(또는 반증)해야 한다. 각 리드의 정확한 소스 트레이스·차단 사유·검증 절차는 `run-1/NEEDS-VALIDATION.md`에 단계별로 있다.

| # | 핑거프린트(요지) | 다음 검증 |
|---|---|---|
| N-1 | GUI 도구 → uid1001 터미널 실행(allowlist/승인/스냅샷 우회) | 데스크톱 샌드박스에서 GUI 도구만으로 터미널을 띄워 `/workspace` 변경이 승인·스냅샷 없이 되는지 |
| N-2 | exec stdout가 64KB 캡 전에 컨트롤 플레인 메모리에 전량 버퍼링 | cgroup 메모리 제한 아래 고속 stdout 생성기로 RSS 증가 관측 |
| N-3 | `docker commit` 스냅샷 무제한(디스크 고갈) | 격리 인스턴스에서 같은 파일 write_file 반복, `agentbox-snap:*` 이미지 증가 관측 |
| N-4 | 무제한 `source_dir` → 호스트 비밀 복사 | 배포 런타임에서 컨테이너 uid0=호스트 root 등가 여부 확인, 더미 0600 파일로 재현 |
| N-5 | 터미널 승인 화면 이스케이프 스푸핑 | 터미널 `approve` 플로우 사용 여부 확인, 크래프트된(무해) 이스케이프 렌더링 관측 |

기각 1건: `desktop.py:redeem:...full-admin-session` — 데스크톱 티켓은 전체관리자(human 토큰)만 발급 가능하므로 넘는 신뢰 경계 없음(반증됨). 재보고 금지. (관련 완화책은 REPORT.md §6 하드닝에 있음.)

## 이어서 작업하는 법 (새 세션)

0. 이 브랜치를 클론/체크아웃: `git fetch origin ccr-53433386-ji3dh4 && git checkout ccr-53433386-ji3dh4`. 감사 산출물은 `docs/security-audit/run-1/`에 있다.

1. **먼저 전체 테스트 녹색 확인** (Docker 필요):
   ```bash
   pip install -e '.[test]'
   docker pull buildpack-deps:noble-curl
   # (데스크톱 항목까지 보려면) docker build -t agentbox-desktop:0.1 images/desktop
   pytest
   ```
   Docker 없이 오프라인 부분만: `pytest tests/test_unit.py`(pyyaml 필요). 세 수정의 회귀 테스트가 여기 있다.

2. **needs_validation 5건 검증** — `run-1/NEEDS-VALIDATION.md`의 각 local/deployment 절차를 격리 환경에서 수행. 확정되면 `run-1/findings.json`의 해당 레코드를 `confirmed`로 갱신하고 `node <skill>/validate-findings.cjs`로 재검증.

3. **2차 감사 런(선택)** — 같은 스킬을 Docker 가능한 환경에서 재실행하면 커버리지가 는다(스킬 설계상 다회차 가산). 이전 원장/결과(`run-1/`)를 prior-run 입력으로 주면 바뀐 소스·미해결 리드를 우선 타겟팅한다. run-2는 `docs/security-audit/run-2/`로.

4. **PR(선택, 아직 안 만듦)** — `ccr-53433386-ji3dh4` → 기본 브랜치. 사용자가 명시 요청할 때만 생성.

## 참고: 감사를 어떻게 돌렸나 (재현용)

- 스킬 원본: `cloudflare/security-audit` (SKILL.md의 6단계). 로컬 클론은 세션별 임시 경로라 영구 보관 안 함 — `npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit` 또는 레포 클론으로 다시 가져온다.
- 단계별 에이전트 수: 정찰 6 → 헌팅 7 → 적대적 교차검증 9 → 기록 재검증 8. 커버리지 원장 15유닛, 두 검증기(coverage-ledger / findings) 모두 PASS, `run_status: complete`.
- 정책 우회는 순수함수 하네스로 재현: `policy.py`를 `python3 -I`로 import(부작용 없음) + 더미 파일에 `bash -c "umask 002\n"+command` (Docker/네트워크/공유상태 안 건드림). exec 래퍼 원문은 `agentbox/sandbox.py`의 `exec()`와 동일.

## 파일 맵

- `docs/security-audit/run-1/REPORT.md` — 전체 요약(파라미터·포스처·확정표·needs_validation표·기각·하드닝·커버리지).
- `docs/security-audit/run-1/FINDINGS-DETAIL.md` — 확정 High/Medium 상세(트레이스·재현·수정).
- `docs/security-audit/run-1/NEEDS-VALIDATION.md` — 미해결 5건의 트레이스·차단사유·검증 절차.
- `docs/security-audit/run-1/findings.json` — 9건 전체 구조화 레코드(스키마 검증 통과).
- `docs/security-audit/run-1/coverage-ledger.json` — 15유닛 결정론적 커버리지 원장(검증 통과).
- `docs/security-audit/run-1/architecture.md` — 아키텍처·신뢰경계·커버리지 계획.
- `docs/security-audit/run-1/run-metadata.json` — 런 메타데이터(`run_status: complete`).
