# 보안 감사 핸드오프 (agentbox)

다른 세션이 이어받기 위한 요약. 근거는 `docs/security-audit/run-1/`(1차 감사)과 `docs/security-audit/run-2/`(실측 검증)에 있다.

## 한눈에 보기

- **무엇:**
  - run-1: Cloudflare `security-audit` 스킬(6단계)로 agentbox 전체를 감사했다. 기준 커밋 `7fc501f`.
  - run-2: run-1이 남긴 needs_validation 5건을 실제 Docker에서 검증했다.
- **브랜치·PR:** 작업 브랜치 `ccr-e10bee8e-6wt669`. PR #1(감사 수정·CI), #2(화면 링크 세션 범위), #3(FIFO), #4(runc 차단)는 `main`에 병합됐다. **PR #5(GUI 백그라운드 정리·세션 만료)는 CI 통과, 병합 대기**(사용자 승인 필요). 병합할 때마다 작업 브랜치를 최신 `main`에서 다시 시작한다.
- **현재 상태:** 감사 확정 9건 중 **8건 수정 완료**, **N-1(High)은 방안 C·A·G + 백그라운드 정리로 부분 완화**(복구·경고·기록·정리, 승인 우회는 남음). 기각 1건. README "아직 고치지 않은 것" 항목(비밀값 가림, 화면 링크 세션, FIFO, runc)도 모두 고쳤다.
- **테스트:** 전체 `pytest` 205개 통과(Docker 수용 테스트·데스크톱 포함, 건너뛴 것 0개).

## 전체 목록

| 출처 | 내용 | 심각도 | 상태 | 커밋 |
|---|---|---|---|---|
| run-1 | 따옴표 `#` 주석으로 exec 허용 목록 우회 (이스케이프한 따옴표 변형 포함) | High | 수정 | `6432d20`, `860fe03` |
| run-1 | 결과함 파일 이름(탭·줄바꿈)이 목록 파싱을 깨뜨림 | Medium | 수정 | `6432d20` |
| run-1 | `_DEVNULL`이 `>&<숫자>파일` 리다이렉트를 벗겨 승인 우회 | Low | 수정 | `7f84f61` |
| run-2 N-1 | GUI 도구로 터미널을 열어 uid 1001 임의 실행 (승인·스냅샷 우회) | High | 부분 완화 (GUI 구간 스냅샷·경고·바뀐 파일 기록) | `3028b68`, `d677348` |
| run-2 N-4 | 데이터 폴더와 겹치는 `source_dir` → 사람 토큰 유출 → 자기 승인 | High | 수정 | `e56e2a9` |
| run-2 N-2 | exec 출력이 컨트롤 플레인 메모리에 전부 쌓임 | Medium | 수정 | `c6a0a3c` |
| run-2 신규 | 블로킹 exec로 공용 스레드 풀을 묶어 사람 API 정지 | Medium | 수정 | `c6a0a3c` |
| run-2 N-3 | 덮어쓰기마다 스냅샷, 상한·정리 없음 → 디스크 고갈 | Medium | 수정 | `4826cb5` |
| run-2 N-5 | 터미널 승인 화면이 제어 문자로 다른 명령처럼 보임 | Medium | 수정 | `1a9bb0f` |
| run-1 | 데스크톱 티켓 → 전체 관리자 세션 | — | 기각 (재보고 금지) | — |
| 후속 | 감사 로그 비밀값 가림이 흔한 형식(DB_PASSWORD=, 따옴표, JSON, URL 자격 증명 등)을 놓침 | — | 수정 | `52145e0` (PR #1) |
| 후속 | 화면 링크(샌드박스 A용) 세션이 웹 UI 전체를 씀 → 다른 샌드박스 승인까지. 로그아웃이 화면 연결·인수를 안 정리 | High | 수정 | PR #2 (`be083de`) |
| 후속 | FIFO를 read_file로 읽으면 멈춤, 결과함 내려받기는 바꿔치기로 사람 요청이 멈춤 | Medium | 수정 | PR #3 (`8916a02`) |
| 후속 | 강한 격리 런타임이 없으면 밖에 여는 설치도 runc로 돎 | — | 수정 (밖에 열 때 runc면 안 뜸, `--allow-runc`) | PR #4 (`41cc575`) |
| 후속 | N-1 보강: GUI로 띄운 백그라운드 일이 구간 뒤에도 돎 / 만료 세션의 화면 연결이 안 끊김 | — | 수정, **병합 대기** | PR #5 (`4798075`) |

PR #1에 Codex 리뷰 4건(P1 1·P2 3)이 달렸고 모두 재현한 뒤 `860fe03`에서 고쳤다. 따옴표 밖 `\"`로 `#` 주석 검사를 피하는 변형, 스냅샷 상한 경쟁, 복원·삭제 때 GUI 기록 누락, mtime 되돌리기로 GUI 기록 위조. CI(`.github/workflows/ci.yml`)가 PR마다 단위·Docker 수용 테스트를 돌린다.

새 설정은 README 환경 변수 표에 있다: `AGENTBOX_SNAPSHOT_QUOTA`(기본 50), `AGENTBOX_TOOL_CONCURRENCY`(기본 4), `AGENTBOX_GUI_SNAPSHOT_IDLE`·`_INTERVAL`(기본 60·600).

## 다음 작업: 3차 감사 (run-3)

사용자와 합의한 계획. 시작 전에 PR #5 병합 여부와 프로필·서브에이전트 상한을 사용자에게 확인한다.

- **방법:** Cloudflare `security-audit` 스킬 전체 감사 모드(6단계: 정찰 → 헌팅 → 후보 검증 → findings.json → 독립 재검증 → 보고서).
  스킬은 세션 임시 경로에 있었으니 다시 받는다: `git clone --depth 1 https://github.com/cloudflare/security-audit-skill`.
- **이전 런:** `run-1/`, `run-2/`의 coverage-ledger·findings를 prior-run으로 넘긴다. 고친 9건은 코드가 바뀌었으니 재검증 단위로, 기각 1건은 같은 주장 재보고 금지.
- **우선순위:** `7fc501f` 이후 바뀐 코드(소스 9개 파일): 스트리밍 exec·전용 스레드 풀·스냅샷 상한/락(service·sandbox·api), GUI 구간·파일 목록·프로세스 정리(service·sandbox), 비밀값 가림(audit), 세션 범위·만료(desktop·api·web), FIFO 제한(sandbox), runc 차단(cli).
- **검증:** Docker와 데스크톱 이미지가 있으니 후보를 이 세션의 일회용 컨테이너에서 재현한다(1차처럼 needs_validation으로 남기지 않는다). 차등 퍼저(정책 vs bash)와 `run-2/repro/`를 활용.
- **프로필:** 제안은 `standard`(서브에이전트 30~40회). 결과는 `docs/security-audit/run-3/`. 확정 건은 재현 → 수정 → 회귀 테스트 → PR.

## 남은 일

1. **N-1 후속(선택).** 방안 C·A·G로 복구 지점·경고·바뀐 파일 기록은 생겼지만 승인 우회는 남는다. 더 막아야 하면 `run-2/N-1-OPTIONS.md`의 D2(시간 제한 GUI 허가)나 E(화면 계정의 `/workspace` 쓰기 분리)를 검토한다. 백그라운드 프로세스 보완(돌려줄 때 화면 계정의 남은 프로세스 정리)도 후보다.
2. **PR #1.** 사용자 요청으로 ready(리뷰 가능) 상태로 바꿨다. 리뷰·병합은 사용자 몫이다.
3. **3차 감사(선택).** 같은 스킬을 `run-2/`를 prior-run 입력으로 다시 돌리면, 바뀐 코드(스트리밍 exec, 전용 스레드 풀, 스냅샷 상한)를 우선 볼 수 있다. 결과는 `docs/security-audit/run-3/`에 둔다.

## 이어서 작업하는 환경 만들기 (새 세션)

이 클라우드 컨테이너에는 Docker CLI가 있고, 데몬은 직접 띄우면 된다. 이전(run-1) 세션은 데몬이 없어 소스만 봤지만, run-2 세션은 아래 순서로 전부 돌렸다.

```bash
git fetch origin ccr-e10bee8e-6wt669 && git checkout ccr-e10bee8e-6wt669
nohup dockerd >/tmp/dockerd.log 2>&1 &          # root로. 몇 초 뒤 docker info 확인
pip install -e '.[test]'
docker pull buildpack-deps:noble-curl
docker build -t agentbox-desktop:0.1 images/desktop   # 약 3분 (apt 239MB)
pytest                                                 # 160 passed
```

- 재현 스크립트는 `docs/security-audit/run-2/repro/`에 있다. 레포 루트에서 `python3 docs/security-audit/run-2/repro/<이름>.py`로 돌린다. `n5_spoof.py`는 `pip install pyte`가 필요하다.
- 감사 레코드 검증: `git clone --depth 1 https://github.com/cloudflare/security-audit-skill` 후 `node security-audit-skill/skills/security-audit/validate-findings.cjs docs/security-audit/run-2/findings.json` (현재 `PASS: 10 findings valid`).
- 수용 테스트가 실패하면 샌드박스 컨테이너나 `agentbox-snap:*` 이미지가 남을 수 있다. `docker ps -a`, `docker images`로 확인하고 지운다.

## 파일 맵

- `run-2/VALIDATION.md`: 5건 + 신규 1건의 재현·관측·수정 요약(한국어).
- `run-2/N-1-OPTIONS.md`: N-1 대응 방안 8가지 비교와 권장 조합, 결정할 것.
- `run-2/findings.json`: 현재 기준 전체 10건 구조화 레코드(확정 9 · 기각 1, 검증기 통과). 트레이스 줄 번호는 감사 기준 커밋 `7fc501f` 기준이다.
- `run-2/repro/`: 재현 스크립트 8개. `run-2/n1-terminal-via-gui-tools.png`: N-1 증거 스크린샷.
- `run-1/`: 1차 감사 산출물(REPORT, FINDINGS-DETAIL, NEEDS-VALIDATION, findings, coverage-ledger, architecture, run-metadata). 기록으로 두고 고치지 않는다.

## 3차 감사(run-3) 진행 상태 — 다음 세션이 여기서 이어받는다

작업 브랜치: `ccr-df7eb88d-1nmb5q` (PR #6 브랜치 `ccr-e10bee8e-6wt669`의 커밋 18개 + 이후 커밋). **PR #6 브랜치에는 아직 반영하지 않았다**(사용자 허락 필요). 사용량 한도로 3단계 중간에 멈췄다(한도 해제 15:30 UTC).

### 3단계 결과 (후보 14개)
| 검증자 | 후보(fingerprint 요약) | 상태 |
|---|---|---|
| v02 | audit.py:list 타임라인 5000행 고정 | **확정 medium** — `agents/v02/result.json` 저장·승격 완료 |
| v04 | cli.py runtime_problem runc 별칭 | **기각** (운영자 설정, 경계 없음) — 방어 강화 메모: 거부 목록→허용 목록 |
| v05 | desktop.py 사람 토큰 교체해도 브라우저 세션 유지 | **확정 medium** — 저장·승격 완료 (패치 초안 `agents/v05/artifacts/desktop_fixed.py`) |
| v07 | gui_strays _NET_WM_PID | 이전 세션이 **기각**했으나 레코드가 소실됨 → **v15로 재검증 필요** (`agents/v15/prompt.md` 준비됨) |
| v12 | service.py GUI 구간 상태가 restore/pause에서 유실 | 검증자는 **확정 low**를 냈으나 trace에 `sink` 2개로 스키마 위반 → 폐기. 내용은 `agents/v12/result.rejected-by-validator.json`에 참고용 보존. **새 검증자로 재실행** |
| v01 v03 v08 v09 v10 v11 v13 v14 | — | 한도로 중도 종료(결과 없음). **새로 실행** (v08은 확정 직전이었음) |
| v06 | source_dir 대소문자 우회 | 아직 실행 안 함. 이 커널은 대소문자 무시 FS가 없어 로컬 재현 불가 → needs_validation 유력 |

에이전트 사용: 이전 19 + v07(소실) 1 + 이번 세션 12(완료 4 + 중도 종료 8) = **32회**. 남은 일을 하려면 재실행 10(v01,v03,v06,v08,v09,v10,v11,v12,v13,v14)+v15, 5단계 재검증이 더 필요해 40~45를 넘길 수 있다 → 사용자에게 상한을 다시 확인할 것.

### 이어서 하는 법
1. 환경: `nohup dockerd &` → `pip install -e '.[test]'` → 이미지는 Docker Hub가 429면 `mirror.gcr.io/library/<이미지>`로 받아 `docker tag`(buildpack-deps:noble-curl, ubuntu:24.04) → `docker build -t agentbox-desktop:0.1 images/desktop`. 스킬은 `git clone --depth 1 https://github.com/cloudflare/security-audit-skill`. 베이스라인 pytest 205개 통과 확인됨.
2. 도구는 `docs/security-audit/run-3/tools/`: `sbx`(격리 실행기), `promote.py`(부모 전용 승격, no-follow), `ingest.py`(검증자 결과 엄격 파싱·스키마 검증·승격). 파일 안의 절대 경로(스크래치패드, 스킬 경로)를 새 세션 값으로 고칠 것. 검증자별 `agents/vNN/scratch`는 `chown 65534`로 미리 만들어 둔다.
3. 검증자는 `agents/vNN/prompt.md`를 읽고 따르게 하고, `sbx` 경로만 새 위치를 알려준다. v09는 부모 실측 `agents/parent-live/artifacts/l7_burst_open.{py,out}`(pid 압력 시 구간이 빈 기준으로 조용히 기록되고 gui_changes가 실제 변경을 가림)를 추가 증거로 알려 줄 것(단 압력 프로세스가 exec로 떴다는 한계도 함께).
4. 결과가 다 모이면 장부(`coverage-ledger.json`)에 검증자 check와 `x_decisions` 반영(v07 때 형식 참고) → 4단계 `findings.json` → 두 검증기 → 5단계 독립 재검증 → 보고서 → 확정 건 수정.
5. 확정 건의 수정 방향(검증자 제안): v02는 `AuditLog.recent()`로 최신 N건+실제 총계, CLI는 `after_id` 페이징. v05는 사람 토큰 지문(gen)을 세션·티켓에 묶고 시작 시 불일치 행 삭제 + owner용 revoke-all. 둘 다 회귀 테스트 필요.
6. 부수 관찰: 구간 기준(pid 집합)이 낡은 상태에서 닫으면 `gui_strays`가 새로 뜬 데스크톱 세션 전체를 죽인다(컨테이너 재시작 후 실험에서 확인). v12 후보와 같은 뿌리라 검증자에게 알릴 것.
