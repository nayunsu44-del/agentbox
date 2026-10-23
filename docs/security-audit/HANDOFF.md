# 보안 감사 핸드오프 (agentbox)

다른 세션이 이어받기 위한 요약. 근거는 `docs/security-audit/run-1/`(1차 감사)과 `docs/security-audit/run-2/`(실측 검증)에 있다.

## 한눈에 보기

- **무엇:**
  - run-1: Cloudflare `security-audit` 스킬(6단계)로 agentbox 전체를 감사했다. 기준 커밋 `7fc501f`.
  - run-2: run-1이 남긴 needs_validation 5건을 실제 Docker에서 검증했다.
- **브랜치·PR:** run-3은 `ccr-e2c70e17-r0gmhn`, draft PR #8(아래 "3차 감사(run-3) 진행 상태"). run-1·2 때 작업 브랜치는 `ccr-e10bee8e-6wt669`. PR #1(감사 수정·CI), #2(화면 링크 세션 범위), #3(FIFO), #4(runc 차단), #5(GUI 백그라운드 정리·세션 만료, `8e4db9e`)는 `main`에 병합됐다. 병합할 때마다 작업 브랜치를 최신 `main`에서 다시 시작한다.
- **현재 상태:** 감사 확정 9건 중 **8건 수정 완료**, **N-1(High)은 방안 C·A·G + 백그라운드 정리로 부분 완화**(복구·경고·기록·정리, 승인 우회는 남음). 기각 1건. README "아직 고치지 않은 것" 항목(비밀값 가림, 화면 링크 세션, FIFO, runc)도 모두 고쳤다.
- **테스트:** 전체 `pytest` 214개 통과(run-3 수정 회귀 테스트 9개 포함, 2026-10-22)(Docker 수용 테스트·데스크톱 포함, 건너뛴 것 0개).

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

- `run-3/REPORT.md`: 3차 감사 보고서(한국어). 미완료 이유, 확정 8건, 검증 필요 5건, 보강 메모, 커버리지를 담았다. 상세 내용은 `run-3/FINDINGS-DETAIL.md`와 `run-3/NEEDS-VALIDATION.md`에 레코드 원문 그대로 있다.
- `run-3/findings.json`, `coverage-ledger.json`, `run-metadata.json`: 최종 레코드, 장부, 실행 기록. `agents/`에는 지시문, 결과, 승격된 산출물이 있다.
- `run-2/VALIDATION.md`: 5건 + 신규 1건의 재현·관측·수정 요약(한국어).
- `run-2/N-1-OPTIONS.md`: N-1 대응 방안 8가지 비교와 권장 조합, 결정할 것.
- `run-2/findings.json`: 현재 기준 전체 10건 구조화 레코드(확정 9 · 기각 1, 검증기 통과). 트레이스 줄 번호는 감사 기준 커밋 `7fc501f` 기준이다.
- `run-2/repro/`: 재현 스크립트 8개. `run-2/n1-terminal-via-gui-tools.png`: N-1 증거 스크린샷.
- `run-1/`: 1차 감사 산출물(REPORT, FINDINGS-DETAIL, NEEDS-VALIDATION, findings, coverage-ledger, architecture, run-metadata). 기록으로 두고 고치지 않는다.

## 3차 감사(run-3) 진행 상태 — 다음 세션이 여기서 이어받는다

작업 브랜치: `ccr-e2c70e17-r0gmhn` (`ccr-0da6ba34-sc9pu1`의 `d2537f0`에서 이어받음. 그 전은 `ccr-df7eb88d-1nmb5q`, PR #7). draft PR #8. **1~6단계를 마쳤고, 이어서 4차 헌팅을 하다 소유자의 사용량 한도로 멈췄다. `run_status: incomplete`(`owner_usage_limit`)다.** 보고서는 `run-3/REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`에 있다.

### 최종 결과 (`run-3/findings.json` 14건, 두 검증기 통과)
| 판정 | 심각도 | ID | 내용 | 수정 |
|---|---|---|---|---|
| 확정 | high | v11 | 유휴 GUI 구간 닫기가 남의 샌드박스 스레드와 사람 승인·감사 스레드에서 제한 시간 없는 docker exec로 돎 | 아직 |
| 확정 | medium | v02 | 감사 타임라인이 오래된 5000행에서 멈춤 | `3587c9c` |
| 확정 | medium | v05 | 사람 토큰을 바꿔도 브라우저 세션 유지 | `3587c9c` |
| 확정 | medium | v08 | 도구 인자가 크기 제한 없이 감사 로그에 기록 | `e63922c` |
| 확정 | medium | v12 | 복원·일시정지 때 GUI 구간 상태 유실 | 아직 |
| 확정 | medium | v13 | 웹 승인 카드의 방향 제어 문자 | 아직 |
| 확정 | low | v03 | `agentbox agent` 터미널 출력의 제어 문자 | 아직 |
| 확정 | low | v06 | `source_dir` 겹침 검사를 별칭으로 우회 (5단계에서 검증 필요→확정, l8 근거) | `152b8e4` (원본 폴더 안쪽에 마운트된 데이터 폴더는 못 막음) |
| 검증 필요 | — | v10 | X가 멈추면 `gui_lock`을 쥔 채 무기한 → 사람의 화면 인수가 막힘 | 아직 |
| 검증 필요 | — | v09 | GUI 구간 열 때 수집 실패를 성공으로 처리 | 아직 |
| 검증 필요 | — | v15 | `gui_strays`가 창 소유로 정리 대상에서 뺌 (근본 원인을 넓힘) | — |
| 검증 필요 | — | v14 | frame-ancestors/X-Frame-Options 없음 | — |
| 검증 필요 | — | v01 | `same_origin`이 scheme을 비교하지 않음 | — |
| 기각 | — | v04 | runc 별칭으로 runc 차단 우회 (운영자 설정, 경계 없음) | — |

### 5단계 (이번 세션)
- **검증 소스와 실행:** 검증자는 감사 소스 worktree(`8e4db9e`)를 읽고, 그 소스를 `/target`으로 붙인 `sbx5`로만 코드를 돌렸다. `sbx5`는 `tools/sbx`에서 `SRC=<scratchpad>/src-audited` 한 줄만 다르다.
- **도구:**
  - `tools/gen5.py`: 지시문 생성. `p5r-<id>`를 주면 재확인용 지시문을 만든다.
  - `tools/ingest5.py`: 결과 수거와 형식 검사. 환경 변수 `AUDIT_SCRATCHPAD`가 필요하다.
  - `tools/apply5.py`: 최종 레코드, 장부, 메타데이터 반영.
- **검증자:** Sonnet 레코드 검증자 13개(`agents/p5-*`)와 Opus 재확인 4개(`agents/p5r-*`). 형식 오류로 버린 결과는 없다.
- **결과:**
  - verified 7건: v02, v03, v05, v11, v12, v13, v14
  - 큰 변경이 아니라 바로 반영 2건: v01(문구), v08(수정 방향. 원래 수정안이 `write_file` 분기에서 먼저 반환하는 결함)
  - 큰 변경이라 재확인 뒤 반영 4건: v06(확정 low로 승격), v09, v10, v15
- **예산:** 소유자가 63까지 승인했고 62개를 썼다.

### 남은 것 (소유자의 사용량 한도로 멈춘 지점)
예산을 80으로 올린 뒤 4차 헌팅을 했다. 70개를 썼다.
- 결과: 헌터 `h-preview`, `h-queue`, `h-autostart`가 각자 후보를 하나씩 냈다. v16(부모가 실측한 pid 한도 후보)은 3단계에서 기각했고 `findings.json`에 넣었다. v17(영향 표 누락)은 3단계에서 확정 low로 통과했다.
- 멈춘 것: critic-3, v18, v19는 사용량 한도 때문에 멈췄다.

이어서 할 순서는 다음과 같다. 지시문은 모두 커밋돼 있다. `AUDIT_SCRATCHPAD`와 스크래치패드 경로만 새 세션 값으로 바꾸고, `tools/gen3.py`와 `tools/gen_critic.py`로 다시 만들 수 있다.
1. `agents/v18/prompt.md`, `agents/v19/prompt.md`로 3단계 검증자를 돌린다. 결과는 `tools/ingest.py`로 수거한다. v19에는 l12가 근거로 들어 있다.
2. `agents/critic-3/prompt.md`로 4차 뒤 비평을 돌린다. 새 작업이 없으면 최종 비평(`gen_critic.py critic-4 final-clean ...`)을 돌린다.
3. v17, v18, v19 레코드를 `findings.json`에 넣고 5단계 검증을 돌린다(`gen5.py`의 FP 표에 추가). 이어서 `apply5.py` 방식으로 반영하고 `gen6.py`로 보고서를 다시 만든다.
4. 확정 건 수정과 회귀 테스트(아래 목록), 그리고 PR.

수정한 것 (`c1f88da`, 회귀 테스트 포함. 내용은 REPORT 3.1·3.5·3.6과 4절 아래 메모):
- v11·v10: GUI와 수집 exec에 컨테이너 쪽 `timeout -k`, 유휴 구간 닫기는 전용 스레드, 인수·반환은 30초 상한과 대기 중 에이전트 GUI 차단
- v12: 일시정지 전 구간 닫기, 일시정지·재개·복원·삭제 때 타이머 초기화, 구간에 `container_id`, 닫기 실패는 `gui_burst_close_failed`
- v13: 웹 템플릿 `finalize`로 모든 출력의 제어·bidi 문자를 보이는 이스케이프로
- v09(일부): 수집 exec 종료 코드 확인, 기준을 못 읽으면 `gui_burst_open_failed`. fail-closed는 아직

남은 수정 목록:
- v03: `cmd_agent.log`에 줄 단위 `_safe`
- v09 나머지: 기준을 못 읽었을 때 GUI 입력을 막을지(fail-closed) 결정
- v14: X-Frame-Options SAMEORIGIN + frame-ancestors 'self'
- v06 남은 틈: `cp -ax` 또는 하위 경로 검사
- v17: preview가 모델링하지 못한 구간마다 경고를 단다

### 이어서 하는 법 (환경)
1. `nohup dockerd >/tmp/dockerd.log 2>&1 &`
2. `pip install -e '.[test]' pyte`
3. `docker pull buildpack-deps:noble-curl ubuntu:24.04`. 429가 나면 `mirror.gcr.io/library/<이미지>`를 받아 `docker tag`한다.
4. `docker build -t agentbox-desktop:0.1 images/desktop`
5. 스크래치패드에서 `git clone --depth 1 https://github.com/cloudflare/security-audit-skill skill`
6. `run-3/tools/`의 `sbx`, `ingest.py`, `promote.py`, `ingest5.py`를 스크래치패드로 복사한다. 그중 `sbx`, `ingest.py`, `promote.py` 안의 스크래치패드 경로는 새 세션 값으로 바꾼다. `ingest5.py`는 경로 대신 환경 변수 `AUDIT_SCRATCHPAD`를 쓰므로 고칠 것이 없다. `sbx`에는 호스트 `python3`가 `/etc/alternatives`를 거치는 경우를 위해 그 폴더를 읽기 전용으로 붙여 두었다.
7. 감사 소스가 필요하면 `git worktree add --detach <scratchpad>/src-audited 8e4db9e`를 실행하고 `sbx5`를 만든다(위 참고).
8. 검증자별 `agents/<id>/scratch`는 `chown 65534`로 미리 만든다. `gen5.py`가 대신 해 준다.

이번 세션 확인 결과: 전체 pytest 214개 통과. CI의 acceptance가 건너뛴 테스트를 실패로 처리하므로, 바인드 마운트 테스트가 root가 아니면 `sudo -n`을 쓰게 고쳤다(`192019f`).
