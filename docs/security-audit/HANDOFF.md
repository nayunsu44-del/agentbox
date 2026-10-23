# 보안 감사 핸드오프 (agentbox)

다른 세션이 이어받기 위한 요약. 근거는 `docs/security-audit/run-1/`(1차 감사)과 `docs/security-audit/run-2/`(실측 검증)에 있다.

## 한눈에 보기

- **무엇:**
  - run-1: Cloudflare `security-audit` 스킬(6단계)로 agentbox 전체를 감사했다. 기준 커밋 `7fc501f`.
  - run-2: run-1이 남긴 needs_validation 5건을 실제 Docker에서 검증했다.
- **브랜치·PR:** run-4는 `ccr-17444317-ygb3a1`, draft PR #15(아래 "4차 감사(run-4) 결과"). run-3은 `ccr-e2c70e17-r0gmhn`, draft PR #8(아래 "3차 감사(run-3) 진행 상태"). run-1·2 때 작업 브랜치는 `ccr-e10bee8e-6wt669`. PR #1(감사 수정·CI), #2(화면 링크 세션 범위), #3(FIFO), #4(runc 차단), #5(GUI 백그라운드 정리·세션 만료, `8e4db9e`)는 `main`에 병합됐다. 병합할 때마다 작업 브랜치를 최신 `main`에서 다시 시작한다.
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
| 확정 | high | v11 | 유휴 GUI 구간 닫기가 남의 샌드박스 스레드와 사람 승인·감사 스레드에서 제한 시간 없는 docker exec로 돎 | `c1f88da` |
| 확정 | medium | v02 | 감사 타임라인이 오래된 5000행에서 멈춤 | `3587c9c` |
| 확정 | medium | v05 | 사람 토큰을 바꿔도 브라우저 세션 유지 | `3587c9c` |
| 확정 | medium | v08 | 도구 인자가 크기 제한 없이 감사 로그에 기록 | `e63922c` |
| 확정 | medium | v12 | 복원·일시정지 때 GUI 구간 상태 유실 | `c1f88da` |
| 확정 | medium | v13 | 웹 승인 카드의 방향 제어 문자 | `c1f88da` |
| 확정 | low | v03 | `agentbox agent` 터미널 출력의 제어 문자 | `28fd4c9` |
| 확정 | low | v06 | `source_dir` 겹침 검사를 별칭으로 우회 (5단계에서 검증 필요→확정, l8 근거) | `152b8e4`, 안쪽 마운트는 `28fd4c9`(NonRecursive 바인드) |
| 확정 | low | v17 | 승인 카드 영향 표가 `rm`과 섞인 조각을 경고 없이 뺌 | `e0add14` |
| 확정 | low | v18 | 승인 캡처 PNG가 지워지지 않고 대기 수 상한 없음 | `e0add14` |
| 확정 | low | v19 | `/home/desktop` autostart가 스냅샷을 거쳐 복원 뒤 uid 1001로 다시 실행 | `e0add14` |
| 검증 필요 | — | v10 | X가 멈추면 `gui_lock`을 쥔 채 무기한 → 사람의 화면 인수가 막힘 | `c1f88da`(판정과 별개로 막음) |
| 검증 필요 | — | v09 | GUI 구간 열 때 수집 실패를 성공으로 처리 | `c1f88da`(일부) |
| 검증 필요 | — | v15 | `gui_strays`가 창 소유로 정리 대상에서 뺌 (근본 원인을 넓힘) | — |
| 검증 필요 | — | v14 | frame-ancestors/X-Frame-Options 없음 | `28fd4c9`(판정과 별개로 막음) |
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

### 재개 세션 (사용량 한도 뒤)
예산 80 중 77을 썼다. `run_status`는 `incomplete`이고 사유는 `budget_exhausted`다.
- **3단계:** v18·v19를 다시 돌렸고 둘 다 확정 low였다(Sonnet).
- **critic-3:** 새 단위 3개를 냈다(`stop: false`).
  - 인증 전 요청이 하는 일
  - GUI 구간 상태의 스레드 간 경쟁
  - 디스크·SQLite 압박 때의 감사 읽기와 기록 유실

  세 단위는 장부에 `deferred`로 남겼다(`tools/intake_wave3.py`). 첫 실행은 컨테이너 재시작으로 끊겨 다시 돌렸다.
- **5단계:** v17~v19 모두 verified였다(Sonnet, `tools/apply5_wave3.py`). 다만 셋 다 도구 호출이 5~6회로 짧았다.
- `findings.json`은 18건이다. 확정 11(high 1, medium 5, low 5), 검증 필요 5, 기각 2. 장부는 29단위다. 검사기 둘 다 PASS.

수정한 것. 모두 회귀 테스트가 있고, 새 테스트는 수정 전 코드나 이미지에서 실패하는 것을 확인했다.
- **`c1f88da`**
  - v11·v10: GUI와 수집 exec에 컨테이너 쪽 `timeout -k`를 씌웠다. 유휴 구간 닫기는 전용 스레드에서 돈다. 인수·반환은 30초 상한이 있고, 인수를 기다리는 동안 에이전트 GUI 도구를 막는다.
  - v12: 일시정지 전에 구간을 닫는다. 일시정지·재개·복원·삭제 때 타이머를 초기화한다. 구간에 `container_id`를 기록하고, 닫기에 실패하면 `gui_burst_close_failed`를 남긴다.
  - v13: 웹 템플릿 `finalize`로 모든 출력의 제어·bidi 문자를 보이는 이스케이프로 바꾼다.
  - v09(일부): 수집 exec의 종료 코드를 확인한다. 기준을 못 읽으면 `gui_burst_open_failed`를 남긴다.
- **`28fd4c9`**
  - v03: 에이전트 출력에 줄마다 `_safe`를 건다.
  - v14: `X-Frame-Options`와 `frame-ancestors 'self'`를 붙인다.
  - v06 남은 틈: 원본을 NonRecursive 바인드로 붙인다. `cp -ax`는 같은 디스크의 바인드 마운트를 못 거른다.
- **`e0add14`**
  - v18: 캡처는 결정·만료·삭제 때 지운다. 승인 대기는 샌드박스마다 20개까지다.
  - v19: 데스크톱 이미지가 시작할 때마다 `/home/desktop`을 처음 상태로 되돌린다. 이미지를 다시 빌드해야 한다.
  - v17: 영향 표에 조각마다 "계산 못 함"을 단다.

남은 것:
- critic-3의 보류 단위 3개를 헌팅하고 검증한 뒤 최종 비평(`gen_critic.py critic-4 final-clean ...`)을 돌린다. 예산을 새로 정해야 한다.
- 검증 필요 5건의 로컬 계획(NEEDS-VALIDATION.md).
- v09 나머지는 소유자 결정으로 fail-closed로 했다(병합 뒤 후속 PR). 기준을 못 읽으면 구간을 여는 GUI 입력을 실행하지 않고 503을 준다.
- 소유자 결정: 검증은 다음 run(run-4)에서 다시 돌린다. 보류 단위 3개와 이번 수정이 바꾼 소스를 포함한다.
- 다음 감사에서는 이번 수정이 바꾼 소스를 다시 검증 단위로 넣는다.

### 이어서 하는 법 (환경)
1. `nohup dockerd >/tmp/dockerd.log 2>&1 &`
2. `pip install -e '.[test]' pyte`
3. `docker pull buildpack-deps:noble-curl ubuntu:24.04`. 429가 나면 `mirror.gcr.io/library/<이미지>`를 받아 `docker tag`한다.
4. `docker build -t agentbox-desktop:0.1 images/desktop`
5. 스크래치패드에서 `git clone --depth 1 https://github.com/cloudflare/security-audit-skill skill`
6. `run-3/tools/`의 `sbx`, `ingest.py`, `promote.py`, `ingest5.py`를 스크래치패드로 복사한다. 그중 `sbx`, `ingest.py`, `promote.py` 안의 스크래치패드 경로는 새 세션 값으로 바꾼다. `ingest5.py`는 경로 대신 환경 변수 `AUDIT_SCRATCHPAD`를 쓰므로 고칠 것이 없다. `sbx`에는 호스트 `python3`가 `/etc/alternatives`를 거치는 경우를 위해 그 폴더를 읽기 전용으로 붙여 두었다.
7. 감사 소스가 필요하면 `git worktree add --detach <scratchpad>/src-audited 8e4db9e`를 실행하고 `sbx5`를 만든다(위 참고).
8. 검증자별 `agents/<id>/scratch`는 `chown 65534`로 미리 만든다. `gen5.py`가 대신 해 준다.

이번 세션 확인 결과: 전체 pytest 231개 통과(재개 세션, 실제 Docker와 다시 빌드한 데스크톱 이미지, 건너뛴 것 없음). 이전 세션은 214개. CI의 acceptance가 건너뛴 테스트를 실패로 처리하므로, 바인드 마운트 테스트가 root가 아니면 `sudo -n`을 쓰게 고쳤다(`192019f`).

## 4차 감사(run-4) 결과 — 2026-10-23 (부분 감사, 확정 8건 수정 완료)

- **기준과 브랜치:** 작업 브랜치 `ccr-17444317-ygb3a1`, draft PR #15. 감사 기준은 `main` `9805d91`(리팩토링 PR #11~#14 뒤)이다.
- **프로필·예산:** `standard`, 호출 상한 50을 **모두** 썼다.
- **상태:** `run_status: incomplete`(`budget_exhausted`). 비평이 제안한 3단위(critic-1 2개, critic-2 1개)를 헌팅하지 못했다.
- **보고서(한국어):** `run-4/REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`. 영어 레코드 원문은 항목마다 접어 두었다.

### 진행 경과
1. **정찰(리눅스, Opus 4회):** `architecture.md`와 30단위 장부를 만들었다.
2. **2~6단계 1차(Windows DeepSeek 하네스, 46회):** 소유자 지시로 모든 서브에이전트를 DeepSeek(`deepseek-ai/DeepSeek-V4.1-Flash`)로 돌렸다.
3. **검토 보완(리눅스, 4회):** DeepSeek를 쓸 수 없는 환경이라 소유자 승인으로 Opus·Sonnet을 썼다.
   - 1차에서 판정 없이 빠진 후보 v11을 v11(Opus)이 다시 검증했다. r13(Sonnet)이 레코드를 확인했다.
   - 부모가 실제 Docker로 v11을 재현했고, r14(Opus)가 확정 승격을 검증했다.
   - 최종 비평 critic-2(Opus)를 돌렸다.
   - critic-1의 2단위를 장부에 `deferred`로 넣었다. 승인 카드 단위의 잘못 매핑된 검사를 바로잡았다.
   - 도구를 리눅스로 이식했고, 보고서를 한국어로 다시 썼다.

### 결과 (`run-4/findings.json` 13건, 두 검증기 PASS)
| ID | 판정 | 심각도 | 내용 | 지문 파일 |
|---|---|---|---|---|
| F1 | 확정 | 중간 | 인증 전 요청 본문을 끝까지 읽고 해석·임시 저장한 뒤 401 | `api.py` |
| F2 | 확정 | 중간 | 인계 사이 `gui_lock`을 기다리던 GUI 입력이 구간 없이 실행 → 스냅샷·`gui_changes` 없음 | `service.py` |
| F3 | 확정 | 중간 | 승인 미리보기·도구 오류 문자열로 감사 로그 상한 우회(run-3 v08 수정이 덜 막음) | `service.py` |
| F4 | 확정 | 낮음 | 승인 카드 `rm` 영향 표가 공백·줄바꿈 경로를 잘못 표시 | `sandbox.py` |
| F5 | 확정 | 낮음 | 인증 없는 `/static/novnc/*`가 요청마다 `docker create`와 tar 추출 | `sandbox_desktop.py` |
| F6 | 확정 | 낮음 | 복원과 삭제가 겹치면 삭제한 샌드박스와 토큰이 되살아남(parent-live 6회 중 5회) | `service.py` |
| F7 | 확정 | 낮음 | 스냅샷 상한 TOCTOU: `touch`와 `write_file`을 겨루면 승인 없이 커밋(parent-live 21회 중 18회) | `service.py` |
| F8 | 확정 | 낮음 | 인증 없는 로그인 실패마다 지울 수 없는 감사 행 | `web.py` |
| N1~N5 | 검증 필요 | — | `same_origin` scheme 무시, 감사·승인 행 무제한, 컨테이너 출력 리더 상한 부재, `_NET_WM_PID` 신뢰, 남은 bidi/보이지 않는 문자 | |

### 남은 일
1. **확정 8건 수정.** 제안 순서: F1·F3(인증 전·감사 상한) → F2·F7(스냅샷 게이트를 락 안에서 다시 판단) → F6(수명 주기 락) → F4·F5·F8.
   - **F1·F3 수정 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #16 병합).
     - F1: `_BodyLimit` 미들웨어가 본문을 읽기 전에 413을 준다(`AGENTBOX_MAX_BODY` 8MB, `AGENTBOX_MAX_UPLOAD_BODY` 256MB). 파일 넣기는 인증한 뒤 폼을 읽고, Caddyfile에 `request_body` 상한을 넣었다.
     - F3: `AuditLog.append`가 해시를 계산하기 전에 payload를 묶는다(문자열 64KB, 목록 200개, 한 행 128KB).
     - 회귀 테스트 4개(`test_m4_unit.py`, `test_m4_acceptance.py`)는 수정 전 코드에서 실패한다. 전체 pytest 237개 통과.
   - **F2·F7 수정 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #17 병합).
     - F2: `_run_tool`이 `gui_lock`을 잡고 제어 확인을 마친 뒤, 열린 구간이 없으면 GUI 입력을 실행하지 않는다(`GuiBursts.covers`, 400). 입력 시각을 남기지 않으므로 다시 부르면 새 스냅샷과 구간을 연다.
     - F7: 허용 경로의 커밋 직전에 스냅샷 상한을 다시 확인한다. 상한 이상이면 커밋하지 않고 409와 `tool_blocked`(`snapshot_quota_changed`)를 남긴다. 다시 부르면 승인 요청으로 간다.
     - 회귀 테스트 2개(`test_m2_unit.py`)는 수정 전 코드에서 실패한다. 전체 pytest 239개 통과.
   - **F6·F4·F5·F8 수정 완료**(브랜치 `ccr-534dd824-2jgcsj`, 건마다 커밋, PR #18 병합).
     - F6: `AgentBox._lifecycle`가 일시정지·재개·스냅샷·복원·삭제를 샌드박스마다 직렬화한다. `SandboxManager.restore`는 `deleted`를 거절하고, 마지막 상태 쓰기를 `status != 'deleted'` 조건으로 해서, 그사이 삭제됐으면 새 컨테이너를 지우고 실패한다.
     - F4: 미리보기 `_expand`는 `IFS=`로 단어를 쪼개지 않고 NUL로 나누며, `_walk`는 `find -print0 | head -z`를 쓴다.
     - F5: noVNC 꺼내기는 잠금 아래 한 번만 한다. 실패하면 60초 동안 다시 하지 않고, 예외는 500 대신 404다.
     - F8: 로그인 실패는 1분에 5개까지만 하나씩 기록하고, 나머지는 센 수(`suppressed_before`)로 다음 기록에 붙인다. `/login`과 Bearer 토큰 비교를 바이트로 바꿔 ASCII 밖 입력의 500을 없앴다.
     - 회귀 테스트 6개(`test_m4_acceptance.py`)는 모두 수정 전 코드에서 실패한다. 전체 pytest 244개 통과.
   - **확정 8건을 모두 고쳤다.** 검증 필요 건 중 확정 후보였던 N2·N4·N5도 아래처럼 고쳤다. 남은 것은 N1·N3, 보류 3단위, 다음 run이다.
   - **N5 수정 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #19 병합). `display.escape_controls`가 문자를 손으로 나열하지 않고 유니코드 범주 Cc·Cf·Zl·Zp로 고른다. U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028, U+2029와 태그 문자까지 `\uXXXX`로 보인다. 웹(`web._shown`)과 터미널(`cli._safe`)이 같이 쓴다. 회귀 테스트 1개(`test_m4_unit.py`)는 수정 전 코드에서 실패한다.
   - **N2 1단계 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #20 병합). 디스크가 차도 사람이 수습할 수 있게 했다.
     - 디스크 여유 보호선: DB가 있는 디스크의 남은 공간이 `AGENTBOX_MIN_FREE`(기본 256MB)보다 적으면 에이전트 도구 호출은 507로 받지 않고, 에이전트의 승인 시도(`approval_forbidden`)도 기록하지 않는다. 사람의 삭제·승인·반환은 남은 공간을 쓴다. 상태가 바뀔 때만 `disk_low`·`disk_ok`를 남긴다.
     - 끝난 승인(실행·거절·실패·만료)은 원본 인자 대신 감사 로그와 같은 모양(크기·sha256·앞부분 16KB)만 남기고, 미리보기도 `bound_payload`로 묶는다.
     - 디스크가 찼을 때 승인 결정이 처리되지 않은 `OperationalError`(500)를 내던 것을 503으로 바꾸고, 기한 처리(`expire_stale`)가 조회를 막지 않게 했다.
     - 회귀 테스트 3개(`test_m4_unit.py`)는 수정 전 코드에서 실패한다. 전체 pytest 248개 통과.
   - **N2 2단계 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #21 병합). 운영자가 호스트에서 실행하는 정리 명령을 넣었다(`retention.py`, HTTP API로는 열지 않음).
     - `agentbox prune --before <시각> --archive <파일> [--dry-run]`: 기준 시각보다 오래된 앞쪽 감사 행과 끝난 승인 행을 아카이브(gzip JSON Lines)로 먼저 내보낸 뒤 지운다. 아카이브를 못 쓰면 지우지 않고, 있는 파일은 덮어쓰지 않으며, 미래 시각은 거절한다.
     - 한 트랜잭션에서 지우고, 기준점(`audit_anchor`: 지운 마지막 행의 id·해시, 아카이브 sha256)과 `audit_pruned` 항목을 남긴다. 기준점 표도 트리거로 고치거나 지울 수 없다.
     - `verify()`는 기준점부터 검사하고 `pruned_through`를 돌려준다. 기준점이 있는데 표가 비어 있으면 실패한다(예전에는 빈 로그가 통과).
     - `agentbox verify --archive a1 --archive a2 …`: 아카이브들과 지금 표를 처음부터 이어 검사한다. 아카이브 수·sha256·마지막 행이 기준점과 맞아야 한다.
     - 테스트 7개(`tests/test_retention.py`). 남은 한계: 기준점이 같은 DB 안에 있어, DB를 직접 고칠 수 있는 사람의 위조는 막지 못한다(바깥 앵커는 README 알려진 한계에 남김).
   - **N4 수정 완료**(브랜치 `ccr-534dd824-2jgcsj`, PR #22 병합). 방향은 A(위조만 막고 동작은 유지)로 정했다.
     - 창 주인을 `xdotool getwindowpid`(창이 스스로 적는 `_NET_WM_PID`) 대신 X-Resource 확장(`XResQueryClientIds`)으로 X 서버에 묻는다. X 서버가 소켓 상대(SO_PEERCRED)로 아는 pid라 남의 pid를 댈 수 없다. 이미지에 있는 `libXRes`와 `python3 -I`로 돌리고, 실패하면 창이 없는 것으로 본다(더 많이 멈추는 쪽).
     - 구간이 끝날 때 창이 있어 남긴 프로세스는 `gui_processes_kept`로 기록하고, 다음 구간의 기준(baseline)에 넣지 않아 끝날 때마다 다시 판단한다. 예전에는 한 번 남으면 영영 면제됐다.
     - 실제 이미지에서 위조 창(`_NET_WM_PID`=데몬 pid)의 주인이 위조한 프로세스로 나오는 것을 확인했다. 회귀 테스트 3개(`test_unit.py` 보강, `test_m4_unit.py`, `test_m4_acceptance.py` 실데스크톱)는 수정 전 코드에서 실패한다.
     - 남은 한계(README에 적음): 프로세스가 직접 창을 띄우면 남는다. 선택지 B(창과 관계없이 모두 정리)는 앱이 쉬면 닫히는 비용 때문에 택하지 않았다. X 서버가 화면 계정으로 돌아 그 계정이 X 서버를 바꿔치기하는 것은 막지 못한다.
2. **보류 3단위**는 다음 run의 1순위다.
   - 데스크톱 WebSocket이 `ws.accept()` 전에 동기 SQLite·Docker를 호출한다.
   - 승인 테이블이 마스킹·상한 없이 남는다. (상한·정리는 N2 1·2단계에서 넣었다. 마스킹은 아직이다.)
   - 인수 중 열리는 에이전트 GUI 구간(critic-2).
3. **검증 필요 5건**은 run 뒤에 부모가 실측했다(`run-4/agents/parent-live/`, 에이전트 예산 밖). 판정은 그대로다. 바꾸려면 새 검증자 예산이 필요하다.
   - N2(감사·승인 행 무제한), N4(`_NET_WM_PID` 위조), N5(ALM으로 `>`가 `<`로 보임)는 저장소 쪽 막힌 지점이 모두 풀린 **확정 후보**다. N5는 위 1번에서 고쳤다.
   - N1은 Chromium에서 강제 로그아웃만 성립한다. Firefox·WebKit은 확인하지 못했다.
   - N3은 증가가 선형이고 제한 시간으로 묶여 낮음이나 하드닝 쪽이다.
   - 남은 배포 사실: 데이터 볼륨 크기, 컨테이너 메모리 제한, 운영자가 쓰는 브라우저.
4. **최종 비평(critic-2)**은 `stop: false`였고 새 경계 1개를 냈다. 사람이 화면을 인수한 동안 `decide`나 `call_tool` 스냅샷이 에이전트 GUI 구간을 열어, 사람이 띄운 프로세스를 죽이거나 사람 편집을 에이전트 기록으로 남길 수 있는지다. 예산이 없어 `deferred`로 넣었다. 그래서 보류는 **3단위**이고, 깨끗한 커버리지는 주장하지 않는다.
5. **추후 개선(소유자 지시, 2026-10-23): LLM 공급자로 가는 데이터.** 샌드박스 네트워크 차단과 별개로, 에이전트 루프가 도구 결과(파일 내용, 명령 출력, 화면 캡처)를 LLM API로 보내는 길은 컨트롤 플레인이 보지도 막지도 않는다. README "알려진 한계"에 적고 개선 후보(도구 결과 비밀값 가림, 민감 경로 읽기 승인, 돌려준 결과의 크기·해시 기록, LLM 호출을 컨트롤 플레인·프록시 경유)를 남겼다. 다음 감사 run의 범위에 넣을지 정한다.

### 실행 환경 (리눅스에서 이어받을 때)
1. 서비스와 이미지를 준비한다.
   - `nohup dockerd >/tmp/dockerd.log 2>&1 &`
   - `pip install -e '.[test]' pyte`
   - `docker pull ubuntu:24.04 buildpack-deps:noble-curl`
   - `docker build -t agentbox-desktop:0.1 images/desktop`
2. 스크래치패드에 스킬과 감사 소스를 준비한다.
   - `git clone --depth 1 https://github.com/cloudflare/security-audit-skill skill`
   - `git worktree add --detach <scratchpad>/src-audited 9805d91`
3. `run-4/tools/common.py`는 호스트(`os.name`)에 따라 경로와 `sbx`를 고른다.
   - run 폴더 경로는 도구 파일 위치에서 계산한다.
   - 스크래치패드는 `AUDIT_SCRATCHPAD`로 준다. Windows(`sbx.py`, `common.py`, `parent_live_lifecycle.py`)에서는 반드시 설정해야 하고, 리눅스에서는 설정하지 않으면 기본값을 쓴다. 리눅스 bash `tools/sbx`의 `TARGET`·`LOG` 줄은 새 스크래치패드로 바꾼다.
   - 1차 Windows 기록의 사용자 경로는 `<WINDOWS_HOST_ROOT>`로 가렸다.
   - 승격은 `tools/promote_linux.py`, Windows에서는 `tools/promote.py`·`tools/sbx.py`를 쓴다.
4. 도구:
   - 지시문 생성: `gen_hunt.py`, `gen3.py`, `gen5.py`, `gen_critic.py`
   - 결과 반영: `apply.py`(3·5단계), `ingest_hunt.py`
   - 보고서: `gen6.py`(`ko_text.py`의 한국어 문장과 `report_notes.py`를 씀)
   - 1차 때 쓴 일회용 스크립트는 `tools/oneoff/`에 설명과 함께 모았다.
5. 검증기: `node <skill>/skills/security-audit/validate-findings.cjs run-4/findings.json`, `validate-coverage-ledger.cjs run-4/coverage-ledger.json`.
