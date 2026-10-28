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
6. **다음 감사(run-5) 계획(소유자 결정, 2026-10-23).** 프로필 standard, 호출 상한 **30**. 모델은 헌터만 Opus, 나머지(3단계 검증, 5단계 레코드 검증, 비평, 재확인)는 Sonnet. parent-live 실측은 예산 밖에서 부모가 한다.
   - 범위: 보류 3단위 + run-4 뒤 바뀐 코드 4단위(정리 명령·기준점 `retention.py`, 디스크 보호선·승인 행 줄이기, XRes 창 주인 확인, 본문 상한 미들웨어·업로드 폼). LLM 공급자 경로(5번)는 문서화한 한계라 헌팅에서 뺀다.
   - 예상: 헌터 7, 3단계 약 8, 5단계 약 8, 재시도 2, 비평 2, 정찰 갱신 1~2 → 약 28. 넘을 것 같으면 먼저 소유자에게 묻는다.

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

## 5차 감사(run-5) 결과 — 2026-10-23~24 (집중 후속 감사, 확정 6건 수정)

- **기준과 브랜치:** 감사 기준 `main` `346df29`(PR #16~#23 뒤), 작업 브랜치 `ccr-534dd824-2jgcsj`. 보고서는 `run-5/REPORT.md`(한국어), 상세는 `FINDINGS-DETAIL.md`·`NEEDS-VALIDATION.md`.
- **프로필·예산:** `standard`, 소유자 상한 30을 모두 썼다. 헌터 8(Opus), 나머지 Sonnet. 정찰은 부모가 했고(0회), 실제 Docker 확인 7건은 부모가 예산 밖에서 했다(`run-5/agents/parent-live/`).
- **결과(`run-5/findings.json` 8건, 두 검증기 PASS):** 확정 6(중간 1, 낮음 5), 검증 필요 1, 기각 1.
  - 중간: 에이전트 exec 한 번이 요청의 약 45배인 승인 대기 행을 써서 디스크 보호선을 한 번에 넘음(run-4 N2의 남은 부분).
  - 낮음: 인수 중 GUI 구간이 사람 프로세스를 멈춤(실제 데스크톱 재현), 정리 명령이 COMMIT 직후 중단되면 아카이브 삭제, 화면 웹소켓이 이벤트 루프에서 SQLite 대기, 긴 명령의 정책 파싱 CPU, 미리보기의 피연산자별 docker exec.
  - 검증 필요: 인증 없는 8MiB JSON이 401 전에 약 200MB를 씀. 512MiB 제한에서 동시 4건에 OOM(세 번 재현). 배포 메모리 제한에 달려 있다.
  - 기각: 삭제 중 커밋의 고아 이미지(실제 dockerd에서 커밋이 실패).
- **수정:** 소유자 지시로 확정 6건을 같은 PR에서 고쳤다. 새 회귀 테스트는 `tests/test_m5_unit.py`(9개)와 `tests/test_retention.py`(2개)이고 수정 전 코드에서 실패한다.
- **소유자 결정(2026-10-24):**
  - N1(인증 없는 JSON): (a)+(c)로 고쳤다(PR #25). 본문이 있는 요청은 토큰·로그인 세션이 유효해야 본문을 읽고(아니면 401, 로그인 폼만 64KiB까지), compose `mem_limit`(기본 2g), Caddy 경로별 본문 상한(파일 넣기 256MB, 나머지 8MiB), uvicorn `limit_concurrency`(기본 256). 같은 조건(512MiB, 동시 4·8건)에서 수정 뒤 최고 RSS 59MB, 서버 생존(`run-5/agents/parent-live/artifacts/preauth_json_512m_after_fix.json`).
  - 도구 인자 16KiB 상한: 소유자 결정으로 그대로 둔다(바꿀 실익이 없음. 큰 내용은 write_file로 보내면 된다).
  - policy-cpu 레코드: 다시 검토하기로 했다(재검증자 `rv2-policy-cpu`, 31번째 호출, 소유자 승인).
  - `same_origin`: 감사 없이 고치지 않고 run-6 범위에 넣는다.
- **run-6 계획(다른 세션에서 할 수 있음):**
  - 범위: run-5 보류 중 상위 4단위(`same_origin` scheme — run-4 N1, 컨테이너 출력 판독기 상한 — run-4 N3, 승인 미리보기가 실제 실행과 맞는지, `AuditLog._lock` 경합) + PR #24·#25가 바꾼 코드(`DesktopControl` 잠금 분리, `_snapshot`의 GUI 구간 개폐와 `decide` 인수 확인, `TOOL_ARG_MAX`·미리보기 상한, `_BodyLimit` 자격 증명 확인, `retention.prune` 정리).
  - 나머지 보류 3단위(GUI 입력 차단의 컨테이너 바인딩, 제어 문자 필터 출력 지점, Docker 디스크 계산)는 가치가 낮다고 비평이 매겼다. 예산이 남으면 본다.
  - 예산 약 20. 모델은 시작할 때 소유자가 지정한다(마지막 감사라 지금까지와 다른 모델을 쓸 수도 있다). 실제 Docker 확인은 부모가 예산 밖에서. 넘길 것 같으면 먼저 묻는다.
  - 시작 순서: (1) 아래 '실행 환경'대로 준비, (2) `run-5/tools`를 `run-6/tools`로 복사하고 `run-5`→`run-6`, `run-4`→`run-5`(이전 기록), 기준 커밋을 바꾼다(run-5 때 한 `sed`와 같다), (3) `seed5.py`를 본떠 `seed6.py`를 쓴다: run-5 장부의 `deferred` 단위를 `prior_deferred`로 옮기고 바뀐 코드 단위를 더한다. 제외 사유가 장부에 없는 단위(h-session 등)를 가리키지 않게 한다, (4) `architecture.md`에 0절(변경분)을 새로 쓴다, (5) `gen_hunt.py` → 헌터 → `ingest_hunt.py` → `gen3.py`/`apply.py 3` → `gen5.py`/`apply.py 5` → `gen_critic.py` → `gen6.py`.
  - run-5에서 배운 것: 헌터 결과는 단위 `reviewed_paths`가 검사들의 합집합과 같아야 한다(지시문에 미리 적었다). 검증자가 Docker 없이 가짜로 낸 경쟁 주장은 실제 dockerd에서 꼭 확인한다(삭제 중 커밋 건은 실제로는 성립하지 않았다). 사용량 한도로 멈춘 에이전트는 같은 에이전트로 이어 가면 된다.
- **실행 환경:** run-4와 같다. 도구는 `run-5/tools/`(seed5, gen_hunt, gen3, gen5, gen_critic, apply, ingest_hunt, promote_linux, apply_reverify, apply5_nonmaterial, intake_critic1/2, settle_xres, gen6). `common.py`의 스크래치패드 기본값과 `tools/sbx`의 `TARGET`·`LOG`를 새 세션 값으로 바꾼다.

## 6차 감사(run-6) 결과 — 2026-10-24 (보류 7단위 전체 + PR #24·#25 변경 4단위 완료, 보고 전용)

- **기준과 브랜치:** 감사 기준 `main` `530b29e`(PR #24·#25 반영 뒤), 작업 브랜치 `main`. 보고서는 `run-6/REPORT.md`(한국어), 상세는 `run-6/FINDINGS-DETAIL.md`·`run-6/NEEDS-VALIDATION.md`.
- **프로필·예산·모델:** `standard`, 소유자 상한 30 중 **20회**를 썼다(헌터 6, 3단계 검증 6, 5단계 레코드 검증 6, 비평 2, 모두 소유자 지시로 `flash` 모델). 정찰은 부모가 수행했고(0회), 실제 Docker 데몬과 데스크톱 이미지가 필요한 확인 5건은 부모가 일회용 컨테이너에서 직접 실측했다(`run-6/agents/parent-live/artifacts/`, 예산 밖).
- **결과(`run-6/findings.json` 6건, 두 검증기 PASS, `run_status: complete`):** 확정 3(중간 2, 낮음 1), 검증 필요 3, 기각 0. 장부 11단위는 모두 닫혔고(`covered` 5, `confirmed` 3, `needs_validation` 3), 사후 비평(`critic-1`)과 최종 비평(`critic-2`) 모두 빠진 단위 없이 `stop: true`를 반환했다.
  - **확정 F1(중간, `agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore`):** `GuiBursts.covers(sid)`가 `sid in self._gui_burst`만 보고 `burst['container_id'] == sandboxes.get(sid)['container_id']`를 확인하지 않으며, `restore_sandbox`가 `sandboxes.restore` 뒤에 `bursts.end` 대신 `reset_timers`만 호출한다. 복원 도중 옛 컨테이너 C1 기준으로 열린 구간이 복원 뒤에도 살아남아 새 컨테이너 C2의 GUI 입력이 통과하고, 구간이 닫힐 때 `_finish`가 컨테이너 불일치(`C2 != C1`)로 `_stop_strays`와 `diff_manifest`를 건너뛰어 C2에서 띄운 백그라운드 프로세스가 살아남고 다음 구간의 기준(baseline)에 들어간다(일회용 실제 데스크톱 컨테이너와 샌드박스에서 모두 재현).
  - **확정 F2(중간, `agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory`):** `audit` 테이블에 `sandbox_id` 인덱스가 없어 웹 화면(`templates/sandbox.html`)이 3초마다 폴링하는 `AuditLog.recent()`가 전역 `AuditLog._lock`을 잡은 채 전체 리프·오버플로 페이지를 스캔하고, `AuditLog.verify()`는 `_lock` 아래에서 `.fetchall()`로 전체 행을 한꺼번에 파이썬 메모리에 올린다(25.2KiB 페이로드 1,200행/30.5MiB DB에서 무인덱스 `recent()` 평균 175.15ms vs 인덱스 적용 시 28.86ms로 6.07배 단축, `verify()`는 `_lock` 5.63초 점유·58.64MiB 힙 사용; 10,000행 외삽 시 3초 폴링마다 1.46초 점유, `verify()` 46.9초·488.6MiB).
  - **확정 F3(낮음, `agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets`):** 승인 미리보기(`_expand`)는 컨테이너 `/bin/sh`(dash)에서 위치 인자 `$1`을 써서 중괄호(`rm {a,b}.txt`)와 틸드(`rm ~/file`)를 확장하지 못하고 `삭제 시도 (현재 존재하지 않음)` 및 빈 `notes`를 돌려주지만, 승인 뒤 실제 실행(`exec`)은 `/bin/bash`로 돌아 실제 파일을 삭제한다(일회용 실제 컨테이너와 샌드박스에서 재현).
  - **검증 필요 N1(`agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare`):** `same_origin`이 `netloc`만 비교하고 스킴(`http` vs `https`)이나 빈 `Origin`을 구분하지 않으며 `deploy/Caddyfile`에 HSTS가 없다. 실제 악용은 운영자 브라우저의 Schemeful Same-Site 적용 여부와 평문 HTTP 도달 가능성에 달려 있다.
  - **검증 필요 N2(`agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap`):** `list_dir`·`outbox_list`·`_expand`·`screenshot`이 `_Head` 스트리밍 상한 없이 `c.exec_run`으로 전체 출력을 먼저 메모리에 모으며 `list_dir`·`outbox_list`에는 `_timed`도 없다. 실제 OOM·고갈 여부는 배포 메모리 제한(`mem_limit: 2g`)과 컨테이너 파일 수 한도에 달려 있다.
  - **검증 필요 N3(`agentbox/service.py:disk_low-unmonitored-docker-data-root`):** `disk_low()`가 `db_path.parent`만 검사하고 Docker `DockerRootDir`(`container upperdir`·`c.commit` 스냅샷 이미지가 쌓이는 경로)는 보지 않으며 `disk_limit` 기본값은 빈 문자열이다. `AGENTBOX_HOME`과 `/var/lib/docker`가 다른 파티션·볼륨으로 분리된 배포에서 507 보호선이 동작하지 않는다.
- **PR #24·#25 및 PR #19 검증 완료(`covered` 5단위):**
  - PR #24가 고친 `DesktopControl` 잠금 분리(`_db_lock` vs `_lock`)·웹소켓 스레드풀 오프로드·`retention.prune` COMMIT 뒤 아카이브 보존, `_snapshot`/`call_tool`/`decide`의 화면 인수 중 GUI 구간 열기 차단, `TOOL_ARG_MAX`(16KiB)·`_relex_changes`·미리보기 40회/50메모 상한·대기 승인 행 128KiB 상한이 모두 지켜짐을 확인했다.
  - PR #25가 고친 `_BodyLimit` 본문 읽기 전 자격 증명 확인(`authenticated` 콜백, `/login` 64KiB 상한)과 배포 설정 상한이 지켜짐을 확인했다.
  - PR #19의 제어문자 필터(`display.escape_controls`, 웹 `finalize=_shown` 및 CLI `_safe`)가 모든 출력 지점을 덮어 run-4의 미해결 리드(`exec-command-bidi-controls-unneutralized`)가 해소됨을 확인했다.
- **후속 수정 완료:** 보고 직후 소유자 지시("수정해서 사용에 영향없는건 보고 없이 수정해")에 따라 정상 사용에 영향을 주지 않는 확정 3건(F1~F3)과 검증 필요 하드닝 3건(N1~N3)을 모두 수정하고 `tests/test_m5_unit.py`에 회귀 테스트 6건을 추가해 검증했다:
  - `agentbox/gui_bursts.py`·`agentbox/service.py`: `GuiBursts.covers(sid)`의 `container_id` 일치 확인 및 `restore_sandbox`의 `self.bursts.end(sid, "sandbox_restored")` 호출.
  - `agentbox/audit.py`: `idx_audit_sandbox_id ON audit (sandbox_id, id)` 복합 인덱스 추가 및 `verify()`·`verify_archives()`의 200행 배치 조회·`_lock` 외부 해시 계산(`_verify_live`).
  - `agentbox/preview.py`·`agentbox/sandbox.py`: `{`·`~` 확장 주의 문구 및 미매칭 피연산자 안내 문구 보강, `_expand`의 `~`/`~/` → `$HOME` 확장 및 `head -z -n` 상한.
  - `agentbox/api.py`·`agentbox/web.py`·`deploy/Caddyfile`: `secure_cookie` 활성 환경에서 `same_origin`의 `https` 스킴 검증 및 Caddy HSTS 헤더 추가.
  - `agentbox/sandbox.py`·`agentbox/sandbox_desktop.py`: `list_dir`의 `_exec_head`(`_timed` + `_Head` 스트리밍 상한), `outbox_list`의 `_timed` + `head -c` 상한, `screenshot`의 심볼릭 링크 차단 및 16MiB `head -c` 상한.
  - `agentbox/sandbox.py`·`agentbox/service.py`: `DockerRootDir` 감지 및 `disk_low()`의 `docker_root` 여유 공간 병행 확인.

## 7차 감사(run-7) 결과 — 2026-10-28 (run-6 이후 변경분 집중 감사, 보고 전용)

- **기준과 브랜치:** 감사 기준 `main` `3580df0`(PR #26 병합 뒤), 변경분 `530b29e..3580df0`. 작업 브랜치 `audit-run-7`, 초안 PR. 보고서는 `run-7/REPORT.md`, 상세는 `run-7/FINDINGS-DETAIL.md`·`run-7/NEEDS-VALIDATION.md`.
- **프로필·예산·모델:** `standard`. 상한은 15였고 critic-1 뒤 소유자 승인으로 20으로 올렸다. **18회**를 썼다(헌터 7, 3단계 5, 5단계 4, 비평 2). 정찰은 부모가 했다(0회). 서브에이전트 도구에 모델 선택 인수가 없어 모두 세션 모델(Claude Opus 5.5)로 돌았다. 소유자가 요청한 Sonnet 5.5로는 바꾸지 못했다.
- **결과(`run-7/findings.json` 5건, 두 검증기 PASS, `run_status: complete`):** 확정 3(중간 1, 낮음 2), 검증 필요 2, 기각 0. 장부 7단위가 모두 닫혔다. critic-1이 IF-policy를 다시 맡기라고 했고 2차 헌터가 닫았다. critic-2는 `stop: true`였다.
  - **F1(중간):** 지시 파일 쓰기 승인 카드가 쓸 내용 전체를 상한 없이 2초마다 다시 그린다. 대기 승인 20건이면 `GET /ui/approvals` 한 번이 83.9MB, 13.7초였다(실제 API). 대기 내용은 `max_write_bytes`가 아니라 본문 상한 8MiB로만 묶인다.
  - **F2(낮음):** `cfg -> .claude`처럼 지시 폴더 자체를 가리키는 링크에 `write_file`을 하면 승인 없이 `.claude/` 안에 쓴다. `kind()`가 경로의 끝 조각을 지시 폴더로 보지 않는다.
  - **F3(낮음):** 허용 목록 exec(`tail -f /dev/null &` 약 55개)로 pid 상한을 채우면 `resolve()`가 실패하고, `_resolved`가 이를 None으로 삼켜 요청 경로로만 판정된다. 그래서 `.claude/settings.json`을 승인 없이 덮어썼다(실제 Docker). 단발 F2 수정(a0a186c)이 우회된다.
  - **N1:** U+0130 `İ`가 casefold에서 `i`+결합 점으로 펼쳐져 `gemİni.md`를 지시 파일로 보지 않는다. macOS에서 `gemini.md`와 같은 파일이 되는지 확인이 필요하다.
  - **N2:** run-6 N3 수정이 덜 막았다. compose 구성의 컨트롤 플레인은 Docker 저장소 경로를 볼 수 없고, `disk_low()`는 그 오류를 무시한다(parent-live). 배포의 파일 시스템 분리 여부에 달려 있다.
- **확인한 것(`covered`):** `5bb3c17` 리팩토링은 동작이 바뀌지 않았다. run-6 F1~F3·N1·N2 수정은 근본 원인을 막았다. 읽기 결과 경계(`with_notice`), 사람 화면 출력 지점 이스케이프, 원본 훑기(`scan`) 상한과 `complete` 표시도 지켜졌다. 하드닝 메모 10개는 REPORT 6절에 있다(F3 수정의 틸드 펼치기가 dash에서 동작하지 않음, 읽기의 링크 비대칭 등).
- **실행 환경(이 호스트에서 이어받을 때):** Kiro Web 리눅스 샌드박스는 명령마다 새로 뜨고 `/projects/sandbox`만 남는다.
  - 스크래치패드는 `/projects/sandbox/.scratch`이다(`skill/`, `src-audited/` 워크트리, `docker/` 데이터, `sbx-image/` 이미지 tar, `venv/`).
  - `.scratch/dk.sh '<명령>'`이 사설 마운트 네임스페이스에 tmpfs `/run`을 깔고 cgroup을 다시 마운트한 뒤 dockerd를 띄워 명령을 돌린다. `.scratch/pl.sh`는 parent-live용으로 감사 소스와 venv를 붙인다(`AGENTBOX_CPUS=0`: 이 호스트는 CPU 쿼터를 못 건다).
  - 에이전트용 `run-7/tools/sbx.py`는 호출마다 임시 dockerd를 띄우고 `agentbox-audit-sbx:1`을 tar에서 올린다. 메모리는 RLIMIT_DATA로, CPU는 cpuset으로 건다.
  - 스킬은 git 게이트웨이가 막아 GitHub tarball(`c1c8a8c`)로 받았다.
  - 단위 테스트 기준선(sbx): 270 통과, 1 건너뜀, 1 실패. 실패는 `test_m4_unit` overlap으로, `sudo`가 없어서 난다.
- **남은 일:** 수정 여부는 소유자가 정한다. F2와 F3는 같은 정책 판정을 고치므로 함께 고치는 것이 낫다. N1은 macOS 확인, N2는 배포의 Docker 저장소 위치 확인이 필요하다.
- **수정(소유자 지시, 2026-10-28, 브랜치 `fix-run7`):** 확정 3건과 N1을 고쳤다. N2는 고치지 않았다(배포 구성 확인 필요).
  - F1: 승인 목록 카드는 쓸 내용 앞 4096자만 싣고, 다시 받지 않는 `/ui/approvals/{id}/content`에서 전체를 본다. `write_file` 내용이 `max_write_bytes`를 넘으면 승인 요청 전에 413. 실측: 대기 20건 `GET /ui/approvals`가 83.9MB·13.7초 → 368KB·1.2초. 남은 1.2초는 대기 행 20개(각 1MiB)를 SQLite에서 읽고 JSON을 푸는 비용이다.
  - F2: `instruction_files.target_kind()`가 대상 자체가 지시 폴더인 경우도 맞힌다. 정책·미리보기가 쓴다.
  - F3: `_resolved`가 풀기 실패를 따로 알리고, 정책의 `match.instruction_files`는 `resolve_failed`면 맞는 것으로 본다. 에이전트가 넣은 `resolved_path`·`resolve_failed`는 지운다. 미리보기에 '실제 대상을 확인하지 못함'을 보인다.
  - N1: `_norm`이 NFKD 뒤 결합 문자(Mn)를 떼고 casefold한다. `gemİni.md`도 지시 파일로 본다.
  - 하드닝: `_expand`의 `${1#~/}`를 `${1#??}`로 바꿔 틸드가 실제로 펼쳐진다.
  - 회귀 테스트 9개(`tests/test_instruction_files.py` 끝). 단위 280 통과(실패 1은 알려진 `sudo` overlap). 실제 Docker로 다시 돌린 parent-live 3건(링크 쓰기, 틸드, pid 채우기)에서 모두 승인으로 가거나 바르게 펼쳐졌다.
