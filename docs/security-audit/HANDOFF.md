# 보안 감사 핸드오프 (agentbox)

다른 세션이 이어받기 위한 요약. 근거는 `docs/security-audit/run-1/`(1차 감사)과 `docs/security-audit/run-2/`(실측 검증)에 있다.

## 한눈에 보기

- **무엇:**
  - run-1: Cloudflare `security-audit` 스킬(6단계)로 agentbox 전체를 감사했다. 기준 커밋 `7fc501f`.
  - run-2: run-1이 남긴 needs_validation 5건을 실제 Docker에서 검증했다.
- **브랜치·PR:** run-3은 `ccr-0da6ba34-sc9pu1`(아래 "3차 감사(run-3) 진행 상태"). run-1·2 때 작업 브랜치는 `ccr-e10bee8e-6wt669`. PR #1(감사 수정·CI), #2(화면 링크 세션 범위), #3(FIFO), #4(runc 차단)는 `main`에 병합됐다. **PR #5(GUI 백그라운드 정리·세션 만료)는 CI 통과, 병합 대기**(사용자 승인 필요). 병합할 때마다 작업 브랜치를 최신 `main`에서 다시 시작한다.
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

- `run-2/VALIDATION.md`: 5건 + 신규 1건의 재현·관측·수정 요약(한국어).
- `run-2/N-1-OPTIONS.md`: N-1 대응 방안 8가지 비교와 권장 조합, 결정할 것.
- `run-2/findings.json`: 현재 기준 전체 10건 구조화 레코드(확정 9 · 기각 1, 검증기 통과). 트레이스 줄 번호는 감사 기준 커밋 `7fc501f` 기준이다.
- `run-2/repro/`: 재현 스크립트 8개. `run-2/n1-terminal-via-gui-tools.png`: N-1 증거 스크린샷.
- `run-1/`: 1차 감사 산출물(REPORT, FINDINGS-DETAIL, NEEDS-VALIDATION, findings, coverage-ledger, architecture, run-metadata). 기록으로 두고 고치지 않는다.

## 3차 감사(run-3) 진행 상태 — 다음 세션이 여기서 이어받는다

작업 브랜치: `ccr-0da6ba34-sc9pu1` (이전 run-3 브랜치 `ccr-df7eb88d-1nmb5q`, PR #7을 이어받음). **4단계(findings.json)까지 끝났고 사용량 한도로 멈췄다.** 5단계 독립 재검증과 6단계 보고서는 아직이다(`run-metadata.json`의 `run_status: incomplete`).

### 3단계 결과 (`run-3/findings.json`, 14건, 두 검증기 통과)
| 판정 | 심각도 | 검증자 | 내용 | 수정 |
|---|---|---|---|---|
| 확정 | high | v11 | 입력이 끊긴 GUI 구간 닫기가 다른 샌드박스의 도구 스레드·사람 승인/감사 요청 스레드에서 제한 시간 없는 docker exec로 돎 → 한 샌드박스의 X가 멈추면 남의 요청이 무기한 막힘 | 아직 |
| 확정 | medium | v02 | UI·CLI 감사 타임라인이 오래된 5000행에서 멈춤 | `3587c9c` |
| 확정 | medium | v05 | 사람 토큰을 바꿔도 브라우저 세션이 12시간 유지 | `3587c9c` |
| 확정 | medium | v08 | 도구 인자가 크기 제한 없이 지울 수 없는 감사 로그에 남음 | `e63922c` |
| 확정 | medium | v12 | 복원·일시정지 때 GUI 구간 상태가 유실(남은 프로세스 안 멈춤, gui_changes 누락, 낡은 기준으로 새 데스크톱을 죽일 수 있음) | 아직 |
| 확정 | medium | v13 | 웹 승인 카드가 exec 명령의 유니코드 방향 제어 문자를 그대로 보여 줌(터미널은 `_safe`로 막음) | 아직 |
| 확정 | low | v03 (v03b) | `agentbox agent`가 파일 내용·모델 출력을 제어 문자 그대로 터미널에 찍음 | 아직 |
| 검증 필요 | — | v06 | `source_dir` 겹침 검사가 경로 문자열 비교 → 대소문자 무시 FS(WSL2 /mnt/c)의 다른 철자로 우회 | `152b8e4` (실체 비교로 수정) |
| 검증 필요 | — | v09 | GUI 구간 열 때 수집 실패를 성공으로 취급(빈 기준, 기록 없음) | 아직 |
| 검증 필요 | — | v10 | X가 멈추면 GUI 도구가 gui_lock을 쥔 채 무기한 → 사람 인수(takeover)가 막힘 | 아직 |
| 검증 필요 | — | v01 | `same_origin`이 scheme을 비교하지 않음(최신 브라우저는 schemeful same-site로 막힘) | — |
| 검증 필요 | — | v14 | UI에 frame-ancestors/X-Frame-Options 없음(같은 사이트 출처가 있어야 함) | — |
| 검증 필요 | — | v15 | gui_strays가 클라이언트가 정하는 _NET_WM_PID로 창 소유를 판단 | — |
| 기각 | — | v04 | runc 별칭으로 runc 차단 우회 (운영자 설정, 경계 없음) | — |

v07(이전 세션, 레코드 소실)은 같은 fingerprint로 v15가 대신했다. 형식 위반으로 폐기한 결과 3개(v12 1차, v03 1·2차)는 `agents/v12/result.rejected-by-validator.json`, `agents/v03/result.rejected-*`에 참고용으로 둔다.

### 3단계 뒤에 부모가 실측한 것 (레코드에는 아직 반영 안 됨 → 5단계 검증자에게 줄 것)
- **l8** (`parent-live/artifacts/l8_alias.*`): 심볼릭 링크가 아닌 바인드 마운트 별칭으로 프로젝트 폴더를 주면 겹침 검사를 통과하고 에이전트가 사람 토큰을 읽는다. v06의 근본 원인(문자열 비교)이 실제로 재현됨 → v06을 확정으로 올리는 근거.
- **l10** (`l10_bound.*`): Xvfb를 멈추면 GUI 도구와 사람 인수, 그리고 다른 샌드박스의 도구 호출이 **150초 넘게** 막히고 Xvfb를 재개해야 풀린다. docker 클라이언트 60초 제한 같은 상한이 없다 → v10의 두 번째 blocker 해소. Xvfb는 uid 1001이라 GUI 터미널로 에이전트가 직접 멈출 수 있다(N-1 경로).
- **l9** (`l9_agent_pressure.*`, `l9_probe.*`): 허용 목록 exec `tail -f /dev/null & ` ×1100 하나로 에이전트 혼자 pid 한도(1024)를 1초 만에 채우고, 이어진 GUI 입력이 **빈 기준(0개)으로 구간을 기록**한다(감사 기록 없음) → v09의 첫 blocker 해소.
- **새 후보(미검증)**: 위 exec에서 bash가 fork 실패로 일찍 끝나면(exit 254) GNU timeout의 그룹 종료가 일어나지 않아 tail ~1000개가 남고, 샌드박스가 계속 pid 한도에 걸린다(root `docker exec pkill`도 못 돎). `run-metadata.json`의 `new_unvalidated_leads`에 적어 둠. 독립 검증이 필요하다.

### 수정 (이 브랜치에 커밋, 회귀 테스트 포함)
- `3587c9c` v02: `AuditLog.recent()`로 최신 400건+실제 총계, CLI는 `after_id`로 끝까지, 검증 화면은 한 줄 조회. v05: 세션·티켓에 사람 토큰 지문(PBKDF2) → 토큰 교체 후 재시작하면 예전 세션 전부 무효. 지문 열이 없던 DB의 세션은 한 번 버림.
- `e63922c` v08: JSON 64 KiB 넘는 도구 인자는 앞 16 KiB + 크기·sha256만 기록.
- `152b8e4` v06: 겹침 검사를 `os.path.samefile`로 조상까지 비교.
- 아직 안 고친 것과 방향: v11·v10(GUI·수집 exec에 컨테이너 쪽 `timeout -k`, 구간 닫기를 호출자 스레드에서 떼기, takeover는 `gui_lock.acquire(timeout)`), v09(exit code 확인, 실패 시 `gui_burst_error` 기록), v12(재시작·복원·일시정지 때 구간 타이머 초기화, 구간에 container_id 기록), v13(웹 템플릿에 `_safe`와 같은 필터), v03(`cmd_agent.log`에 줄 단위 `_safe`), v14(X-Frame-Options SAMEORIGIN + frame-ancestors 'self'; 앱이 자기 데스크톱 페이지를 iframe으로 쓰므로 DENY는 안 됨).

### 에이전트 사용
45/60 (이전 32 + 이번 13: 검증자 11 + v03 재실행 2). 남은 15로 5단계를 레코드당 1개(13개: 확정 7 + 검증 필요 6)로 돌릴 수 있다. 재실행 2회분이 남는다.

### 이어서 하는 법
1. 환경: `nohup dockerd >/tmp/dockerd.log 2>&1 &` → `pip install -e '.[test]' pyte` → `docker pull buildpack-deps:noble-curl ubuntu:24.04`(429면 `mirror.gcr.io/library/<이미지>`를 받아 `docker tag`) → `docker build -t agentbox-desktop:0.1 images/desktop` → 스킬 `git clone --depth 1 https://github.com/cloudflare/security-audit-skill`.
2. 도구 `run-3/tools/`의 `sbx`, `ingest.py`, `promote.py`에서 스크래치패드 경로(`/tmp/claude-0/.../scratchpad`)를 새 세션 값으로 바꾸고 스크래치패드에 복사한다. `ingest.py`는 서브에이전트 transcript(JSONL)의 마지막 텍스트도 결과로 읽는다: `python3 -I ingest.py <id> <task output 파일> <fingerprint>`. 검증자별 `agents/<id>/scratch`는 `chown 65534`로 미리 만든다.
3. **5단계**: `findings.json`의 확정·검증 필요 레코드마다 새 검증자 1개. 스킬의 VALIDATION-AND-REPORTING.md 5단계 지시(확정 6항목, 검증 필요 5항목)와 레코드를 주고 `{"decision":"verified",...}` 또는 `{"decision":"replace",...}`만 받는다. v06·v09·v10 검증자에게는 위 l8·l9·l10을 근거로 준다. 확정으로 올리는 replace는 **다른 새 검증자가 한 번 더** 확인해야 적용할 수 있다(남은 재실행 2회로 부족하면 사용자에게 상한 확인).
4. 6단계: `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`(한국어 요약은 HANDOFF·VALIDATION 스타일).
5. 남은 수정(위 목록) → 회귀 테스트 → PR. 새 후보(exec 뒤 남는 백그라운드 프로세스)는 독립 검증부터.
