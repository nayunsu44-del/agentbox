# agentbox 보안 감사 run-5 보고서

감사 기준은 `main` 커밋 `346df29`(run-4 수정 PR #16~#23 이후)이다. 작업 브랜치는 `ccr-534dd824-2jgcsj`, 프로필은 `standard`, 호출 상한은 소유자가 정한 **30**이다. run-4가 보류한 3단위와 run-4 수정이 바꾼 코드 4단위를 보는 **집중 후속 감사**다. LLM 공급자로 가는 데이터 경로는 문서화한 한계라 뺐다.

## 1. 요약

- 확정 **6건**: 중간 1건, 낮음 5건. 검증 필요 **1건**, 기각 **1건**(레코드 8건).
- 장부 16단위: 헌팅한 9단위는 모두 닫혔다(candidate 8, covered 1). 비평이 낸 7단위는 예산이 다해 `deferred`로 남겼다.
- 예산 30/30회를 썼다: 헌터 8(Opus), 형식 재시도 2, 3단계 8, 5단계 8, 재검증 2, 비평 2(모두 Sonnet). 정찰은 부모가 했다(0회). 실제 Docker가 필요한 확인 7건은 부모가 예산 밖에서 했다(`agents/parent-live/`).
- run-4 확정 F1~F8의 수정은 이번 단위들이 다시 봤다. 같은 지문으로 이어진 것: F1(인증 전 본문)은 바이트 상한은 지켜지나 JSON 해석 확대가 남아 검증 필요로 다시 올랐다. run-4 N2(감사·승인 행 무제한)는 승인 대기 행 확대로 확정됐다. N4(창 주인 위조)는 실제 이미지에서 고쳐진 것을 확인했다.
- **확정 6건은 소유자 지시(2026-10-23 밤)로 같은 PR에서 고쳤다.** 건마다 회귀 테스트가 있고, 새 테스트는 수정 전 코드에서 실패한다(아래 3절). 검증 필요 1건은 고치는 방향을 정해야 해서 손대지 않았다(8절).

## 2. 감사 방법과 경계

- **실행 환경:** 리눅스 클라우드 컨테이너. 대상 코드는 `tools/sbx` 컨테이너 안에서만 돌렸다(네트워크 없음, 대상 읽기 전용, 스크래치만 쓰기, uid 65534, 512MiB, 1 CPU, 120초).
- **모델:** 소유자 지시로 헌터만 Opus, 나머지(3단계·5단계·재검증·비평)는 Sonnet.
- **정찰:** 에이전트를 쓰지 않았다. run-4 구조 요약에 `9805d91` 이후 바뀐 15개 파일의 변경분(현재 줄 번호)을 부모가 덧붙였다(`architecture.md` 0절).
- **범위 단위:** 보류 3(인수 중 GUI 구간, 화면 웹소켓 accept 전 작업, 승인 테이블), 바뀐 코드 4(정리 명령·기준점, 디스크 보호선·승인 행 줄이기, XRes 창 주인, 본문 상한). 사후 비평(critic-1)이 3단위를 더 냈고 그중 2개(수명 주기 락 범위, 긴 명령의 정책·미리보기 비용)를 헌팅했다.

## 3. 확정과 수정

| ID | 심각도 | 제목 | 주 경로 | 수정 |
|---|---|---|---|---|
| F1 | 중간 | 에이전트 exec 한 번이 요청의 약 45배 크기인 승인 대기 행을 써서, PR #20의 디스크 보호선을 한 번에 넘는다 | `agentbox/audit.py` | 미리보기 메모 수 상한, 대기 행 미리보기에도 `bound_payload`, 행을 쓰기 직전 디스크 보호선 재확인, 에이전트 문자열 인자의 길이 상한(정책 판단 전 413). |
| F2 | 낮음 | 화면 웹소켓 처리기가 이벤트 루프에서 SQLite·감사 잠금을 기다려, 연결 하나에 모든 HTTP 요청이 멈춘다 | `agentbox/desktop_ws.py` | 세션 확인·vnc 명령 준비·연결/끊기 기록·세션 재확인을 스레드에서 한다. `DesktopControl`은 메모리 상태와 SQLite를 다른 잠금으로 지켜, 입력마다 부르는 `touch`·`lease`가 SQLite를 기다리지 않게 한다. |
| F3 | 낮음 | 최대 8MiB의 에이전트 exec 명령이 호출마다 GIL을 쥔 정책 파싱을 수 분씩 일으켜 컨트롤 플레인을 느리게 한다 | `agentbox/policy.py` | 에이전트 문자열 인자(write_file 본문 제외) 16KiB 상한(정책 판단 전 413). `_words`는 다시 렉싱해도 결과가 같은 토큰(구분자만 있는 토큰, 공백·구분자·따옴표·역슬래시가 없는 토큰)만 건너뛴다. 탐지는 예전과 같다(무작위 10만 개 비교). |
| F4 | 낮음 | 승인 미리보기가 rm 피연산자마다 제한 시간 없는 docker exec를 두 번씩, 횟수 상한 없이 돌린다 | `agentbox/preview.py` | 미리보기의 컨테이너 확인은 모두 합쳐 40회까지, 각 10초 제한. 같은 피연산자는 한 번만. 넘으면 계산하지 않았다고 알린다. 인자 길이 상한(16KiB)도 함께 묶는다. |
| F5 | 낮음 | 정리 명령이 반영(COMMIT) 직후 중단되면, 이미 지운 감사 행의 유일한 사본인 아카이브를 지운다 | `agentbox/retention.py` | 트랜잭션이 남아 있을 때만 ROLLBACK한다. 바깥에서는 이 아카이브를 가리키는 기준점이 있는지 보고 없을 때만 지우며, 확인하지 못하면 남긴다. 아카이브를 쓰다 실패하면 쓰다 만 파일을 지운다. |
| F6 | 낮음 | 사람이 화면을 인수한 동안 에이전트 GUI 구간이 열려, 사람이 띄운 프로세스를 멈추고 사람의 편집을 에이전트 변경으로 남긴다 | `agentbox/service.py` | 구간은 인수와 같은 `gui_lock` 아래에서, 인수·인수 대기가 없을 때만 연다(있으면 열지 않고 423). 인수 중에 결정한 GUI 입력 승인은 스냅샷 없이 실패로 끝낸다. |

상세 근거, 재현, 원문은 `FINDINGS-DETAIL.md`에 있다. 수정 확인: 새 회귀 테스트 `tests/test_m5_unit.py`(9개)와 `tests/test_retention.py` 2개가 수정 전 코드에서 실패하고 수정 뒤 통과한다. 실제 Docker를 쓰는 전체 테스트도 통과했다(PR CI).

## 4. 검증 필요

| ID | 제목 | 막힌 지점 |
|---|---|---|
| N1 | 인증 없는 JSON 본문을 principal() 전에 해석한다. 8MiB 요청 하나가 401 전에 약 200MB를 쓰고, 512MiB 제한에서는 동시 4건에 서버가 OOM으로 죽었다 | 배포의 메모리 제한은 저장소 밖이다. compose에는 제한이 없다. 1GiB에서는 동시 8건을 견뎠고 512MiB에서는 동시 4건에 죽었다. |

검증 계획과 부모 실측은 `NEEDS-VALIDATION.md`에 있다.

## 5. 기각

- **R1. 삭제 중 커밋이 고아 스냅샷 이미지·행을 남긴다는 주장 — 실제 Docker 29.9.1에서 성립하지 않아 기각** 소스상 경쟁은 있다(삭제는 `_lifecycle`만, 스냅샷은 `_snap_locks`만 잡는다). 그러나 실제 dockerd는 진행 중 커밋의 컨테이너를 강제 삭제하면 커밋을 404('failed to apply diff: NotFound: snapshot')로 실패시켰다. 커밋 시작 0.5~8.5초 뒤 다섯 시점 모두에서 스냅샷 행·이미지·뒤늦은 'snapshot' 감사 기록이 없었다. 남는 창은 1초 미만이고 영향은 호스트 이미지 하나라 하드닝으로 남긴다.

## 6. 커버리지와 남은 단위

- 헌팅한 단위: 보류 3, 바뀐 코드 4, critic-1 2. XRes 창 주인 단위는 헌터가 실제 이미지 확인 2건으로 막혔고, 부모 실측(`agents/parent-live/artifacts/xres.json`)으로 닫았다: XRes가 돌려준 창 주인 pid가 xfwm4·panel·xfdesktop의 실제 pid와 맞고, 구간 중에 띄운 창 없는 작업은 구간이 끝날 때 멈춘다.
- 보류(`deferred`) 7단위. 다음 run의 우선순위다(비평이 매긴 순서):
  - [critic-1] AuditLog._lock as a global contention point reachable by agent-grown table size and by unauthenticated traffic: GET /ui/audit (polled every 3 s by templates/san…
  - [critic-2] Approval-preview truthfulness after the F4 change: preview_command (rm operand expansion via _expand, recursive _walk, curl upload detection, _split_segments an…
  - [critic-2] Browser-origin checks on cookie-authenticated routes: api.py same_origin (api.py:189-191) used by screen_principal (api.py:203, every /ui and screen route), the…
  - [critic-2] Completeness of the PR #19 control-character filter at its sinks: display.escape_controls (Cc/Cf/Zl/Zp via unicodedata) applied through Jinja finalize web._show…
  - [critic-2] Container identity binding of the F2 GUI-input gate: GuiBursts.covers (gui_bursts.py:68-71) checks only 'sid in _gui_burst', called from _run_tool under gui_loc…
  - [critic-2] Container output readers that fully buffer attacker-controlled bytes: sandbox.py exec_run without a read cap or container-side timeout (list_dir ls -la :436, ex…
  - [critic-2] Docker data-root growth that AgentBox.disk_low does not measure: container writable layers (AGENTBOX_DISK default empty so no storage_opt), docker commit snapsh…
- 최종 비평(critic-2)은 `stop: false`였다. 그래서 깨끗한 커버리지는 주장하지 않는다. critic-2는 run-4 N1(`same_origin` scheme)과 N3(컨테이너 출력 판독기 상한)이 이번 장부에 주인이 없다는 점, 두 단위의 제외 사유가 이번 장부에 없는 'h-session' 단위를 가리킨다는 점을 짚었다(seed가 run-4 제외 문구를 그대로 옮긴 탓).

## 7. 편차와 주의

- r-prune Phase 5 replace changed only two line references (cli.py:322->323, audit.py:353-354->358-359) and wording in trace/execution/confidence; apply.py parked it as material by field, the parent checked the diff (verdict, root cause, severity, trace kinds/files/lines unchanged) and applied it with tools/apply5_nonmaterial.py without a re-verifier.
- rv-policy-cpu (fresh re-verifier of r-policy-cpu's parked replacement) returned a final message that is not valid JSON (one closing brace missing at the end). Under the never-repair rule it was discarded; a resend would have been invocation 31 over the owner cap of 30. The parked replacement (agents/r-policy-cpu/pending-replacement.json) was therefore not applied and findings.json keeps the Phase 3 record (v-policy-cpu, confirmed low). The discarded text is kept at agents/rv-policy-cpu/final.txt; its technical point (a narrower _words recursion would lose detection; use a lossless skip) was used for the code fix, not for the record.
- 헌터 두 명(h-gui-lease, h-bodylimit)의 결과가 단위 `reviewed_paths`가 검사들의 합집합과 다르다는 형식 검사에 걸렸다. 결과를 고쳐 쓰지 않고 같은 헌터에게 그 부분만 고쳐 다시 보내게 했다(재시도 2회).
- 사용량 한도(18:10 UTC 해제)로 검증자 5명이 멈췄다가 같은 에이전트로 이어서 끝냈다(새 호출로 세지 않음).
- v-preview의 증거 하나가 스크래치 경로(`agents/v-preview/scratch/count.py`)를 가리킨다. 부모가 `agents/v-preview/artifacts/count.py`로 승격해 두었다.

## 8. 아침에 판단할 것 (소유자 결정 필요)

1. **N1 인증 전 JSON 해석(검증 필요).** 고치는 방향을 골라야 한다: (a) 자격 증명(Authorization 헤더나 세션 쿠키)이 없는 요청은 본문을 읽기 전에 401, (b) 자격 증명 없는 요청의 본문 상한을 작게(예: 64KiB), (c) 배포 쪽(compose `mem_limit`, Caddy JSON 경로 상한, uvicorn `limit_concurrency`). 512MiB 제한에서 동시 4건으로 OOM이 재현됐다.
2. **도구 인자 길이 상한 16KiB.** 수정에서 에이전트 문자열 인자(write_file 본문 제외)를 16KiB로 묶었다(넘으면 413). 정책 판단이 가장 느린 모양에서도 16KiB면 0.06초다. 긴 exec 스크립트를 쓰는 사용 방식이 있으면 값을 올리거나 413 대신 '너무 길어 분석하지 않음' 승인으로 돌리는 쪽을 고를 수 있다.
3. **policy-cpu 레코드.** 5단계가 낸 교체 레코드의 재검증 결과가 JSON 형식이 깨져 버렸다(다시 돌리면 상한 31회째). 그래서 `findings.json`은 3단계 판(확정 낮음)을 유지한다. 판정은 같고, 교체는 수정 방향 정정이었다. 수정 코드는 재검증자가 짚은 '탐지가 줄지 않는 조건'을 따랐다.
4. **보류 7단위**를 다음 run에서 볼지, 예산을 얼마로 할지.
