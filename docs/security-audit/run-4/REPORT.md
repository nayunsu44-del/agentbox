# agentbox 보안 감사 run-4 보고서

감사 기준: `main` 커밋 `9805d91`(리팩토링 PR #11~#14 이후). 작업 브랜치 `ccr-17444317-ygb3a1`, 프로필 `standard`, 에이전트 호출 상한 50회 중 46회 사용.

## 1. 요약

- 확정(confirmed) **7건**: 낮음 4건, 중간 3건.
- 검증 필요(needs_validation) **5건**, 기각 **0건**.
- 커버리지 장부 30단위: candidate 10, covered 20.
- run-3 확정 9건을 모두 재검증 단위로 다시 확인했고, 다수가 이미 고쳐져 있음을 확인했다. 이번 run에서 새로 확정된 것은 전부 인증 전 처리·자원 상한·감사 기록 원자성 계열이다.
- 확정 건은 **고치지 않았다**(지시대로 보고서까지만). 수정은 별도 지시로 진행한다.

## 2. 감사 방법과 경계

- 실행 호스트: Continuation host is Windows 11 (not the Linux container of runs 1-3): Docker Desktop 4.96.3 with the WSL2 Linux engine 29.9.2, WSL 3.0.3 installed without a distribution. Agent-run target code goes only through tools/sbx.py, the Windows replacement for the bash tools/sbx: docker run --network none, no docker socket, --read-only, audited worktree bind-mounted read-only at /target, writes only to a
- 소유자 지시로 서브에이전트는 전부 DeepSeek(`doph`/`doph-2`, `deepseek-ai/DeepSeek-V4.1-Flash`)로 통일했다. 정찰 4회만 이전 세션의 Opus 결과다.
- 대상 코드 실행은 전부 `tools/sbx.py`(네트워크 없음, 대상 읽기 전용, 스크래치만 쓰기, uid 65534, 512 MiB, 1 CPU, 120초) 안에서만 했다. Docker가 필요한 확인은 부모가 일회용 컨테이너에서 직접 재현했다(`agents/parent-live/`).

## 3. 확정 findings

| # | 심각도 | 제목 | 대표 경로 |
|---|---|---|---|
| 1 | 중간 | Unauthenticated request bodies are fully read, JSON-decoded and multipart-spooled before the principal dependency rejects the request | `agentbox/api.py` |
| 2 | 중간 | A GUI input queued on gui_lock across a human handback executes with no open burst, so its changes get no snapshot and no gui_changes row | `agentbox/api.py` |
| 3 | 중간 | Agent tool input still reaches the append-only audit log uncapped through approval previews and tool error strings | `agentbox/api.py` |
| 4 | 낮음 | Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent) | `agentbox/api.py` |
| 5 | 낮음 | Unauthenticated GET /static/novnc/* runs docker create plus a full /usr/share/novnc tar extraction on every request while home/novnc/core/rfb.js is absent, with no single-flight | `agentbox/api.py` |
| 6 | 낮음 | A restore racing a delete resurrects the deleted sandbox row and re-authorizes the agent token the delete revoked | `agentbox/api.py` |
| 7 | 낮음 | Unauthenticated failed POST /login writes one permanent hash-chained audit row per attempt, with no rate limit, aggregation or retention | `agentbox/audit.py` |

각 건의 상세 근거·재현 절차·수정안은 `FINDINGS-DETAIL.md`에 있다.

## 4. 검증 필요 항목

| # | 제목 | 막힌 지점 |
|---|---|---|
| 1 | same_origin compares only the Origin netloc with Host, so an http:// page on the same host passes the CSRF origin check of a TLS deployment and can clear the session cookie | Browser behaviour (decisive): whether a browser an operator actually uses attaches the Secure SameSite=strict session cookie to a cross-scheme http://H -> https |
| 2 | Agent-grown audit and approval rows in the shared control-plane SQLite file have no aggregate bound or retention, so an agent can fill the host disk and neither recovery path keeps the audit chain | Free space, any filesystem or volume quota, and the planned lifetime of the volume holding data/agentbox.db (config.py:29 home=./data, config.py:84-86 db_path,  |
| 3 | list_dir, outbox_list, preview glob expansion and screenshot buffer unbounded container output in the shared control-plane process | The decisive quantity - how much memory the control plane actually holds while a real container streams - is produced inside the docker SDK's non-streaming exec |
| 4 | GUI burst stray kill spares a uid-1001 process in a burst-start session whose pid the client-declared _NET_WM_PID window list names | The decisive platform step is not observable here: this sandbox has no X server and no X client. Reproduced in the run (agents/v05/artifacts/v05_probe.out:25-33 |
| 5 | The shared control-character filter misses U+061C - the only Unicode Bidi_Control code point it omits - plus the Cf/Zl/Zp invisibles, and the approval card renders them raw beside the argv that will execute | No browser or terminal renderer is reachable from the approved sandbox (python3 plus the repo and jinja2/fastapi only, no network, no display), so the rendered  |

로컬·배포 검증 계획은 `NEEDS-VALIDATION.md`에 있다.

## 5. 하드닝(취약점 아님, 개선 권고)

장부에 보존된 헌터 하드닝 노트 180건과 Phase 3·5 검증자가 덧붙인 항목이 각 `agents/<id>/result.json`의 `hardening`에 있다. 여러 건에서 공통으로 지적된 것: 감사·승인 테이블의 집계 상한과 보존 정책 부재, `display.escape_controls`의 문자 집합 누락, `deploy/Caddyfile`에 요청 크기·속도 제한 없음, `/healthz`·`/docs` 무인증 노출.

## 6. 커버리지와 한계

- 30개 커버리지 단위를 13명의 헌터가 모두 닫았다(covered 20, candidate 10).
- 사후 커버리지 비평(`critic-1`)이 **미할당 경계 2건**을 제안했다: (a) 데스크톱 WebSocket 업그레이드 경로에서 async 핸들러가 `ws.accept()` 전에 SQLite·Docker SDK를 동기 호출해 이벤트 루프를 막는 문제, (b) 승인 테이블이 마스킹·상한 없이 원본 인자·프리뷰를 보존하고 삭제 후에도 남는 문제.
- 남은 예산을 3·5단계 검증에 예약해야 해서 이 2건은 이번 run에서 **deferred**로 기록한다. 따라서 이 run은 그 두 경계에 대해 **명시적 조기 종료**이며, 전체 커버리지 완전 달성으로 주장하지 않는다. 다음 run의 1순위다.
- run-3에서 기각된 두 주장(runc 별칭, 백그라운드 자식 pid 고갈)은 변경된 근거가 없어 재보고하지 않았다.

## 7. 편차와 주의

- Windows 호스트로 옮기면서 bash `sbx`와 loop 마운트 스크래치를 쓸 수 없어 `sbx.py`/`promote.py`를 같은 경계로 다시 구현했다(`run-metadata.json`의 `execution_note`).
- 헌터 4명(h-policy, h-queue, h-gui-race, h-preauth)이 결과 파일을 남기지 않아 부모가 마지막 메시지에서 옮겨 적었고, 장부 coverage_id로 재매핑했다.
- v06 검증자는 지시문 파일이 없어 형제 지시문으로 계약을 재구성했고 그 사실을 결과에 적었다.
- Phase 5에서 r03·r09가 `replace`를 냈지만 스스로 **비물질 수정**이라고 밝혀(경로 접두사·서술 순서·관측 문장 1개) 두 번째 검증자 없이 반영했다. 이 편차를 여기에 공개한다.
- v05 검증자는 자기 턴에 들어온 범위 밖 쓰기 지시를 거부했다. 감사 경계가 실제로 작동한 사례로 기록한다.
- 스킬의 `validate-findings.cjs`·`validate-coverage-ledger.cjs`는 Linux 전용 no-follow I/O를 요구해 Windows 호스트에서 직접 실행되지 않는다. 구조 검증은 node:22-alpine 컨테이너에서 돌렸고 두 검사기 모두 통과했다(PASS: 12 findings valid, PASS: 30 coverage units valid).

