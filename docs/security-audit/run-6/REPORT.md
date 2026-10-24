# agentbox 보안 감사 run-6 보고서

감사 기준은 `main` 커밋 `530b29e`(run-5 수정 PR #24·#25 반영 이후)이다. 프로필은 `standard`, 서브에이전트 호출 상한은 소유자가 정한 **30**(모두 `flash` 모델)이다. run-5에서 보류한 7단위(상위 4단위 + 나머지 3단위)와 PR #24·#25가 바꾼 코드 4단위를 합친 **11단위 전체 후속 감사**다. 1차 보고 뒤 소유자 지시('사용에 영향 없는 건 보고 없이 수정')에 따라 확정 3건(F1~F3)과 검증 필요 하드닝 3건(N1~N3)을 모두 수정하고 회귀 테스트를 추가했다.

## 1. 요약

- 확정 **3건**(중간 2건, 낮음 1건), 검증 필요 **3건**, 기각 **0건**(총 레코드 6건).
- 장부 11단위: 헌팅한 11단위는 모두 닫혔다(candidate 6, covered 5). 보류(deferred)로 남은 단위는 없다.
- 서브에이전트 예산 20/30회를 썼다(모두 `flash`): 헌터 6, 형식 재시도 0, 3단계 6, 5단계 6, 재검증 0, 비평 2. 정찰은 부모가 수행했다(0회). 실제 Docker 데몬과 데스크톱 이미지가 필요한 확인 5건은 부모가 일회용 컨테이너에서 직접 수행했다(`agents/parent-live/artifacts/`, 예산 밖).
- **PR #24·#25 수정 검증 결과:** PR #24가 고친 3개 영역(DesktopControl 잠금 분리·웹소켓 스레드풀 오프로드·prune 아카이브 보존, GUI 구간 인수 중 열기 차단, 에이전트 도구 인자 16KiB 상한·`_relex_changes`·미리보기 40회/50메모 상한·대기 승인 행 128KiB 상한)과 PR #25가 고친 1개 영역(`_BodyLimit` 본문 읽기 전 자격 증명 확인·`/login` 64KiB 상한·배포 설정 상한)은 모두 현재 코드에서 안전하게 지켜짐(`covered`)을 확인했다.
- **PR #19 제어문자 필터(`display.escape_controls`) 완전성:** 웹 템플릿(`finalize=_shown`)과 CLI(`_safe`)의 모든 에이전트·컨테이너 문자열 출력 경로가 Bidi·제어문자(`Cc`/`Cf`/`Zl`/`Zp`)를 이스케이프하여 run-4의 미해결 리드(`exec-command-bidi-controls-unneutralized`)가 완전히 해소됨(`covered`)을 확인했다.

## 2. 감사 방법과 경계

- **실행 환경:** Windows 호스트 + Docker Desktop WSL2 리눅스 엔진. 모든 서브에이전트 검증 스크립트는 `tools/sbx.py`를 통해 격리된 일회용 리눅스 컨테이너(`agentbox-audit-sbx:1`, `--network none`, 대상 소스 읽기 전용 `/src`, `/scratch`만 쓰기, uid 65534, 512MiB, 1 CPU, 120초) 안에서만 실행했다.
- **모델:** 소유자 지시로 모든 서브에이전트(`invoke_subagent`)는 질문 없이 `flash`로만 호출했다.
- **정찰:** 에이전트 호출 없이 부모가 직접 수행했다. run-5 구조 요약에 `346df29..530b29e`(PR #24·#25)에서 바뀐 13개 소스 파일의 변경분과 현재 줄 번호를 반영했다(`architecture.md` 0.1절).
- **범위 단위(11단위):** run-5 보류 상위 4단위(`same_origin` 스킴 비교, 컨테이너 출력 판독기 상한, 승인 미리보기의 정확성, `AuditLog._lock` 경합) + PR #24·#25 변경 4단위 + 나머지 보류 3단위(Docker data-root 증가와 `disk_low`, 복원 전후 `GuiBursts.covers` 컨테이너 ID 바인딩, PR #19 제어문자 필터 완전성). 1차 파동 뒤 사후 비평(`critic-1`)이 빠진 단위가 없음을 확인하고 `stop: true`를 반환했다.

## 3. 확정 항목 (모두 수정 완료)

| ID | 심각도 | 제목 | 주 경로 | 권장 수정 방향 |
|---|---|---|---|---|
| F1 | 중간 | 감사 테이블에 sandbox_id 인덱스가 없고 verify()가 전체 테이블을 fetchall()로 읽어, 테이블이 커지면 AuditLog._lock 경합과 메모리 급증을 일으킨다 | `agentbox/audit.py` | `SCHEMA`에 `CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id, id)`를 추가하고, `AuditLog.verify()`는 `fetchmany()`로 나누어 읽거나 WAL 읽기 전용 연결을 써서 전체 테이블 적재와 긴 `_lock` 점유를 없앤다. |
| F2 | 중간 | 복원 중 열린 옛 컨테이너의 GUI 구간을 GuiBursts.covers()가 구분하지 못해, 복원된 컨테이너에서 실행된 에이전트 프로세스가 정리·기록에서 빠진다 | `agentbox/gui_bursts.py` | `GuiBursts.covers(sid)`에서 열린 구간의 `container_id`를 현재 `sandboxes.get(sid)['container_id']`와 비교하고, `restore_sandbox`가 `sandboxes.restore` 뒤에도(또는 `gui_lock`/`_snap_locks`와 직렬화하여) 옛 컨테이너로 열린 구간을 정리한다. |
| F3 | 낮음 | 승인 영향 미리보기가 중괄호({a,b})와 틸드(~) 확장을 계산하지 못해 실제 삭제될 파일을 '현재 존재하지 않음'으로 잘못 표시한다 | `agentbox/sandbox.py` | `preview.py:88`의 치환·확장 경고 검사에 `{`와 `~`를 추가하거나(또는 피연산자에 `{`·`~`가 있을 때 미확장 경고), `_expand`를 실행과 같은 `/bin/bash` 기반으로 맞춘다. |

상세 근거, 샌드박스·실제 컨테이너 재현 결과, 영어 레코드 원문은 `FINDINGS-DETAIL.md`에 있다.

## 4. 검증 필요 항목

| ID | 제목 | 막힌 지점 (배포·환경 의존) |
|---|---|---|
| N1 | same_origin()이 Origin의 호스트:포트(netloc)만 비교하고 스킴(http vs https)은 보지 않는다 | 동봉된 기본 배포(`deploy/Caddyfile`)는 80 포트를 HTTPS로 리다이렉트하고 443에서 TLS를 종료하므로, 같은 `host:port`에서 평문 HTTP 응답을 받을 수 없다. |
| N2 | exec 외의 컨테이너 출력 판독기들이 docker-py의 스트리밍 상한(_Head) 없이 c.exec_run()으로 전체 출력을 메모리에 먼저 받는다 | `desktop_processes`는 `pids_limit`(기본 256 / 데스크톱 1024)에 묶여 출력 크기가 수백 KiB 수준에 그친다. |
| N3 | AgentBox.disk_low()가 컨트롤 플레인 데이터 폴더만 검사하고 Docker data-root(/var/lib/docker)는 보지 않으며, 기본 설정에는 컨테이너 쓰기 레이어 용량 상한(disk_limit)이 없다 | 단일 루트 파티션에 `settings.home`과 `/var/lib/docker`를 함께 두는 배포에서는 `shutil.disk_usage(settings.home).free`가 Docker 쓰기 레이어 증가도 그대로 반영한다. |

검증 계획과 부모의 일회용 Docker 컨테이너 실측은 `NEEDS-VALIDATION.md`에 있다.

## 5. 기각 항목

- 이번 run에서 기각(`rejected`)된 후보는 없다.

## 6. 커버리지와 비평 결과

- 헌팅한 11단위 중 5단위는 보안 불변식이 지켜짐을 확인해 `covered`로 닫았고, 6단위는 후보를 내어 3단계·5단계 검증을 거쳐 확정 3건(`confirmed`)과 검증 필요 3건(`needs_validation`)으로 닫았다.
- 사후 비평(`critic-1`)과 최종 비평(`critic-2`) 모두 빠진 단위 없이 `stop: true`를 반환했다.

## 7. 후속 수정 결과 (소유자 지시 반영)

정상 사용에 영향을 주지 않는 범위에서 확정 3건(F1~F3)과 검증 필요 하드닝 3건(N1~N3)을 모두 수정하고 `tests/test_m5_unit.py`에 회귀 테스트 6개를 추가했다:
- **F1 (`agentbox/audit.py`):** `SCHEMA`에 `CREATE INDEX IF NOT EXISTS idx_audit_sandbox_id ON audit (sandbox_id, id)`를 추가하고, `verify()`·`verify_archives()`가 `_VERIFY_BATCH = 200`행씩 끊어 읽고 해시 계산은 `self._lock` 밖에서 수행하도록 수정했다.
- **F2 (`agentbox/gui_bursts.py`, `agentbox/service.py`):** `GuiBursts.covers(sid)`가 `burst.get('container_id') == self.sandboxes.get(sid)['container_id']`까지 확인하고, `restore_sandbox`가 `sandboxes.restore` 뒤에 `self.bursts.end(sid, 'sandbox_restored')`를 호출해 복원 중 열린 옛 구간을 닫도록 수정했다.
- **F3 (`agentbox/preview.py`, `agentbox/sandbox.py`):** `preview_command`가 명령에 `{` 또는 `~`가 있으면 주의 문구를 남기고 매칭이 없을 때 `'삭제 시도 (중괄호·틸드 확장 — 명령 원문 확인)'`으로 표시하며, `_expand`가 앞쪽 `~`/`~/`를 `$HOME`으로 펼치도록 수정했다.
- **N1 (`agentbox/api.py`, `agentbox/web.py`, `deploy/Caddyfile`):** `secure_cookie(request)`가 참(`AGENTBOX_SECURE_COOKIE=1` 또는 `https`/`wss` 요청)일 때 `same_origin()`이 `Origin`의 `https` 스킴까지 요구하도록 하고, `deploy/Caddyfile`에 `Strict-Transport-Security` 헤더를 추가했다(로컬 평문 HTTP 개발 환경은 기존대로 동작).
- **N2 (`agentbox/sandbox.py`, `agentbox/sandbox_desktop.py`):** `list_dir`가 `_exec_head`(`_timed` + `_Head` 64KiB 스트리밍 상한)를 쓰고, `outbox_list`(`_timed` + `head -c 524288`), `_expand`(`head -z -n`), `screenshot`(`rm -f` + 일반 파일 확인 + `head -c 16MiB`)에 상한을 걸었다.
- **N3 (`agentbox/sandbox.py`, `agentbox/service.py`):** `SandboxManager._detect_runtime()`이 `client.info()`의 `DockerRootDir`를 저장하고, `AgentBox.disk_low()`가 접근 가능한 `docker_root`의 남은 공간도 함께 확인하도록 수정했다.
