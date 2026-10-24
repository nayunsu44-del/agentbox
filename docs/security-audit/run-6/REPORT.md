# agentbox 보안 감사 run-6 보고서

감사 기준은 `main` 커밋 `530b29e`(run-5 수정 PR #24·#25 반영 이후)이다. 프로필은 `standard`, 서브에이전트 호출 상한은 소유자가 정한 **30**(모두 `flash` 모델)이다. run-5에서 보류한 7단위(상위 4단위 + 나머지 3단위)와 PR #24·#25가 바꾼 코드 4단위를 합친 **11단위 전체 후속 감사**다. 소유자 지시에 따라 이번 감사에서는 확정 건에 대해 보고서까지만 작성하고 코드 수정은 하지 않았다.

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

## 3. 확정 항목 (코드 미수정 — 보고 전용)

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

## 7. 소유자 판단이 필요한 사항

1. **확정 3건(F1~F3) 수정 여부 및 범위 지시:**
   - **F1 (`GuiBursts.covers` 컨테이너 ID 바인딩 및 복원 경합, 중간):** `GuiBursts.covers(sid)`에서 `burst['container_id'] == sandboxes.get(sid)['container_id']`를 확인하고, `restore_sandbox`가 `sandboxes.restore` 뒤에도 열린 구간을 닫도록 고칠지.
   - **F2 (`AuditLog` 인덱스 부재 및 `verify()` 전체 테이블 `fetchall()` 잠금 점유, 중간):** `audit(sandbox_id, id)` 인덱스를 추가하고 `verify()`를 배치 조회 또는 별도 읽기 연결로 바꿀지.
   - **F3 (승인 미리보기의 중괄호 `{a,b}`·틸드 `~` 미확장 오표시, 낮음):** `preview.py`에서 `{`·`~`에 대해 자동 계산 한계 주의 메모(`notes`)를 띄울지, 아니면 `_expand`를 `/bin/bash`로 맞출지(또는 둘 다 할지).
2. **검증 필요 3건(N1~N3)에 대한 하드닝 여부:**
   - **N1 (`same_origin` 스킴 비교):** 배포 앞단(Caddy)에 맡길지, 코드에서 `secure_cookie(request)`일 때 `Origin`의 `https://` 스킴까지 함께 요구할지.
   - **N2 (컨테이너 출력 판독기 `_Head` 스트리밍 상한):** `list_dir`·`desktop_processes`·`screenshot` 등 `c.exec_run` 호출도 `_Head` 스트리밍(또는 `head -c`)으로 통일할지.
   - **N3 (`disk_low`의 Docker `data-root` 미감시):** 단일 파일시스템 배포를 전제로 문서화할지, 아니면 `DockerRootDir`(또는 설정 가능한 추가 감시 경로)를 `disk_low()` 검사 경로에 추가할지.
