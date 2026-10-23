"""Korean text for the run-5 Phase 6 reports (written by the parent from findings.json).

The English record in findings.json stays authoritative; gen6.py renders these Korean fields
and attaches the original record text below each entry.
"""

KO = {
    "agentbox/api.py:preauth-request-body-read-before-principal": {
        "title": "인증 전 요청 본문을 401로 거절하기 전에 끝까지 읽고 JSON 해석·멀티파트 임시 저장까지 한다",
        "desc": "본문 모델이나 `File(...)`을 받는 라우트(`POST /sandboxes`, `/restore`, `/tools/{tool}`, `/approvals/{aid}`, `/files`)는 FastAPI가 본문을 읽고 해석한 다음에야 `principal`·`human_only`·`screen_human` 의존성을 푼다. 그래서 토큰이 없는 클라이언트가 고른 크기만큼 컨트롤 플레인이 메모리에 올리고, 업로드 라우트는 TMPDIR에 임시 파일까지 쓴 뒤에 401을 돌려준다. 앱 미들웨어는 `_NoFraming` 하나뿐이다. `agentbox serve`는 uvicorn에 본문·동시성 상한을 넘기지 않고, 배포용 Caddyfile에도 `request_body` 제한이 없다. 파일당 상한(`max_upload_bytes`)과 `LOGGED_ARGS_MAX`는 인증이 끝난 뒤에만 적용된다.",
        "root": "인증 의존성이 FastAPI의 본문 해석 단계 뒤에 돈다. 그리고 앞단(ASGI 미들웨어, uvicorn 옵션, 동봉 Caddy)에 본문 크기 상한이 없다. 그래서 인증 없는 요청에 드는 일이 공격자가 고른 본문 크기에 비례한다.",
        "intended": "인증할 수 없는 요청은 본문을 버퍼링·해석·디스크 기록하기 전에 거절해야 한다. 문서화한 상한을 넘는 본문은 자격 증명과 관계없이 413이어야 한다.",
        "obs": "fastapi 0.161.1 / starlette 1.9.0 / uvicorn 0.54.0에서 확인했다.\n- 인증 없이 16 MiB JSON을 `POST /sandboxes`에 보냈다. 401이 나왔지만 응답 전에 16,777,216바이트를 모두 읽고 해석했고, RSS가 32 MiB(본문의 2배) 늘었다.\n- `/tools/exec`, `/restore`, `/approvals/{aid}`도 4 MiB 본문으로 같았다.\n- `/files`에 4 MiB 파일 한 개를 보냈다. 401 전에 TMPDIR에 4 MiB 임시 파일이 생겼다. 엔드포인트의 파일당 50 MiB 상한은 실행되지 않았다.",
        "fix": "FastAPI 본문 단계 앞에 ASGI 미들웨어를 둔다. Content-Length가 상한을 넘으면 413을 주고, chunked 본문은 읽은 바이트를 세다 상한에서 끊는다. JSON 상한은 정상 최대(`write_file` 1 MiB)보다 크게 잡고, 멀티파트는 요청 전체 상한을 새 설정으로 둔다. `deploy/Caddyfile`에 `request_body { max_size … }`를 추가한다.",
    },
    "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare": {
        "title": "`same_origin`이 Origin의 netloc만 Host와 비교해, 같은 호스트의 http:// 페이지가 TLS 배포의 CSRF 출처 검사를 통과하고 세션을 끊을 수 있다",
        "desc": "쿠키로 인증하는 UI 변경 요청은 모두 `api.same_origin`(api.py:131-133)을 거친다. 이 함수는 Origin이 없거나 `urlsplit(Origin).netloc`이 Host와 같으면 통과시키고 scheme은 보지 않는다. 그래서 `http://H` 페이지가 `https://H` 배포의 검사를 통과한다. 검증자가 실제 앱을 ASGI로 띄워 확인했다. `Origin: http://agentbox.example`이 `/login`, `/ui/approvals/.../approve`, `/ui/sandboxes`, `/logout`에서 모두 받아들여졌다. 다른 호스트, `null`, userinfo, 다른 포트는 403이었다.",
        "root": "api.py:131-133이 netloc만 비교하고 scheme은 비교하지 않는다. 함수가 헤더만 받아 요청 scheme을 모른다. HSTS를 내보내는 곳도 없다.",
        "blockers": [
            "결정적 사실은 브라우저 동작이다. 사람이 쓰는 브라우저가 `Secure; SameSite=Strict` 세션 쿠키를 `http://H` → `https://H` 폼 POST에 붙이는지 봐야 한다. run-4에서 Chromium 141은 붙이지 않았다. Firefox·WebKit은 확인하지 않았다. 쿠키가 안 붙으면 남는 영향은 강제 로그아웃뿐이다.",
            "공격자가 같은 호스트 이름으로 평문 http를 띄울 수 있는지(경로상 공격자, 80 포트, DNS 탈취)는 배포 조건이다.",
            "두 scheme이 같은 netloc으로 노출되는지는 배포 형태에 달렸다. HSTS나 preload가 있으면 http 페이지가 아예 열리지 않는다.",
        ],
        "plan": "로컬: H를 127.0.0.1로 잡고 자체 서명 TLS로 `https://H:443`을 띄운다. `http://H:80`에서 `/logout`과 `/ui/sandboxes`로 자동 제출하는 폼을 둔다. 로그인한 상태로 http 페이지를 열어 쿠키 전송 여부, 응답 코드, 세션 종료, 샌드박스 생성 여부를 Chromium·Firefox·WebKit에서 기록한다.\n수정 방향(결과와 관계없이 권장): `same_origin`이 `request.url.scheme`까지 함께 비교하게 한다.",
    },
    "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention": {
        "title": "에이전트가 늘리는 감사·승인 행에 전체 상한과 보존 정책이 없다. 호스트 디스크를 채울 수 있고, 어느 복구 방법을 써도 감사 체인을 지킬 수 없다",
        "desc": "에이전트 도구 호출마다 감사 행이 최소 2개 생긴다. 승인이 필요한 호출은 `approval_requested` 행과, 원본 인자를 담은 `approvals` 행을 더 남긴다. 레코드당 인자는 이제 16 KiB로 잘리지만, 테이블 전체에는 상한이 없다.\n- 실측: 최대 크기 호출 하나에 17,203바이트, `ls` 하나에 512바이트가 늘었다.\n- 400 KB 인자의 승인 행 5개가 2 MB를 차지했고, 실행·거절·만료 뒤에도 남았다.\n- 감사 테이블은 트리거로 DELETE·UPDATE가 막혀 있다. 보존 작업도 없다.\n디스크가 차면 `AuditWriteError`가 나고, 모든 샌드박스의 도구 호출·승인·인계가 503으로 멈춘다. 복구도 막혀 있다. 오래된 행만 지우면 `verify()`가 영구 실패하고, 전부 지우면 빈 로그가 통과한다.",
        "root": "감사 테이블은 설계상 추가 전용이다. 에이전트가 늘리는 양을 제한하는 것은 레코드당 인자 상한뿐이다. 감사·승인 테이블에 전체 할당량, 보존 기간, 정리 명령, 크기 검사가 없다.",
        "blockers": [
            "남은 디스크 용량, 볼륨 할당량, 볼륨 수명은 배포 사실이다. 소진까지 걸리는 시간은 저장소만으로 정해지지 않는다.",
            "에이전트가 낼 수 있는 호출 속도는 운영자가 앞단에 둔 제한에 달렸다. 저장소에는 속도 제한이 없다.",
            "운영자가 SQLite 파일을 따로 정리하는지, 어떤 손실을 받아들일지는 소유자 결정이다.",
        ],
        "plan": "로컬(이미 수행): 스크래치 DB로 `_call_tool`이 쓰는 행을 재생해 위 수치를 얻었다. 디스크가 차서 503이 나는 과정은 포화 테스트라 직접 돌리지 않았다.\n배포: 작은 볼륨(예: 64 MiB tmpfs)에 데이터 폴더를 두고, 더미 에이전트로 최대 크기 호출을 반복한다. 503이 모든 샌드박스로 번지는지, 정리 뒤 `verify()` 결과가 어떤지 기록한다.",
    },
    "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap": {
        "title": "`list_dir`, `outbox_list`, 미리보기 glob 확장, 스크린숏이 컨테이너 출력을 상한 없이 컨트롤 플레인 메모리에 올린다",
        "desc": "에이전트 토큰이 다루는 샌드박스에서 네 리더가 Docker의 비스트리밍 `exec_run`으로 출력을 통째로 받는다. 바이트 상한이 없고, 셋은 컨테이너 쪽 제한 시간도 없다. 대상은 `list_dir`(sandbox.py:428), `outbox_list`(534), `_expand`(560), `screenshot`(sandbox_desktop.py:86-88)이다. `_truncate`와 `_parse_outbox`는 버퍼가 다 찬 뒤에 돈다. 그래서 반환 값만 줄이고 최대 사용량은 줄이지 못한다.\n가짜 `exec_run` 실측:\n- 16 MiB 출력에서 `list_dir`가 16.19 MiB까지 썼다(exec의 `_Head`는 0.32 MiB).\n- `find` 출력 5 MB가 파싱 뒤 72.6 MiB까지 올라갔다.\n- 8 MiB PNG를 그대로 받아 base64로 11.2 MB 응답을 만들었다.",
        "root": "exec의 `_Head` 상한과 read_file 쪽 컨테이너 상한을 리더마다 따로 붙였다. 위 네 리더는 빠졌다.",
        "blockers": [
            "결정적인 양은 실제 컨테이너가 스트리밍할 때 docker SDK 안에서 생긴다. 감사 샌드박스에는 Docker 데몬이 없어 가짜 `exec_run`으로만 쟀다. 실제 값은 SDK가 한 번 더 버퍼링하므로 더 크다.",
            "스크린숏 변형은 데스크톱 컨테이너 안에서 uid 1001이 스크린숏 경로를 `/dev/zero` 심볼릭 링크로 바꿔야 한다. 이 환경에는 데스크톱 이미지와 X 세션이 없었다.",
            "치명적인지는 컨트롤 플레인 메모리 제한과 호스트 메모리에 달렸다. 배포에 메모리 상한이 없다.",
        ],
        "plan": "로컬: 일회용 샌드박스(`AGENTBOX_DISK=2g`, 네트워크 없음)의 `/workspace`에 빈 파일 약 20만 개를 만든다. `list_dir` 호출 전후로 컨트롤 플레인 VmHWM을 잰다. 대조군으로 같은 디렉터리를 상한이 있는 exec(`ls -la`)로 읽는다. outbox와 `rm /workspace/*` 미리보기도 같은 방식으로 잰다. 데스크톱 샌드박스에서는 스크린숏 경로를 `/dev/zero`로 바꿔 증가가 보이면 바로 멈춘다.\n배포: compose 스택에서 같은 비교를 하고, 메모리 제한과 OOM 동작을 기록한다.",
    },
    "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process": {
        "title": "GUI 구간 정리가, 클라이언트가 스스로 선언한 `_NET_WM_PID`에 이름이 오른 uid 1001 프로세스를 죽이지 않는다",
        "desc": "GUI 구간을 닫을 때 `_stop_strays`가 새로 생긴 uid 1001 프로세스를 죽인다(gui_bursts.py:83-85). 예외는 창 검사 하나다. pid나 새 조상 pid가 창 pid 목록에 있으면 남긴다(gui_state.py:85-86). 창 pid 목록은 `xdotool getwindowpid` 출력이고, 이 값은 X 클라이언트가 직접 써 넣는 `_NET_WM_PID`다. 검증자가 실제 함수로 재현했다. 구간 시작 세션의 데몬은 창 목록이 비면 죽었고, 창 목록에 그 pid가 있으면 살아남았다.",
        "root": "정리 예외를 컨트롤 플레인이 확인할 수 있는 관계가 아니라, 컨테이너가 선언한 X 창 정보로 정한다. 데스크톱 세션의 모든 프로세스가 디스플레이 :0에 접근할 수 있으니 공격자가 남길 pid를 고를 수 있다.",
        "blockers": [
            "이 환경에는 X 서버와 X 클라이언트가 없어 `_NET_WM_PID` 위조와 그 값이 `xdotool`에 보이는지를 관찰할 수 없었다.",
            "이미지(`images/desktop/Dockerfile`)에는 xprop·python·컴파일러가 없다. 임의의 `_NET_WM_PID`를 쓸 프로그램이 실제 이미지에 있는지 확인해야 한다. 없으면 위조 경로는 이 이미지에서 성립하지 않는다.",
            "데몬이 구간 시작 때 있던 세션 안에 있어야 한다. GUI 입력만으로 그렇게 만들 수 있는지는 런타임 성질이다.",
        ],
        "plan": "로컬: 네트워크 없는 일회용 `agentbox-desktop:0.1`에서 다음을 순서대로 한다.\n1. 속성을 쓸 수 있는 도구를 확인한다(`command -v xprop python3 gcc socat xdotool`).\n2. desktop 계정으로 구간 시작 세션에 쓰기 데몬을 띄운다.\n3. 1×1 창의 `_NET_WM_PID`를 데몬 pid로 설정한다. 도구가 없으면 여기서 멈추고 '위조 경로 불성립'으로 기록한다.\n4. 실제 `desktop_processes`와 `gui_strays`로 정리 목록에 그 pid가 빠지는지 본다.",
    },
    "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets": {
        "title": "승인 카드 영향 표가 공백·줄바꿈이 든 `rm` 대상을 잘못 보여 준다(있는 파일을 '없음'으로 표시)",
        "desc": "승인이 필요한 exec의 '시스템 계산 영향' 표는 `_expand`·`_walk`와 `preview_command`가 만든다.\n- `_expand`는 이미 따옴표를 벗긴 `rm` 인자를 `$1`로 넘기고 따옴표 없이 순회한다. 그래서 인자가 IFS로 쪼개지고 조각마다 다시 확장된다.\n- 결과는 줄바꿈으로 나뉜다.\n- 실제 `rm`은 원래 따옴표대로 `bash -c`에서 돈다.\n그래서 `rm \"final report.docx\"`의 카드는 '삭제 시도 (현재 존재하지 않음)' 한 줄만 보여 주는데, 실제로는 그 파일이 지워진다. 같은 이름 조각의 미끼 파일이 있으면 미끼가 삭제 목록에 오른다. run-4 v17(인식 못 한 조각 경고)은 고쳐져 있음을 함께 확인했다.",
        "root": "미리보기 경로 전달이 파일 경로를 손실 없이 나타내지 못한다. sandbox.py:559가 `$1`을 따옴표 없이 순회하고, 결과를 줄 단위로 나눈다. preview.py:90-98은 빈 결과를 '없음' 행으로, 줄마다 '삭제' 행으로 바꾼다.",
        "intended": "승인 카드 옆 영향 목록은 저장된 명령이 실제로 건드릴 경로를 정확히 보여 줘야 한다. 있는 경로를 없다고 하거나, 지우지 않을 경로를 삭제 목록에 넣어서는 안 된다.",
        "obs": "- 경우 B: 실제로 있는 `final report.docx`가 '삭제 시도 (현재 존재하지 않음)'로 표시됐고 메모도 없었다.\n- 경우 C: 미끼 파일 `final`과 `report.docx`가 삭제 행으로 나왔고 실제 대상은 나오지 않았다.\n- 실행: `sh -c 'rm \"final report.docx\"'`가 0으로 끝났고 파일이 지워졌다.\n- 제안한 수정(IFS 비우기와 NUL 구분)을 같은 입력에 돌리면 정확한 목록이 나왔다.",
        "fix": "`_expand`에서 IFS를 비워 인자를 한 단어로 다루고, 결과를 NUL로 구분한다. `_walk`는 `find -print0 | head -z`를 쓰고 NUL로 나눈다. 공백·탭·줄바꿈 이름으로 회귀 테스트를 추가한다.",
    },
    "agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight": {
        "title": "인증 없는 `GET /static/novnc/*`가 표식 파일이 없는 동안 요청마다 `docker create`와 noVNC 전체 tar 추출을 한다(동시 실행 제어 없음)",
        "desc": "`GET /static/novnc/{path}`(api.py:355-358)에는 인증 의존성이 없고, 경로를 확인하기 전에 `extract_novnc`를 부른다. `extract_novnc`(sandbox_desktop.py:146-169)의 보호 장치는 `core/rfb.js` 존재 확인 하나다. 이 파일이 없는 동안에는 요청마다 다음을 한다.\n- `containers.create`로 컨테이너를 만든다.\n- `/usr/share/novnc` 아카이브를 메모리로 읽는다.\n- 데이터 폴더에 풀고 컨테이너를 지운다.\n락, 진행 중 표시, 실패 캐시가 없다. Docker 클라이언트를 대역으로 바꾼 실측에서 동시 요청 6개가 create 6회를, 12개가 12회를 일으켰다. 디렉터리 항목이 없는 아카이브에서는 동시 요청 5개가 `FileExistsError` 500으로 끝났다. 실제 `get_archive` 형태에서는 전부 200이었다.",
        "root": "인증 없는 정적 파일 라우트가 Docker 데몬 작업과 압축 해제를 한다. 이를 표식 파일 하나의 확인-후-실행으로만 막고, 락·진행 중 표시·실패 캐시가 없다.",
        "intended": "정적 파일은 요청마다 데몬 작업을 일으키면 안 된다. 추출은 시작할 때나 인증된 첫 데스크톱 요청에서 락을 잡고 한 번만 해야 한다. 실패하면 일정 시간 다시 시도하지 않는 상태를 남겨야 한다.",
        "obs": "- 트리를 지우고 인증 없이 GET 1회: 200, create 1회, `rfb.js` 생성. 다음 요청은 create 0회.\n- 트리를 지우고 동시 6회: create 6회. 동시 12회: create 12회. 둘 다 전부 200.\n- 디렉터리 항목 없는 아카이브: 200 1개와 500 5개.\n- 없는 파일을 3번 요청: create 3회, 응답은 모두 404.",
        "fix": "추출을 요청 경로 밖으로 옮긴다(시작할 때나 인증된 첫 데스크톱 라우트). 디렉터리별 락과 진행 중 이벤트를 두고, 성공한 뒤에만 표식을 쓴다. 실패하면 일정 시간 짧게 거절하는 실패 표식을 남긴다. 표식이 없으면 `/static/novnc/*`는 컨테이너를 만들지 않고 404·503을 준다.",
    },
    "agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback": {
        "title": "사람이 화면을 돌려주는 사이 `gui_lock`을 기다리던 GUI 입력이, 열린 구간 없이 실행돼 스냅샷과 `gui_changes` 기록이 남지 않는다",
        "desc": "GUI 입력이 스냅샷을 찍을지는 `gui_lock`을 잡기 전에 정한다(service.py:343). 사람이 화면을 쥔 동안에는 리스가 있어서 `needs_snapshot`이 False가 되고, 입력은 구간을 열지 않은 채 `gui_lock`을 기다린다. 그사이 사람이 화면을 돌려주면 입력은 리스 검사를 통과해 구간 없이 uid 1001로 실행된다. 이어서 `mark_input`이 입력 시각을 갱신한다. 그래서 그 뒤 입력도 60초 동안 입력이 없거나 마지막 스냅샷 뒤 600초가 지날 때까지 스냅샷·구간·`gui_changes`가 생기지 않는다.",
        "root": "구간을 열지 결정하는 일이, 실행을 직렬화하는 락 밖에서 일어난다. 락 안에서 다시 확인하는 `_check_control`은 리스 상태만 보고 구간이 있는지는 보지 않는다.",
        "intended": "실행되는 GUI 입력은 모두, 그 입력 전에 찍은 스냅샷에 묶인 열린 구간 안에 있어야 한다. 락을 기다리기 전에 내린 결정은 락을 잡은 뒤 다시 확인해야 한다.",
        "obs": "대기하던 클릭이 200으로 실행됐고, 판단 시점에는 리스가 있어 `needs_snapshot`이 False였다. 스냅샷은 1개 그대로였고 `gui_changes`도 인수 때 쓴 1행 그대로였다. 클릭과 뒤이은 3번의 클릭(모두 200)이 파일 4개를 만들었지만 아무 기록이 없었다. 같은 4번의 클릭을 열린 구간 안에서 한 대조군은 `gui_changes added=4`를 남겼다. 시간 창을 넓히려고 인계의 감사 기록 안에 멈춤을 넣었는데, 그 순서 자체는 코드가 허용한다.",
        "fix": "`_run_tool`이 `gui_lock`을 잡은 뒤 `needs_snapshot`을 다시 판단하고 그 자리에서 스냅샷·구간을 연다. 구간이 없으면 실패로 닫는다. 판단 기준은 입력 시각뿐 아니라 구간이 있는지까지 본다. 인계 경로에서는 다음 입력이 새 구간을 열게 한다. 위 순서로 회귀 테스트를 추가한다.",
    },
    "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap": {
        "title": "에이전트 도구 입력이 승인 미리보기와 도구 오류 문자열을 거쳐 여전히 상한 없이 추가 전용 감사 로그에 들어간다",
        "desc": "run-4 v08 수정(`_logged_args`)은 `tool_request`와 `tool_execute` 두 기록만 자른다. 같은 요청 경로에서 에이전트 문자열이 상한 없이 들어가는 곳이 두 군데 남았다.\n1. 승인이 필요한 호출의 `approval_requested` 기록이 미리보기를 그대로 담는다. 미리보기는 exec 명령 원문 전체와 조각마다 붙는 메모를 개수 제한 없이 담고, 실패하면 에이전트 경로가 든 오류 문자열을 담는다.\n2. 승인 없이 허용되는 `read_file`이 실패하면 오류 문자열 전체를 `tool_error`에 남긴다.\n본문 크기 제한도, `audit.append`의 크기 검사도 없다. 감사 행은 지울 수 없다.",
        "root": "`_call_tool`은 `_logged_args`를 거치는 두 기록만 자른다. 미리보기와 `SandboxError` 문자열은 그대로 기록되고, `audit.append` 자체에는 길이 제한이 없다.",
        "intended": "추가 전용 감사 로그에 들어가는 모든 payload는 어디서 만들어졌든 넣기 전에 크기가 제한돼야 한다. 오류 문자열, 미리보기 명령, 메모, 영향 경로를 자르고, 메모 개수도 제한한다.",
        "obs": "- `tool_request`는 `_logged_args`로 제한됐다.\n- 131,072바이트 경로의 `read_file`은 승인 없이 131,142바이트 `tool_error` 행을 남겼다.\n- 262,144바이트 경로의 `delete_file`은 262,342바이트 `approval_requested` 행을 남겼다.\n- 2,001조각 exec는 96,207바이트 행과 메모 2,001개를 남겼다.\n- `DELETE FROM audit`은 'append-only'로 거부됐다.",
        "fix": "`AuditLog.append` 안에 해시 계산 전에 문자열과 목록을 자르는 함수를 둔다. 그래야 `verify()`가 일관된다. 미리보기 명령·메모·영향 목록과 `SandboxError` 문자열도 기록 전에 자른다. 다층 방어로 도구 인자 본문 크기를 라우트와 프록시에서 제한한다.",
    },
    "agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token": {
        "title": "복원과 삭제가 겹치면 삭제한 샌드박스 행이 되살아나고, 폐기한 에이전트 토큰이 다시 유효해진다",
        "desc": "`DELETE /sandboxes/{sid}`와 `POST /sandboxes/{sid}/restore`는 같은 행을 락 없이 읽고 고쳐 쓴다. 복원이 새 컨테이너를 만든 뒤 마지막 상태를 쓰기 전에 삭제가 끝나면 다음 일이 생긴다.\n- 삭제는 성공을 돌려주고 `sandbox_delete`를 감사에 남긴다.\n- 복원의 마지막 쓰기가 `status='running'`과 새 `container_id`를 되돌려 놓는다.\n- 토큰 폐기는 `status!='deleted'`로만 표현되므로, 삭제가 폐기한 `agt_` 토큰이 다시 그 샌드박스로 연결되고 도구 호출이 새 컨테이너에서 실행된다.\n- 스냅샷 행도 남는다.\n컨트롤 플레인은 삭제가 끝났다고 보고하지만 샌드박스, `/workspace`, 에이전트 권한은 살아 있다.",
        "root": "수명 주기 작업에 샌드박스별 락이 없다. 각각 행을 한 번 읽고, 상태 조건 없는 `UPDATE`로 덮어쓴다(sandbox.py:234-237). `restore`는 `status=='deleted'`를 확인하지 않는다.",
        "intended": "`deleted`는 최종 상태여야 한다. 삭제된 샌드박스는 쓸 수 없고 그 에이전트 토큰은 무효다. 뒤이은 수명 주기 호출이나 동시 호출이 행을 되살리거나 컨테이너를 다시 붙이면 안 된다.",
        "obs": "- 경쟁 실행: 삭제가 오류 없이 끝나 상태가 `deleted`가 되고 토큰이 무효로 나왔다. 그다음 멈춰 있던 복원이 정상 반환했다.\n- 결과: 상태 `running`, 새 컨테이너가 살아 있었고 옛 토큰이 다시 유효했다. `list_dir` 호출이 200으로 실행됐다.\n- 부모가 실제 Docker로 재현했다(`agents/parent-live/artifacts/lifecycle-race.json`, 6회 중 5회). 0.25초와 0.4초 오프셋에서 되살아났고, 0.7초에서는 삭제가 이겼다.",
        "fix": "샌드박스별 수명 주기 락 하나로 pause·resume·snapshot·restore·delete를 직렬화한다. `restore`는 락 안에서 행을 다시 읽고 `deleted`면 거절한다. `_set`에 상태 조건을 넣는 방법도 함께 검토한다.",
    },
    "agentbox/service.py:snapshot-quota:toctou-between-quota-gate-and-pre-exec-snapshot": {
        "title": "스냅샷 상한은 컨테이너를 한 번 확인해서 정하는데, docker commit은 상한이 보지 않는 두 번째 확인으로 일어난다",
        "desc": "샌드박스가 `snapshot_quota`(기본 50)에 도달하면, 스냅샷이 필요한 허용 호출은 승인 요청으로 바뀌어야 한다. `_call_tool`은 상한 확인(service.py:298)에서 `_needs_snapshot`을 부른다. `write_file`이면 이것은 컨테이너 안의 `test -e` 확인이다(service.py:236 → sandbox.py:458-461). 이 확인이 '스냅샷 불필요'를 돌려주면 호출은 허용으로 남는다. 그런데 실행 직전(service.py:343)에 `_needs_snapshot`을 한 번 더 부르고, 그 결과로 상한을 다시 보지 않은 채 커밋한다(345). 두 확인 사이에 대상 경로가 생기면, 승인으로 가야 할 상한 초과 호출이 승인 없이 커밋된다. 에이전트는 허용 목록의 `touch`를 `write_file`과 동시에 보내 경로를 만들 수 있다. exec는 `SNAPSHOT_TOOLS`가 아니라 `_snap_locks`로 직렬화되지 않는다. 대기 승인 상한(20)은 승인 분기에만 걸려 이를 막지 못한다. 상한은 커밋이 쓰기 층 전체를 복사하므로 사람 없이 호스트 디스크를 채우지 못하게 하려고 있다(config.py:44-46).",
        "root": "`_call_tool`이 에이전트가 바꿀 수 있는 컨테이너 상태를 두 번 읽는다. 상한 게이트와 커밋을 하나의 '스냅샷 필요' 판단에 묶지 않고, 커밋 자리에서 상한을 다시 확인하지도 않는다.",
        "intended": "스냅샷 수가 상한에 이르면 허용 경로의 어떤 도구 호출도 사람 승인 없이 docker commit을 일으키면 안 된다. 상한 판단과 커밋을 같은 판단에 묶거나, 커밋 경로가 상한을 직접 다시 확인해야 한다.",
        "obs": "부모가 실제 Docker 엔진에서 감사 소스를 그대로 돌려 재현했다(`agents/parent-live/artifacts/snapquota-race.json`). 상한은 2이고 수동 스냅샷 2개를 먼저 만들었다.\n- 대조군: 이미 있는 파일 덮어쓰기는 202 승인 대기(규칙 `snapshot-quota`)가 됐고 커밋은 없었다.\n- 경쟁: `touch /workspace/pN`과 `write_file /workspace/pN`을 동시에 보냈다. 21번 중 18번 `write_file`이 200으로 실행되며 승인 없이 커밋됐고, 스냅샷 수가 2에서 20이 됐다.\n- write가 20ms 먼저 시작한 경우부터 exec가 10ms 먼저 시작한 경우까지는 3/3이 뚫렸다. exec가 20ms 먼저면 첫 확인이 파일을 봐서 0/3이었다.\n- 3단계 샌드박스 하네스(지연을 모델링)도 같은 모양이었다.\n- r14가 제안 수정을 적용한 하네스에서는 상한 초과 커밋이 0이었다.",
        "fix": "실행 직전 `_needs_snapshot`이 True이고 스냅샷 수가 상한 이상이면 커밋하지 않는다. 그 호출은 스냅샷 상한 승인 요청으로 돌리거나 409로 거절해 다시 부르게 한다. 이 확인을 `write_file`·`delete_file`을 이미 직렬화하는 샌드박스별 락 안에서 하면, 두 쓰기가 함께 통과하지 못한다. 두 확인 사이에 대상을 바꾸는 회귀 테스트를 추가한다.",
    },
    "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized": {
        "title": "공용 제어 문자 필터가 U+061C(빠진 유일한 Bidi_Control)와 Cf·Zl·Zp 보이지 않는 문자를 놓쳐, 승인 카드가 실행될 명령 옆에 이 문자를 그대로 보여 준다",
        "desc": "run-4 v13 수정으로 `web._shown`이 모든 템플릿 출력에 `display.escape_controls`를 걸고, run-4 공격 문자열은 막힌다. 다만 문자 집합을 손으로 나열해 Bidi_Control 12개 중 U+061C가 빠졌다. U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028, U+2029도 빠졌다. 이 문자들은 카드의 명령 `<pre>`와 영향 경로 칸에 그대로 나오고, CLI의 `_safe`도 같다. 다만 이 문자들로 카드가 다른 명령처럼 읽히는지는 확인하지 못했다. U+061C는 강한 RTL 문자라 ASCII 글자 순서를 뒤집지 못하고, 주변 문장 부호 방향에만 영향을 준다.",
        "root": "display.py:13·15가 제어·bidi 문자를 손으로 나열해 U+061C와 Cf 보이지 않는 문자, 줄·문단 구분자가 빠졌다.",
        "blockers": [
            "감사 샌드박스에는 브라우저와 터미널 렌더러가 없어 실제로 어떻게 그려지는지 볼 수 없었다. 이 문자들이 카드에 그대로 나오고 실행되는 명령에도 그대로 있다는 데까지만 확인했다.",
            "결정적 사실은 이 문자들 때문에 카드가 다른 명령처럼 읽히는가다. 브라우저 엔진, 기본 방향, 글꼴에 달렸고 저장소가 정하지 않는다.",
            "운영자가 쓰는 브라우저와 터미널을 감사가 알 수 없다.",
        ],
        "plan": "로컬: 같은 카드 조각을 루프백 정적 파일로 Playwright Chromium·Firefox·WebKit에 띄운다. 남은 문자만으로 만든 문자열을 캡처한다. 예: `echo 'x' + ALM + ';>' + ALM + ' ; python3 …'`, U+2028 삽입, 옵션 안의 ZWSP. 화면에 보이는 순서가 실제 argv와 다른지 기록한다.\n수정(결과와 관계없이 권장): display.py 두 정규식에 U+061C와 Cf·Zl·Zp 문자를 더하고 회귀 테스트를 추가한다.",
    },
    "agentbox/web.py:unauthenticated-login-failure-audit-growth": {
        "title": "인증 없는 로그인 실패마다 지울 수 없는 해시 체인 감사 행이 하나씩 쌓인다(속도 제한·집계·보존 없음)",
        "desc": "`POST /login`(web.py:130-140)은 인증 없이 받는다. 토큰이 틀리면 `ui_login_failed`를 기록하고(136), `audit.append`가 프로세스 전체 감사 락을 잡고 체인에 한 행을 넣는다. 속도 제한, 중복 제거, 집계, 상한, 정리가 없다. 삭제 트리거와 `verify()`의 id 연속성 검사 때문에 나중에 지울 수도 없다. 전제는 `same_origin`뿐인데, Origin 헤더가 없으면 통과한다.",
        "root": "인증 없는 클라이언트가 속도를 정하는 영구 기록이다. 실패 로그인 경로가 도구 실행을 막는 것과 같은 직렬화된 해시 체인 기록을 쓴다. 속도 제한과 집계가 없고, 만든 행을 보존·압축할 방법도 없다.",
        "intended": "익명 인증 실패는 감사 체인에 닿기 전에 속도를 제한하고 묶어야 한다(예: 출처·구간마다 'T 이후 N회 실패' 한 행). 한 클라이언트가 감사 기록을 마음대로 늘리거나 감사 락을 독차지하면 안 된다.",
        "obs": "- 틀린 토큰 POST 1회에 정확히 1행이 늘었다.\n- 250회에 250행이 늘었고, 요청당 약 11.5ms였다. 429나 상한은 없었다.\n- 동시 클라이언트 6개로 초당 약 270행이 쌓였다.\n- 그동안 평범한 에이전트 `tool_request` 기록이 4.6~5.5ms에서 36~40ms로 느려졌다.\n- 비 ASCII 토큰은 500(TypeError)을 내고 행을 남기지 않았다. 같은 클라이언트가 시도를 기록에서 숨길 수도 있다.",
        "fix": "감사 기록 전에 클라이언트 주소별 토큰 버킷과 전체 상한을 두고, 구간마다 '실패 N회' 요약 한 행만 남긴다. 실패가 있었다는 사실은 버리지 않는다. 감사 저장소에는 체인 검증을 유지하는 보존 방식(서명한 체크포인트와 보관 구간)을 둔다. 자격 증명은 바이트로 비교하거나 비 ASCII를 명시적으로 거절해, 기록되는 400·401이 되게 한다.",
    },
}

LIVE = {
    "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare": "Chromium 141에서 실측했다(`agents/parent-live/parent_live_scheme.py`, 결과 `artifacts/scheme-csrf.json`). 실제 앱을 `https://agentbox.test`(TLS, 443)로, 공격 페이지를 `http://agentbox.test`(80)로 띄웠다.\n- 로그인 쿠키는 `Secure; SameSite=Strict; HttpOnly`였다.\n- 공격 페이지의 `POST /ui/sandboxes`와 `POST /logout` 모두 서버에 쿠키 없이 도착했다. 샌드박스는 0개 생겼다.\n- 다만 `/logout` 응답의 쿠키 삭제가 브라우저에 적용돼 세션 쿠키가 사라졌고, 다음 `/ui` 요청은 `/login`으로 갔다. 서버 쪽 세션 종료(`ui_logout` 행)는 없었다.\n- 결론: Chromium에서는 '강제 로그아웃'만 성립하고, 사람 권한 실행은 성립하지 않는다. Firefox·WebKit은 이 환경에 없어 확인하지 못했다.",
    "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention": "실제 Docker와 16 MiB 볼륨(ext4 11 MB 사용 가능)으로 실측했다(`agents/parent-live/parent_live_diskfull.py`, `_recovery.py`, 결과 `artifacts/diskfull*.json`).\n- 샌드박스 A의 에이전트 하나가 스레드 4개로 허용된 `ls` 호출 417번을 보내 **18.9초 만에** 볼륨을 채웠다.\n- 그 뒤 실패한 것:\n  - 샌드박스 B의 에이전트 호출: 503\n  - 사람의 B 스냅샷: 503\n  - 사람의 A·B 삭제: 503. 문제를 일으킨 샌드박스조차 지울 수 없었다.\n  - 사람의 승인 결정: 503이 아니라 처리되지 않은 `sqlite3.OperationalError`가 났다. API에서는 500이다.\n- 읽기와 `verify()`는 됐다.\n- 실행이 끝난 호출 3개는 `tool_result` 기록이 빠졌다(`tool_request` 420, `tool_result` 417).\n- 복구: 오래된 100행을 지우면 `verify()`가 '1 다음에 101'로 영구 실패한다. 전부 지우면 0행을 검사하고 통과한다.\n- 남은 배포 사실은 실제 볼륨 크기뿐이다(소진 시간이 그것에 비례한다).",
    "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap": "실제 Docker와 데스크톱 샌드박스로 실측했다(`agents/parent-live/parent_live_readers.py`, 결과 `artifacts/readers-*.json`). 파일은 20만 개이고, 측정값은 프로세스 VmHWM 증가분이다.\n\n| 리더 | 최대 메모리 증가 |\n|---|---|\n| `list_dir` (`ls -la` 출력 17.4 MB, 반환 64 KiB) | 33.6 MiB |\n| 상한 있는 exec(`ls -la`, 대조군) | 0.5 MiB |\n| outbox 목록 | 90.2 MiB |\n| `rm /workspace/many/*` 미리보기 glob | 64.7 MiB |\n| 스크린숏 경로를 `/dev/zero` 링크로 | 77.8 MiB, 15초 X 제한 시간에 끊김 |\n\n결론: 증가는 실제이고 파일 수에 비례한다. 다만 스크린숏 최악 경우도 제한 시간으로 묶인다. 메모리 상한이 없는 배포에서 해가 되려면 수백만 개 파일이나 많은 동시 호출이 필요하다.",
    "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process": "실제 `agentbox-desktop:0.1` 샌드박스에서 끝까지 재현했다(`agents/parent-live/parent_live_netwmpid.py`, `netwmpid_forge.py`, 결과 `artifacts/netwmpid-stray.json`).\n- 이미지 도구 확인: xprop과 컴파일러는 없다. 하지만 `python3`와 `libX11.so.6`이 있어, ctypes로 아무 `_NET_WM_PID`나 쓸 수 있다.\n- 구간 시작 세션에 넣기: `xfconf-query`로 사용자 단축키 명령을 등록하고 키를 누르면, 기준 프로세스인 `xfsettingsd`가 쓰기 데몬을 띄운다. 데몬은 sid 1에 있고 docker exec 출신이 아니다. 에이전트가 GUI 입력만으로 할 수 있는 경로다.\n- 위조 창(1×1, `_NET_WM_PID`=데몬 pid)을 띄우자 실제 `desktop_processes`가 그 pid를 창 pid로 보고했다. `gui_strays`는 데몬을 정리 목록에서 뺐고, `kill_processes` 뒤에도 데몬이 살아 `/workspace` 파일을 계속 갱신했다.\n- 대조: 위조 창을 빼면 데몬이 정리 목록에 들어갔다.\n- 한 번 살아남으면 다음 구간의 기준(baseline)에 들어가 계속 면제된다.\n- 막힌 지점 세 개(이미지 도구, 세션 배치, 실제 정리)가 모두 풀렸다.",
    "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized": "실제 앱의 `/ui/approvals` 카드를 Chromium 141로 그려 캡처했다(`agents/parent-live/parent_live_bidi.py`, 결과 `artifacts/bidi-*.png`, `bidi-render.json`).\n- `cat /workspace/notes.txt ALM>ALM /workspace/outbox/copy.txt`는 카드에 **`cat /workspace/notes.txt < /workspace/outbox/copy.txt`**로 보였다. 두 ALM 사이의 `>`가 오른쪽→왼쪽으로 풀리며 `<`로 거울 반전됐다.\n- 같은 문자열을 bash로 실행하면 이름이 ALM인 새 파일을 만들고 내용을 써 넣는다(`artifacts/bidi-bash-exec.txt`). 화면은 '입력 리디렉션(읽기)'인데 실제는 '출력 리디렉션(쓰기)'이다.\n- U+2028은 같은 줄에 공백처럼 보였고, ZWSP는 보이지 않았다. 둘 다 위험한 쪽으로 오해시키지는 않았다.\n- 결론: Chromium에서 승인 카드가 다른 명령처럼 읽힌다. Firefox·WebKit은 확인하지 못했다.",
}

for _fp, _v in LIVE.items():
    KO[_fp]["live"] = _v
