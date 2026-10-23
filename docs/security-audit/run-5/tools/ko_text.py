"""Korean text for the run-5 Phase 6 reports (written by the parent from findings.json).

The English record in findings.json stays authoritative; gen6.py renders these Korean fields and attaches the
original record text below each entry.
"""

KO = {
    "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention": {
        "title": "에이전트 exec 한 번이 요청의 약 45배 크기인 승인 대기 행을 써서, PR #20의 디스크 보호선을 한 번에 넘는다",
        "desc": "PR #20은 `call_tool` 입구에서 남은 공간을 보는 보호선(`disk_low`)과 끝난 승인 행 줄이기를 넣었다. 그러나 승인 대기 행은 원문 그대로, 크기 제한 없이 쓰였다. 미리보기는 알아보지 못한 셸 조각마다 약 90바이트짜리 한국어 메모를 붙인다. 그래서 2바이트 조각 `x;`를 이어 붙인 명령은 요청의 약 45배 크기 미리보기를 만든다(기본 정책에서 승인 요청으로 간다). 이 행은 WAL 모드 SQLite라 DB와 `-wal`에 두 번 쓰인다. 보호선은 호출 입구에서 한 번만 본다. 13만 바이트 요청 하나가 DB를 6.0MB, WAL을 6.1MB 키웠고, 그 뒤 `disk_low()`가 참이 됐다. 8MiB 본문이면 한 번에 수백 MB가 되어 기본 여유 256MiB를 혼자 넘는다(외삽). 끝난 뒤 줄여도 파일은 줄지 않는다. 디스크가 차면 사람의 결정·삭제가 503으로 막히고, 승인 화면은 행의 메모를 전부 그린다.",
        "root": "보호선이 호출 입구의 한 번 확인뿐이다. 승인 요청 분기의 미리보기(`preview.py:125`)는 메모 수에 상한이 없고, `approvals.create`는 인자와 미리보기를 그대로 저장한다. `bound_payload`는 감사 로그 사본과 끝난 행에만 적용됐다.",
        "intended": "에이전트 요청 하나가 작은 고정 상한 이상의 승인 데이터를 남기지 않는다. 대기 행도 감사 로그와 같은 묶인 모양이어서, 받아들인 호출 하나가 보호선의 여유를 넘지 못한다.",
        "obs": "샌드박스에서 실제 정책·미리보기·승인 저장소·감사 코드로 재현했다(가짜 SandboxManager).\n- `x;`×65,536(본문 131,097바이트): 202, `disk_low` 거짓→참, DB 4,096→6,004,736바이트(45.8배), WAL 6,089,392바이트.\n- 대기 행 인자 131,087바이트, 미리보기 5,832,767바이트(메모 65,536개). 감사 로그 사본은 83,141바이트로 묶였다.\n- 만료로 행을 줄여도 DB 파일은 6.0MB→12.1MB로 오히려 커졌다. 승인 화면 조각은 이 행 하나에 7.47MB였다(헌터 측정).",
        "fix": "미리보기 메모 수 상한, 대기 행 미리보기에도 `bound_payload`, 행을 쓰기 직전 디스크 보호선 재확인, 에이전트 문자열 인자의 길이 상한(정책 판단 전 413).",
    },
    "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease": {
        "title": "사람이 화면을 인수한 동안 에이전트 GUI 구간이 열려, 사람이 띄운 프로세스를 멈추고 사람의 편집을 에이전트 변경으로 남긴다",
        "desc": "`AgentBox._snapshot`은 `gui_lock` 없이, 인수 여부도 보지 않고 GUI 구간을 닫고 연다. 인수 중에 GUI 입력 승인을 결정하거나(`decide`), 에이전트 클릭의 입력 전 `docker commit` 중에 사람이 인수하면(`call_tool`), 인수 중에 잡은 기준으로 구간이 열린다. 입력은 423이나 실패로 끝나지만 구간은 남는다. 그 구간이 쉬어 닫힐 때(에이전트의 아무 도구 호출이나 `GET /approvals/{aid}`로 시점을 고를 수 있다) 인수 중에 사람이 띄운 셸·작업이 `kill -KILL`되고, 사람의 `/workspace` 편집이 에이전트 구간의 `gui_changes`로 남는다. 인수가 구간을 먼저 닫는 설계 의도(service.py:582)를 우회한다.",
        "root": "`_snapshot`(service.py:261-276)의 구간 열기가 인수와 같은 잠금으로 직렬화되지 않고 인수 여부를 보지 않는다. 인수 확인은 커밋 전 `needs_snapshot`에만 있고 `decide`에는 없다. 423·실패 처리기가 방금 연 구간을 치우지 않는다.",
        "intended": "사람이 화면을 쥐고 있거나 쥐려는 동안에는 에이전트 GUI 구간(기준, 멈추기, 변경 귀속)이 존재하지 않는다.",
        "obs": "실제 Docker와 `agentbox-desktop:0.1`에서 부모가 재현했다(`agents/parent-live/artifacts/gui_lease_a.json`).\n- 클릭을 승인 대상으로 둔 정책에서 인수 → 에이전트 클릭 202 → 사람이 인수 중 승인 → `failed`, 구간은 열린 채 남음.\n- 인수 중에 사람 몫으로 `setsid sleep 600`(pid 400)을 띄우고 쉬는 시간이 지난 뒤 정리 호출 → 인수가 유지된 채 `gui_processes_stopped`(reason idle)로 pid 400이 멈춤.\n- 샌드박스 재현(가짜 Docker): 경쟁이 없을 때는 멈춘 것 없음, 커밋 중 인수(b)와 승인(a) 경로는 사람 셸·작업 [201, 202]를 멈추고 사람 파일을 에이전트 변경으로 기록.",
        "fix": "구간은 인수와 같은 `gui_lock` 아래에서, 인수·인수 대기가 없을 때만 연다(있으면 열지 않고 423). 인수 중에 결정한 GUI 입력 승인은 스냅샷 없이 실패로 끝낸다.",
    },
    "agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt": {
        "title": "정리 명령이 반영(COMMIT) 직후 중단되면, 이미 지운 감사 행의 유일한 사본인 아카이브를 지운다",
        "desc": "`retention.prune`은 아카이브를 쓴 뒤 한 트랜잭션에서 행을 지우고 아카이브 sha256을 담은 기준점을 남긴다. 안쪽 처리기는 어떤 예외에도 ROLLBACK하고, 바깥 처리기는 어떤 예외에도 아카이브를 지운다. 둘 다 COMMIT이 끝났는지 보지 않는다. fsync로 오래 걸리는 COMMIT 중에 Ctrl-C가 오면 COMMIT이 끝난 직후 KeyboardInterrupt가 나고, ROLLBACK이 'no transaction is active'로 실패하고, 바깥 처리기가 아카이브를 지운다. DB는 1..N행을 그 아카이브로 옮겼다고 말하지만 아카이브는 없다. `verify()`는 계속 통과하고 `verify_archives`는 다시는 통과하지 못한다.",
        "root": "아카이브 정리(retention.py:130-131)가 '트랜잭션이 반영되지 않았을 때'가 아니라 '예외가 났을 때' 돈다. 안쪽 ROLLBACK도 트랜잭션이 이미 끝났는지 보지 않는다.",
        "intended": "아카이브는 정리가 반영되지 않았을 때만 지운다. 기준점이 이 아카이브를 가리키면 어떤 예외가 와도 남긴다.",
        "obs": "샌드박스에서 COMMIT 직후 SIGINT를 내는 연결로 재현했다. 예외는 OperationalError(바탕 KeyboardInterrupt), 아카이브 없음, 감사 행 6~8과 기준점(last_id 5) 남음, `verify()` ok·pruned_through 5, `verify_archives([archive])`는 FileNotFoundError. 실제 비동기 SIGINT를 실제 20,000행 COMMIT 중에 보내도 5번 모두 같은 처리기 경로를 탔다(헌터 h2).",
        "fix": "트랜잭션이 남아 있을 때만 ROLLBACK한다. 바깥에서는 이 아카이브를 가리키는 기준점이 있는지 보고 없을 때만 지우며, 확인하지 못하면 남긴다. 아카이브를 쓰다 실패하면 쓰다 만 파일을 지운다.",
    },
    "agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop": {
        "title": "화면 웹소켓 처리기가 이벤트 루프에서 SQLite·감사 잠금을 기다려, 연결 하나에 모든 HTTP 요청이 멈춘다",
        "desc": "async 라우트 `/sandboxes/{sid}/desktop/ws`와 `desktop_ws.relay`가 세션 조회, vnc 명령 준비(SQLite+Docker), 연결 감사 기록, 입력마다의 `touch()`, 30초마다의 세션 재확인, 끊을 때의 감사 기록을 이벤트 루프에서 동기로 부른다. 다른 연결이 DB 쓰기 잠금을 쥔 동안(정리 명령의 BEGIN IMMEDIATE 등) 또는 다른 스레드가 감사·화면 잠금을 쥔 동안, 화면 연결·끊기 하나가 사람의 승인·삭제와 `/healthz`를 포함한 모든 요청을 최대 5초 멈춘다. 화면 링크 세션이나 자동 재연결하는 화면 탭이 이를 되풀이할 수 있다. 공격자가 긴 잠금 자체를 만들 수는 없고, 잠금이 있는 동안 이벤트를 일으킬 수 있다.",
        "root": "`desktop_ws`와 `relay`가 막히는 호출을 스레드로 보내지 않는다. `DesktopControl`은 메모리 잠금을 쥔 채 SQLite를 써서, 이벤트 루프가 그 SQLite 대기까지 물려받는다.",
        "intended": "이벤트 루프는 SQLite, I/O 동안 쥔 잠금, Docker를 기다리지 않는다. 느린 DB는 그것이 필요한 요청만 늦춘다.",
        "obs": "샌드박스에서 실제 앱(가짜 Docker)으로 재현했다. 기준 `/healthz` 0.0초. 쓰기 잠금 중 링크 세션 연결: `/healthz` 4.71초, 연결은 5.02초 뒤 1011로 닫힘. 화면 세션 생성이 쓰기 잠금을 기다리는 동안 아무 쿠키 연결: 4.41초. 감사 잠금 4초 중 링크 세션 연결: 3.51초.",
        "fix": "세션 확인·vnc 명령 준비·연결/끊기 기록·세션 재확인을 스레드에서 한다. `DesktopControl`은 메모리 상태와 SQLite를 다른 잠금으로 지켜, 입력마다 부르는 `touch`·`lease`가 SQLite를 기다리지 않게 한다.",
    },
    "agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap": {
        "title": "최대 8MiB의 에이전트 exec 명령이 호출마다 GIL을 쥔 정책 파싱을 수 분씩 일으켜 컨트롤 플레인을 느리게 한다",
        "desc": "에이전트는 `x;x;x;…` 같은 명령을 본문 상한 8MiB까지 보낼 수 있고, 정책 판단 전에 명령 길이 상한이 없다. 기본 정책의 첫 규칙이 `command_names`→`_words`를 부르는데, `_words`는 셸 구분 문자가 든 토큰마다(맨 `;`도) `shlex`를 새로 만들고 깊이 한도까지 되풀이한다. 토큰당 약 40µs, 선형이라 128KiB에 약 5초, 8MiB면 약 5분(외삽)이다. 일은 공유 32스레드 풀에서 GIL을 쥐고 돌며, 에이전트 하나가 4개를 동시에 돌릴 수 있고, 승인 대기 상한보다 먼저 일어난다. 같은 프로세스의 대리 이벤트 루프가 중앙값 약 4배, 최대 30배 이상 느려졌다(멈춤은 아님).",
        "root": "정책 판단에 입력 크기 상한이 없다(service.py:311 앞). `_words`(policy.py:40-62)가 다시 쪼개도 같은 토큰까지 매번 새 shlex로 다시 렉싱한다.",
        "intended": "작은 고정 상한을 넘는 에이전트 인자는 정책 판단·미리보기 전에 거절된다. `_words`는 다시 렉싱해도 같은 토큰을 다시 보지 않아, 판단이 밀리초 단위로 끝난다.",
        "obs": "샌드박스에서 기본 정책으로 측정: `x;`×n 16/32/64/128KiB → 0.76/1.20/2.39/5.54초, 선형. 대리 이벤트 루프(메인 스레드): 평소 중앙값 1.6ms·최대 1.9ms, 판단 1개 6.9/12.2ms, 4개 7.4/60.0ms. 8MiB 수치는 외삽이다.",
        "fix": "에이전트 문자열 인자(write_file 본문 제외) 16KiB 상한(정책 판단 전 413). `_words`는 다시 렉싱해도 결과가 같은 토큰(구분자만 있는 토큰, 공백·구분자·따옴표·역슬래시가 없는 토큰)만 건너뛴다. 탐지는 예전과 같다(무작위 10만 개 비교).",
    },
    "agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound": {
        "title": "승인 미리보기가 rm 피연산자마다 제한 시간 없는 docker exec를 두 번씩, 횟수 상한 없이 돌린다",
        "desc": "승인이 필요한 exec 명령에 rm 조각이 있으면 미리보기가 피연산자마다 `expand`, `-r`이면 일치마다 `walk`를 부른다. 각각 제한 시간 없는 `docker exec`다. 표시 상한 200은 모든 exec가 끝난 뒤 목록만 자른다. 피연산자 수 상한은 본문 8MiB뿐이다. 그래서 작은 요청 하나가 공유 도구 스레드를 피연산자 수에 비례해(exec 1회 약 80ms) 승인 요청이 만들어지기 전까지 붙잡는다. 승인 대기 상한은 미리보기 전에 확인돼 막지 못한다. 다른 샌드박스의 요청이 느려지는 것은 관측되지 않았다.",
        "root": "`preview_command`에 exec 횟수·전체 시간 상한이나 표가 찬 뒤의 중단이 없고, `_expand`·`_walk`가 `_timed` 없이 exec한다.",
        "intended": "미리보기는 작은 고정 횟수와 시간 안에서만 컨테이너를 확인하고, 넘으면 '미리보기 불완전'이라고 알리고 사람에게 넘긴다.",
        "obs": "실제 Docker 엔진에서 부모가 측정했다(`agents/parent-live/artifacts/preview_exec.json`). 피연산자 50개: 202까지 8.05초, exec_start 99회. 200개: 30.75초, 399회(exec 1회 77~81ms). 다른 샌드박스의 허용된 `ls`는 느려지지 않았다. 64KiB·8MiB 수치는 외삽이다.",
        "fix": "미리보기의 컨테이너 확인은 모두 합쳐 40회까지, 각 10초 제한. 같은 피연산자는 한 번만. 넘으면 계산하지 않았다고 알린다. 인자 길이 상한(16KiB)도 함께 묶는다.",
    },
    "agentbox/api.py:preauth-request-body-read-before-principal": {
        "title": "인증 없는 JSON 본문을 principal() 전에 해석한다. 8MiB 요청 하나가 401 전에 약 200MB를 쓰고, 512MiB 제한에서는 동시 4건에 서버가 OOM으로 죽었다",
        "desc": "run-4 F1 수정(PR #16)으로 본문 바이트는 라우팅 전에 8MiB로 묶였다. 그러나 이 상한은 인증 여부와 같고, FastAPI는 본문을 읽고 JSON을 해석한 뒤에야 `principal`·`human_only`를 푼다(모든 JSON 라우트에서 이벤트 루프 위에서). 빈 객체로 된 JSON은 크기의 약 26배 객체가 된다. 실제 uvicorn 서버에서 토큰 없는 8MiB 요청 하나가 RSS를 59→260MB로 올렸다(401). 1GiB 제한에서는 동시 8건까지 살아남았고(최고 734MB), 512MiB 제한에서는 동시 4건에 프로세스가 OOM으로 죽었다(exit -9, 세 번 재현). 실제 배포가 죽는지는 배포의 메모리 제한에 달렸다.",
        "root": "인증 의존성이 FastAPI의 본문 해석 뒤에 돈다. 인증 전 상한은 인증된 최대 요청에 맞춘 8MiB 바이트 상한 하나뿐이고, JSON 확대율, 자격 증명 없는 요청의 작은 상한, 인증 전 해석의 동시성 상한이 없다.",
        "blockers": [
            "배포의 메모리 제한은 저장소 밖이다. compose에는 제한이 없다. 1GiB에서는 동시 8건을 견뎠고 512MiB에서는 동시 4건에 죽었다.",
            "지속 부하 때의 이벤트 루프 굶주림과 재시작·복구 시간은 측정하지 않았다(부하 시험 금지). compose는 `restart: unless-stopped`다.",
            "배포 앞단(엣지)이 더 작은 본문 상한이나 연결·속도 제한을 둘 수 있다. 동봉 Caddyfile은 모든 경로에 256MB다.",
        ],
        "plan": "로컬 OOM은 이미 세 번 재현했다(부모, r-preauth, rv-preauth). 남은 것은 수정 확인이다: 자격 증명 없는 JSON 요청을 본문을 읽기 전에 거절하거나 작은 상한을 둔 뒤, 같은 스크립트를 512MiB 제한에서 동시 4건으로 다시 돌려 401/413과 RSS 무증가를 본다. 배포 쪽은 메모리 제한, 엣지의 본문·속도 제한, 1초 이상 멈춤이나 재시작을 받아들일지를 소유자가 정한다.",
        "live": "- 1GiB: 단건 401(0.69초, RSS 59→260MB), 동시 4건 최고 703MB·그 사이 `/healthz` 1.23초, 동시 8건 최고 734MB·생존.\n- 512MiB: 단건 401(최고 267MB), 동시 4건에서 연결 리셋·exit -9(OOM). r-preauth·rv-preauth가 각자 같은 결과를 냈다.",
    },
    "agentbox/sandbox.py:SandboxManager.snapshot:delete-race-orphaned-snapshot-image": {
        "title": "삭제 중 커밋이 고아 스냅샷 이미지·행을 남긴다는 주장 — 실제 Docker 29.9.1에서 성립하지 않아 기각",
        "reason": "소스상 경쟁은 있다(삭제는 `_lifecycle`만, 스냅샷은 `_snap_locks`만 잡는다). 그러나 실제 dockerd는 진행 중 커밋의 컨테이너를 강제 삭제하면 커밋을 404('failed to apply diff: NotFound: snapshot')로 실패시켰다. 커밋 시작 0.5~8.5초 뒤 다섯 시점 모두에서 스냅샷 행·이미지·뒤늦은 'snapshot' 감사 기록이 없었다. 남는 창은 1초 미만이고 영향은 호스트 이미지 하나라 하드닝으로 남긴다.",
    },
}
