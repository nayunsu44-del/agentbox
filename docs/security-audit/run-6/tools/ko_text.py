"""Korean text for the run-6 Phase 6 reports (written by the parent from findings.json).

The English record in findings.json stays authoritative; gen6.py renders these Korean fields and attaches the
original record text below each entry.
"""

KO = {
    "agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore": {
        "title": "복원 중 열린 옛 컨테이너의 GUI 구간을 GuiBursts.covers()가 구분하지 못해, 복원된 컨테이너에서 실행된 에이전트 프로세스가 정리·기록에서 빠진다",
        "desc": "`GuiBursts.covers(sid)`(`gui_bursts.py:68-71`)는 `sid in self._gui_burst`만 볼 뿐, 열린 구간의 `container_id`가 지금 샌드박스의 `container_id`와 같은지 보지 않는다. 또한 `restore_sandbox`(`service.py:573-581`)는 `sandboxes.restore` 전에 `end_desktop`(`bursts.end`)을 한 번 부르고, 복원이 끝난 뒤에는 `bursts.reset_timers(sid)`만 부른다(`_gui_burst[sid]`를 비우지 않는다). 에이전트의 GUI 도구 호출이 복원 전 컨테이너 C1의 `sandboxes.snapshot` 커밋을 끝내고 `end_desktop` 직후에 `bursts.open`을 돌리면, `_gui_burst[sid]`에는 `container_id = C1`인 구간이 열린다. 이어서 `sandboxes.restore`가 컨테이너를 C2로 바꾸고 `reset_timers`가 끝나도 `_gui_burst[sid]`는 그대로 남는다. 그 호출(또는 뒤이은 GUI 입력)이 `_run_tool`에 들어가면 `covers(sid)`가 `True`를 돌려주어 새 컨테이너 C2에서 C1 구간 아래로 GUI 입력이 실행된다. 나중에 이 구간이 닫힐 때 `_finish`(`gui_bursts.py:131-136`)는 `C2 != C1`(`replaced = True`)을 보고 `gui_burst_close_failed`만 남긴 채 `_stop_strays`와 `diff_manifest`를 건너뛴다. 그 결과 C2에서 에이전트가 띄운 백그라운드 프로세스는 죽지 않고 살아남아 다음 구간의 기준(baseline) PID에 들어가 영구히 면제되며, 파일 변경도 `gui_changes`에 남지 않는다.",
        "root": "1) `GuiBursts.covers(sid)`(`gui_bursts.py:71`)가 `self._gui_burst[sid]['container_id'] == self.sandboxes.get(sid)['container_id']`를 확인하지 않는다.\n2) `restore_sandbox`(`service.py:578`)가 `sandboxes.restore` 뒤에 `bursts.end(sid, ...)` 대신 `bursts.reset_timers(sid)`만 호출하고, `_snapshot`(`service.py:267-279`)과 `restore_sandbox`가 같은 잠금을 공유하지 않아 복원 도중 옛 컨테이너 기준으로 열린 구간이 복원 뒤에도 살아남는다.",
        "intended": "`GuiBursts.covers(sid)`는 열린 구간의 `container_id`가 현재 샌드박스의 `container_id`와 일치할 때만 `True`를 돌려주어야 하며, `restore_sandbox`는 컨테이너가 바뀐 뒤에도 옛 컨테이너의 구간이 남아 있지 않도록 닫아야 한다.",
        "obs": "샌드박스(`agents/h-gui-burst/artifacts/h.out`)와 실제 일회용 Docker 컨테이너(`agents/parent-live/artifacts/gui_burst_restore_live.out`)에서 모두 재현했다.\n- C1에서 구간을 연 뒤 `sb.restore(sid, snap_id)`로 C2로 복원하고 `bursts.reset_timers(sid)`를 호출해도 `bursts.covers(sid)`는 `True`다.\n- C2에서 백그라운드 프로세스(`sleep 300`)를 띄우고 파일을 바꾼 뒤 `bursts.close(sid, 'idle')`을 부르면 `gui_burst_close_failed`(`컨테이너가 바뀌어 비교하지 않음 (복원)`)만 남고 `sleep 300`은 죽지 않고 살아남으며 `gui_changes`도 기록되지 않는다.",
        "fix": "`GuiBursts.covers(sid)`에서 열린 구간의 `container_id`를 현재 `sandboxes.get(sid)['container_id']`와 비교하고, `restore_sandbox`가 `sandboxes.restore` 뒤에도(또는 `gui_lock`/`_snap_locks`와 직렬화하여) 옛 컨테이너로 열린 구간을 정리한다.",
    },
    "agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory": {
        "title": "감사 테이블에 sandbox_id 인덱스가 없고 verify()가 전체 테이블을 fetchall()로 읽어, 테이블이 커지면 AuditLog._lock 경합과 메모리 급증을 일으킨다",
        "desc": "`audit` 테이블 스키마(`audit.py:17-27`)에는 `sandbox_id` 인덱스가 없다. 그런데 샌드박스 웹 화면(`templates/sandbox.html:19`)이 3초마다 폴링하는 `GET /ui/audit`는 `AuditLog.recent(sandbox_id=..., limit=400)`(`web.py:293`)를 부르고, `recent()`(`audit.py:325-334`)는 전역 `AuditLog._lock`을 잡은 채 인덱스 없는 `SELECT COUNT(*) FROM audit WHERE sandbox_id = ?`와 `SELECT ... WHERE sandbox_id = ? ORDER BY id DESC LIMIT ?`를 실행한다. 에이전트가 90일 보관 기간 동안 일상적인 도구 호출·승인 미리보기(행당 최대 128KiB)로 수천~수만 행을 쌓으면, SQLite 페이지 크기(4KiB) 특성상 행마다 리프·오버플로 페이지가 생겨 3초마다 전체 테이블 스캔이 `_lock` 아래에서 돈다. 또한 `AuditLog.verify()`(`audit.py:336-350`)는 `_lock`을 잡은 채 `SELECT ... FROM audit ORDER BY id`의 `.fetchall()`로 전체 행과 페이로드를 한꺼번에 파이썬 메모리에 올리고 해시를 다시 계산한다. 그동안 모든 도구 기록과 실패 시 닫히는(fail-closed) 사람의 `log_human` 호출이 `AuditLog._lock`에서 멈춘다.",
        "root": "`audit` 테이블에 `sandbox_id` 인덱스가 없고, `AuditLog.recent()`·`verify()`·`list()`가 추가(append)와 같은 프로세스 전역 `AuditLog._lock`을 잡은 채 전체 스캔·전체 행 `fetchall()`을 수행한다.",
        "intended": "`recent()`는 `audit(sandbox_id, id)` 인덱스로 해당 샌드박스의 행만 빠르게 읽어야 하며, `verify()`는 `fetchall()`로 전체 테이블을 한 번에 메모리에 올리거나 긴 시간 동안 추가용 `_lock`을 붙잡지 않고 배치(스트리밍)나 별도 읽기 연결(WAL)로 검증해야 한다.",
        "obs": "512MiB 샌드박스에서 약 25.2KiB 페이로드 1,200행(DB 30.49MiB)으로 헌터(`agents/h-locks-ws/artifacts/bench_realistic.out`)와 3단계 검증자(`agents/v-audit-lock/artifacts/v.out`)가 각각 측정했다.\n- 3단계 독립 검증에서 인덱스 없는 `recent('sb_target', limit=25)` 평균 잠금 점유 시간은 **175.15ms**였고, `audit(sandbox_id)` 인덱스를 추가하면 **28.86ms**(6.07배 단축)로 줄었다(헌터 측정은 `recent('sb_other', limit=25)` 113.31ms).\n- 유효한 해시 체인 전체를 검증하는 `verify()`는 `AuditLog._lock`을 **5,628.31ms(5.63초)** 동안 잡고 최고 **58.64MiB** 힙 메모리를 썼다.\n- 10,000행(약 200MiB DB)으로 외삽하면 `verify()`는 약 **46.9초** 동안 `_lock`을 잡고 약 **488.6MiB** 메모리를 쓰며, 3초마다 도는 웹 UI 폴링은 폴링마다 약 **1.46초**(3초 주기의 48% 이상) 동안 `_lock`을 점유한다.",
        "fix": "`SCHEMA`에 `CREATE INDEX IF NOT EXISTS audit_sandbox_id ON audit(sandbox_id, id)`를 추가하고, `AuditLog.verify()`는 `fetchmany()`로 나누어 읽거나 WAL 읽기 전용 연결을 써서 전체 테이블 적재와 긴 `_lock` 점유를 없앤다.",
    },
    "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets": {
        "title": "승인 영향 미리보기가 중괄호({a,b})와 틸드(~) 확장을 계산하지 못해 실제 삭제될 파일을 '현재 존재하지 않음'으로 잘못 표시한다",
        "desc": "사람이 승인할 때 보는 영향 미리보기 카드는 `preview_command`(`preview.py:70-160`)가 명령을 `shlex`로 쪼갠 뒤 컨테이너의 `_expand`(`sandbox.py:578-585`)로 넘겨 만든다. 그런데 `_expand`는 컨테이너의 `/bin/sh`(dash)에서 위치 인자 `$1`로 패턴을 평가한다. POSIX dash는 중괄호 확장(`{a,b}.txt`, `{1..10}`)을 지원하지 않고, 변수(`$1`) 안의 틸드(`~/file`)도 확장하지 않는다. 그 결과 `[ -e \"$p\" ]`가 거짓이 되어 빈 목록이 돌아오고, `preview_command`(`preview.py:110-111`)는 이를 `{'path': op, 'effect': '삭제 시도 (현재 존재하지 않음)'}`으로 표시하며 주의 메모(`notes`)도 붙이지 않는다(`preview.py:88`은 `$`, `` ` ``, `<(`, `eval `만 검사한다). 사람이 '현재 존재하지 않음'이라는 카드를 믿고 승인하면, 실제 실행(`sandbox.py:425`)은 `/bin/bash`로 돌아 중괄호·틸드를 확장하고 실제 파일을 삭제한다.",
        "root": "미리보기 경로 확장(`_expand`, `/bin/sh`)과 실제 실행 셸(`exec`, `/bin/bash`)의 확장 규칙이 다른데, `preview_command`가 `{`나 `~`가 들어간 피연산자에 대해 경고를 남기지 않고 빈 확장 결과를 곧바로 '현재 존재하지 않음'으로 단정한다.",
        "intended": "승인 미리보기는 실행 셸(`/bin/bash`)과 같은 확장 규칙으로 대상 파일을 계산하거나, 자동 계산이 지원하지 않는 셸 확장(`{`, `~` 등)이 있으면 `notes`에 자동 계산이 정확하지 않다는 경고를 띄워 사람이 명령 원문을 확인하게 해야 한다.",
        "obs": "샌드박스(`agents/h-preview-argcap/artifacts/h.out`)와 실제 일회용 Docker 컨테이너(`agents/parent-live/artifacts/preview_brace_tilde_live.out`)에서 모두 확인했다.\n- `/workspace/a.txt`, `/workspace/b.txt`, `/home/agent/tilde_target.txt`가 있을 때 `sb.preview(sid, 'rm {a,b}.txt')`와 `sb.preview(sid, 'rm ~/tilde_target.txt')`는 모두 `effect: '삭제 시도 (현재 존재하지 않음)'`, `notes: []`를 돌려준다.\n- 같은 명령을 `sb.exec`로 실행하면 `exit_code=0`으로 세 파일이 모두 삭제된다.",
        "fix": "`preview.py:88`의 치환·확장 경고 검사에 `{`와 `~`를 추가하거나(또는 피연산자에 `{`·`~`가 있을 때 미확장 경고), `_expand`를 실행과 같은 `/bin/bash` 기반으로 맞춘다.",
    },
    "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare": {
        "title": "same_origin()이 Origin의 호스트:포트(netloc)만 비교하고 스킴(http vs https)은 보지 않는다",
        "desc": "`agentbox/api.py:221-223`의 `same_origin(headers)`는 `urlsplit(origin).netloc == headers.get('host')`만 비교하고 `urlsplit(origin).scheme`은 보지 않는다. 또한 세션 쿠키의 `SameSite=Lax`(`desktop.py:21`)는 스킴을 구분하지 않는다(schemeful SameSite가 아님). 따라서 같은 호스트 이름의 평문 `http://` 출처(또는 비표준 포트 `https://host:8443`을 평문 `http://host:8443`으로 부른 경우)에서 보낸 요청도 `same_origin`을 통과한다. 다만 실제 악용 가능성은 배포 토폴로지(Caddy 리버스 프록시가 80→443 리다이렉트를 강제하는지, 비표준 포트를 직접 노출하는지, 네트워크 경로에 평문 HTTP를 가로챌 수 있는 공격자가 있는지)에 좌우된다.",
        "root": "`same_origin(headers)`가 `Request`의 유효 스킴(또는 `X-Forwarded-Proto`)과 `urlsplit(origin).scheme`을 비교하지 않고 `netloc`만 비교한다.",
        "blockers": [
            "동봉된 기본 배포(`deploy/Caddyfile`)는 80 포트를 HTTPS로 리다이렉트하고 443에서 TLS를 종료하므로, 같은 `host:port`에서 평문 HTTP 응답을 받을 수 없다.",
            "비표준 포트에서 HTTPS를 직접 띄우거나 리버스 프록시 없이 평문 HTTP를 함께 열어 두는지는 운영 배포 설정에 달려 있다.",
        ],
        "plan": "배포 환경에서 (1) TLS가 비표준 포트에 직접 바인딩되는지, (2) 같은 호스트의 평문 80 포트가 리다이렉트 없이 열려 있거나 네트워크 상에서 가로채기 가능한지 확인한다. 코드 수준에서는 `secure_cookie(request)`가 참일 때 `urlsplit(origin).scheme == 'https'`까지 함께 요구하면 배포 가정과 무관하게 닫힌다.",
        "live": "- `TestClient(app, base_url='https://box.example.com')`와 `https://box.example.com:8443`에서 세션 쿠키를 싣고 `Origin: http://box.example.com` 및 `Origin: http://box.example.com:8443`으로 `GET /ui/verify`를 호출하면 모두 `200 OK`가 난다(`agents/parent-live/artifacts/same_origin_live.out`). 다른 호스트(`Origin: https://evil.example.com`)는 `403`으로 막힌다.",
    },
    "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap": {
        "title": "exec 외의 컨테이너 출력 판독기들이 docker-py의 스트리밍 상한(_Head) 없이 c.exec_run()으로 전체 출력을 메모리에 먼저 받는다",
        "desc": "`SandboxManager.exec`(`sandbox.py:427-430`)은 `api.exec_start(..., stream=True, demux=True)`와 `_Head()`로 스트림을 읽으면서 64KiB까지만 메모리에 남긴다. 반면 다른 컨테이너 판독기들(`workspace_manifest`, `_expand`, `_walk`, `read_file`, `list_dir`, `screenshot`, `desktop_processes`)은 `c.exec_run(..., demux=True)`를 부른 뒤 파이썬으로 돌아온 전체 바이트열에 `_truncate`를 적용한다. 그중 `workspace_manifest`, `_expand`, `_walk`, `read_file`은 컨테이너 안의 `head -c`로 바이트 상한이 걸려 있지만, `list_dir`(`ls -la`), `desktop_processes`(`ps -eo ...`), `screenshot`(`cat /home/desktop/.cache/agentbox-shot.png`)에는 컨테이너 쪽 `head -c`나 호스트 쪽 `_Head()` 스트림 상한이 없다.",
        "root": "`c.exec_run()`은 명령이 끝날 때까지의 전체 출력을 `docker-py` 안에서 하나의 `bytes` 객체로 모은 뒤에야 돌려주며, `list_dir`·`desktop_processes`·`screenshot`에는 컨테이너 안의 `head -c` 파이프도 없다.",
        "blockers": [
            "`desktop_processes`는 `pids_limit`(기본 256 / 데스크톱 1024)에 묶여 출력 크기가 수백 KiB 수준에 그친다.",
            "`screenshot`은 `DESKTOP_USER`(`desktop`)로 실행되어 에이전트(`agent`, uid 1000)가 직접 `/home/desktop/.cache`의 파일을 심볼릭 링크로 바꾸지 못한다(단, GUI 입력으로 터미널을 열어 `desktop` 권한 명령을 실행한 경우는 예외).",
            "`list_dir`로 수백 MiB의 `ls -la` 출력을 만들려면 단일 디렉터리에 수백만 개의 파일이 필요해 컨테이너 inode·시간 제한에 먼저 걸릴 가능성이 크다.",
        ],
        "plan": "실제 배포 파일시스템에서 에이전트가 제한 시간 안에 단일 디렉터리에 만들 수 있는 엔트리 수나 GUI 터미널을 통한 `/home/desktop/.cache` 조작으로 `c.exec_run` 버퍼가 컨트롤 플레인 메모리 제한(2GiB)을 위협할 수 있는지 확인한다. 코드에서는 `c.exec_run` 대신 `_Head` 기반 스트리밍 헬퍼를 공통으로 쓰면 원천 차단된다.",
        "live": "- 실제 일회용 컨테이너(`agentbox-desktop:0.1`, `--network none`)에서 2MiB 스트림을 내보낼 때 `c.exec_run(demux=True)`는 2,097,152바이트 전체를 `docker-py` 메모리에 모았고, `exec_start(stream=True, demux=True)` + `_Head()`는 65,537바이트만 남기고 잘랐다(`agents/parent-live/artifacts/readers_live.out`).",
    },
    "agentbox/service.py:disk_low-unmonitored-docker-data-root": {
        "title": "AgentBox.disk_low()가 컨트롤 플레인 데이터 폴더만 검사하고 Docker data-root(/var/lib/docker)는 보지 않으며, 기본 설정에는 컨테이너 쓰기 레이어 용량 상한(disk_limit)이 없다",
        "desc": "`AgentBox.disk_low()`(`service.py:130-137`)는 `{self.settings.home, self.settings.db_path.parent}`에 대해서만 `shutil.disk_usage(p).free < min_free_bytes`를 확인한다. 반면 컨테이너의 `/workspace` 쓰기 레이어(overlay2 `upperdir`)와 스냅샷 이미지(`c.commit`)는 Docker 데몬의 `DockerRootDir`(보통 `/var/lib/docker`)에 쌓인다. 또한 `settings.disk_limit`(`AGENTBOX_DISK`)은 overlay2가 `xfs + pquota`일 때만 동작해 기본값이 빈 문자열(`''`)이고, `write_file`·`exec`는 승인 없이 에이전트가 반복 호출할 수 있다. 만약 배포 환경에서 `settings.home`과 `/var/lib/docker`가 같은 파일시스템에 있으면 `disk_low()`가 함께 감지하지만, 별도 파티션·볼륨으로 분리되어 있으면 `disk_low()`가 전혀 감지하지 못한다.",
        "root": "`disk_low()`가 Docker `DockerRootDir` 경로를 검사 대상에 넣지 않고(컨테이너 안에서 컨트롤 플레인이 돌 때는 `/var/lib/docker`가 마운트되어 있지도 않음), 기본 설정에서 컨테이너별 `storage_opt`(`disk_limit`)가 꺼져 있다.",
        "blockers": [
            "단일 루트 파티션에 `settings.home`과 `/var/lib/docker`를 함께 두는 배포에서는 `shutil.disk_usage(settings.home).free`가 Docker 쓰기 레이어 증가도 그대로 반영한다.",
            "`/var/lib/docker`를 별도 디스크·볼륨으로 분리했는지, 또는 `xfs + pquota`와 `AGENTBOX_DISK`를 켰는지는 운영 호스트 구성에 따라 다르다.",
        ],
        "plan": "운영 호스트에서 `df -P <AGENTBOX_HOME> /var/lib/docker`로 두 경로가 같은 파일시스템인지, 또는 `AGENTBOX_DISK`가 설정되어 있는지 확인한다. 컨트롤 플레인이 컨테이너 안에서 돌면서 `/var/lib/docker`가 다른 볼륨에 있다면 호스트 측 디스크 경로를 함께 마운트해 `disk_low()`에서 확인하거나 `xfs + pquota` 기반 `AGENTBOX_DISK`를 설정한다.",
        "live": "- 실제 일회용 데스크톱 샌드박스에서 `settings.disk_limit`은 `''`(`storage_opt` 미적용), 컨테이너 `/workspace`는 `DockerRootDir=/var/lib/docker` 아래 `overlay` 마운트이며, `AgentBox.disk_low()`는 `settings.home`과 `settings.db_path.parent`만 검사함을 확인했다(`agents/parent-live/artifacts/disk_low_live.out`).",
    },
}
