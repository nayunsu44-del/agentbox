# run-6 검증 필요 항목

코드 상의 동작은 샌드박스와 일회용 Docker 컨테이너에서 확인했으나, 실제 악용 가능성과 영향이 운영 배포 구성(리버스 프록시, 파일시스템 파티션 분리, 호스트 리소스 한도)에 좌우되어 `needs_validation`으로 분류한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.

## N1. same_origin()이 Origin의 호스트:포트(netloc)만 비교하고 스킴(http vs https)은 보지 않는다

- 지문: `agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare`
- 경로: `agentbox/web.py:168`(진입점), `agentbox/api.py:235`(전파), `agentbox/api.py:223`(전파), `agentbox/web.py:171`(도달점)

**설명.** `agentbox/api.py:221-223`의 `same_origin(headers)`는 `urlsplit(origin).netloc == headers.get('host')`만 비교하고 `urlsplit(origin).scheme`은 보지 않는다. 또한 세션 쿠키의 `SameSite=Lax`(`desktop.py:21`)는 스킴을 구분하지 않는다(schemeful SameSite가 아님). 따라서 같은 호스트 이름의 평문 `http://` 출처(또는 비표준 포트 `https://host:8443`을 평문 `http://host:8443`으로 부른 경우)에서 보낸 요청도 `same_origin`을 통과한다. 다만 실제 악용 가능성은 배포 토폴로지(Caddy 리버스 프록시가 80→443 리다이렉트를 강제하는지, 비표준 포트를 직접 노출하는지, 네트워크 경로에 평문 HTTP를 가로챌 수 있는 공격자가 있는지)에 좌우된다.

**주장하는 근본 원인.** `same_origin(headers)`가 `Request`의 유효 스킴(또는 `X-Forwarded-Proto`)과 `urlsplit(origin).scheme`을 비교하지 않고 `netloc`만 비교한다.

**막힌 지점.**

- 동봉된 기본 배포(`deploy/Caddyfile`)는 80 포트를 HTTPS로 리다이렉트하고 443에서 TLS를 종료하므로, 같은 `host:port`에서 평문 HTTP 응답을 받을 수 없다.
- 비표준 포트에서 HTTPS를 직접 띄우거나 리버스 프록시 없이 평문 HTTP를 함께 열어 두는지는 운영 배포 설정에 달려 있다.

**검증 계획.** 배포 환경에서 (1) TLS가 비표준 포트에 직접 바인딩되는지, (2) 같은 호스트의 평문 80 포트가 리다이렉트 없이 열려 있거나 네트워크 상에서 가로채기 가능한지 확인한다. 코드 수준에서는 `secure_cookie(request)`가 참일 때 `urlsplit(origin).scheme == 'https'`까지 함께 요구하면 배포 가정과 무관하게 닫힌다.

**부모 실측 (일회용 컨테이너, 에이전트 예산 밖).**

- `TestClient(app, base_url='https://box.example.com')`와 `https://box.example.com:8443`에서 세션 쿠키를 싣고 `Origin: http://box.example.com` 및 `Origin: http://box.example.com:8443`으로 `GET /ui/verify`를 호출하면 모두 `200 OK`가 난다(`agents/parent-live/artifacts/same_origin_live.out`). 다른 호스트(`Origin: https://evil.example.com`)는 `403`으로 막힌다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** same_origin compares only the netloc of the Origin header with the Host header and accepts missing Origin headers. When agentbox is deployed behind a TLS-terminating reverse proxy (such as Caddy) without HSTS, or on a host with co-located HTTP services, requests originating from an insecure http:// scheme on the same host match the netloc check and can perform state-changing operations (such as session termination via /logout or approval decisions via /ui/approvals) using the browser's session cookie.

**claimed_root_cause** agentbox/api.py:221-223: same_origin() returns True when urlsplit(origin).netloc == headers.get('host') or when Origin is absent. The closure receives only headers and does not verify whether the Origin scheme matches the request scheme (e.g., https). deploy/Caddyfile:1-17 does not set Strict-Transport-Security, so plain-HTTP contexts on the same host are not upgraded to HTTPS by the browser.

**trace**

- `agentbox/web.py:168` (entrypoint, logout) — Cookie-authenticated POST /logout (or /ui/approvals/{aid}/{decision} at web.py:242) is received from a browser context without anti-CSRF tokens or Sec-Fetch validation.
- `agentbox/api.py:235` (propagation, screen_principal) — Browser routes validate request authenticity using same_origin(request.headers) after resolving the session cookie; /logout invokes same_origin directly at web.py:169.
- `agentbox/api.py:223` (propagation, same_origin) — urlsplit(origin).netloc == headers.get('host') ignores the origin scheme (http vs https) and accepts missing Origin headers, allowing plaintext http:// origins to pass origin validation.
- `agentbox/web.py:171` (sink, logout) — With same_origin evaluated to True, box.end_ui_session terminates the authenticated session (or r.delete_cookie at line 175 forces browser session clearance; on /ui/approvals at line 248 box.decide executes human approval).

**blockers**

- Browser behavior (decisive): whether real-world browsers used by operators (Safari, Firefox, Chrome, and embedded WebViews) strictly enforce Schemeful Same-Site policy (RFC 6265bis) to withhold 'SameSite=Strict; Secure' cookies on cross-scheme (http:// to https://) requests against the same domain. In sandboxed test environments, headless execution cannot observe browser-level cookie attachment policies.
- Network position and TLS termination: whether plaintext http:// traffic on the same host can be reached by an operator or injected by an on-path attacker. deploy/Caddyfile lacks Strict-Transport-Security (HSTS), but whether the production deployment uses upstream HSTS, CDN preloading, or an external load balancer is an operator-controlled environment fact.

**validation_plan.local** Deploy agentbox behind a local TLS reverse proxy on https://localhost with a valid test certificate and an authenticated browser session. In multiple real-world browsers (Safari, Firefox, Chromium), open a page served from http://localhost and trigger form POSTs to /logout and /ui/approvals/{aid}/approve. Record whether each browser attaches the 'agentbox_session' cookie on the cross-scheme POST, whether status 303/200 is returned, and whether the server session or approval mutation executes.

**validation_plan.deployment** Operator confirms: (1) whether the production domain sends Strict-Transport-Security (HSTS) with includeSubDomains or is on the HSTS preload list; (2) whether plaintext HTTP port 80 is accessible or unconditionally redirected to HTTPS; (3) the specific browser engines and versions used by operators accessing the admin UI.


</details>

## N2. exec 외의 컨테이너 출력 판독기들이 docker-py의 스트리밍 상한(_Head) 없이 c.exec_run()으로 전체 출력을 메모리에 먼저 받는다

- 지문: `agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap`
- 경로: `agentbox/api.py:306`(진입점), `agentbox/service.py:293`(전파), `agentbox/service.py:136`(전파), `agentbox/sandbox.py:442`(전파), `agentbox/sandbox.py:116`(도달점)

**설명.** `SandboxManager.exec`(`sandbox.py:427-430`)은 `api.exec_start(..., stream=True, demux=True)`와 `_Head()`로 스트림을 읽으면서 64KiB까지만 메모리에 남긴다. 반면 다른 컨테이너 판독기들(`workspace_manifest`, `_expand`, `_walk`, `read_file`, `list_dir`, `screenshot`, `desktop_processes`)은 `c.exec_run(..., demux=True)`를 부른 뒤 파이썬으로 돌아온 전체 바이트열에 `_truncate`를 적용한다. 그중 `workspace_manifest`, `_expand`, `_walk`, `read_file`은 컨테이너 안의 `head -c`로 바이트 상한이 걸려 있지만, `list_dir`(`ls -la`), `desktop_processes`(`ps -eo ...`), `screenshot`(`cat /home/desktop/.cache/agentbox-shot.png`)에는 컨테이너 쪽 `head -c`나 호스트 쪽 `_Head()` 스트림 상한이 없다.

**주장하는 근본 원인.** `c.exec_run()`은 명령이 끝날 때까지의 전체 출력을 `docker-py` 안에서 하나의 `bytes` 객체로 모은 뒤에야 돌려주며, `list_dir`·`desktop_processes`·`screenshot`에는 컨테이너 안의 `head -c` 파이프도 없다.

**막힌 지점.**

- `desktop_processes`는 `pids_limit`(기본 256 / 데스크톱 1024)에 묶여 출력 크기가 수백 KiB 수준에 그친다.
- `screenshot`은 `DESKTOP_USER`(`desktop`)로 실행되어 에이전트(`agent`, uid 1000)가 직접 `/home/desktop/.cache`의 파일을 심볼릭 링크로 바꾸지 못한다(단, GUI 입력으로 터미널을 열어 `desktop` 권한 명령을 실행한 경우는 예외).
- `list_dir`로 수백 MiB의 `ls -la` 출력을 만들려면 단일 디렉터리에 수백만 개의 파일이 필요해 컨테이너 inode·시간 제한에 먼저 걸릴 가능성이 크다.

**검증 계획.** 실제 배포 파일시스템에서 에이전트가 제한 시간 안에 단일 디렉터리에 만들 수 있는 엔트리 수나 GUI 터미널을 통한 `/home/desktop/.cache` 조작으로 `c.exec_run` 버퍼가 컨트롤 플레인 메모리 제한(2GiB)을 위협할 수 있는지 확인한다. 코드에서는 `c.exec_run` 대신 `_Head` 기반 스트리밍 헬퍼를 공통으로 쓰면 원천 차단된다.

**부모 실측 (일회용 컨테이너, 에이전트 예산 밖).**

- 실제 일회용 컨테이너(`agentbox-desktop:0.1`, `--network none`)에서 2MiB 스트림을 내보낼 때 `c.exec_run(demux=True)`는 2,097,152바이트 전체를 `docker-py` 메모리에 모았고, `exec_start(stream=True, demux=True)` + `_Head()`는 65,537바이트만 남기고 잘랐다(`agents/parent-live/artifacts/readers_live.out`).

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** Four control-plane readers take container-produced output through non-streaming c.exec_run without streaming byte caps or container-side timeouts: SandboxManager.list_dir (sandbox.py:442) runs ls -la with no container-side timeout or byte cap, where _truncate (sandbox.py:446) reduces the string only after the entire output is buffered in control-plane RAM; SandboxManager.outbox_list (sandbox.py:548) runs find -printf with no _timed wrapper or head cap, passing raw output to _parse_outbox (sandbox.py:116) which instantiates unbounded lists of dicts (demonstrating an 11-12x memory retention amplification); SandboxManager._expand (sandbox.py:578) runs a container glob loop with a 10s timeout (_PREVIEW_TIMEOUT) but no head -z cap (unlike _walk at sandbox.py:586 which caps output with head -z -n "$2"), buffering all matched filenames into Python strings; and DesktopTools.screenshot (sandbox_desktop.py:114) cats the entire PNG into memory before checking the PNG magic. In contrast, exec (sandbox.py:427) streams output through _Head (capping memory to 64 KiB) and uses _timed(kill_after=5), read_file and outbox_read (sandbox.py:454, 557) enforce head -c and _timed(_READ_TIMEOUT), and workspace_manifest (sandbox.py:384) enforces head -c and _timed(_MANIFEST_TIMEOUT). Parent-live execution on a real Docker container confirmed that exec_run buffers an entire 2 MiB stream in memory before _truncate, whereas exec_start with _Head keeps only 65,537 bytes. However, demonstrating full control-plane memory exhaustion (OOM kill) or threadpool starvation requires large-scale real container execution and depends on deployment topology.

**claimed_root_cause** Container output consumption disciplines were applied inconsistently across SandboxManager and DesktopTools readers: exec uses _Head streaming (_OUT_LIMIT=64 KiB) with _timed(t, kill_after=5); read_file and outbox_read use head -c with _timed(_READ_TIMEOUT); workspace_manifest uses head -c with _timed(_MANIFEST_TIMEOUT); and preview _walk uses head -z with _timed(_PREVIEW_TIMEOUT). However, list_dir and outbox_list use plain c.exec_run without _timed timeouts or stream-limiting byte caps, buffering arbitrary output in control-plane memory before post-read truncation. Furthermore, preview _expand uses _timed(_PREVIEW_TIMEOUT) but omits a head -z record cap, decoding unbounded container paths into Python strings, and screenshot cats full images into control-plane RAM before verifying PNG magic.

**trace**

- `agentbox/api.py:306` (entrypoint, call_tool (POST /sandboxes/{sid}/tools/{tool})) — Agent token invokes list_dir or triggers approval preview via exec on an agent-populated directory (or human calls GET /sandboxes/{sid}/outbox at api.py:385).
- `agentbox/service.py:293` (propagation, AgentBox.call_tool) — Routes tool request on the shared tool_pool thread without request-level byte or memory limits.
- `agentbox/service.py:136` (propagation, AgentBox._run_tool) — Dispatches list_dir to SandboxManager.list_dir (or _preview to preview_command at service.py:354).
- `agentbox/sandbox.py:442` (propagation, SandboxManager.list_dir) — Invokes c.exec_run(["ls", "-la", "--", p], demux=True) with no container-side _timed wrapper and no stream byte cap, buffering all container output in control-plane memory before _truncate at line 446.
- `agentbox/sandbox.py:116` (sink, _parse_outbox) — In outbox listings (sandbox.py:548), parses uncurbed find output into lists of Python dicts with ~11-12x memory amplification, risking memory exhaustion in the control-plane container.

**blockers**

- Demonstrating full control-plane memory exhaustion (OOM kill) or worker threadpool starvation under large-scale container output requires running against a live Docker daemon with a real container, which is excluded from the subagent sandbox environment.
- Whether peak memory from large listings causes fatal service failure depends on deployment configuration and host topology: compose sets mem_limit: 2g, AGENTBOX_DISK is unset by default (allowing unconstrained container filesystem growth up to host disk limits), and host cgroup behavior is environment-specific.

**validation_plan.local** On a host running Docker with AGENTBOX_DISK=2g: (1) create a sandbox container, (2) populate /workspace/outbox with 200,000 files using a fast shell loop, (3) record VmHWM from /proc/<pid>/status of the control-plane process, call GET /sandboxes/{sid}/outbox and POST /sandboxes/{sid}/tools/list_dir with path /workspace/outbox, (4) record VmHWM again to measure memory retention from unbuffered exec_run and _parse_outbox, comparing with capped exec (ls -la /workspace); (5) test replacing outbox with a FIFO or slow character pipe to observe whether tool_pool and HTTP worker threads hang.

**validation_plan.deployment** Deploy agentbox with docker compose (mem_limit: 2g). Generate directories with hundreds of thousands of files across several sandboxes, trigger simultaneous list_dir and outbox listings, and observe container RSS, cgroup memory limits, and whether OOM kills terminate the control plane or in-flight approval workflows.


</details>

## N3. AgentBox.disk_low()가 컨트롤 플레인 데이터 폴더만 검사하고 Docker data-root(/var/lib/docker)는 보지 않으며, 기본 설정에는 컨테이너 쓰기 레이어 용량 상한(disk_limit)이 없다

- 지문: `agentbox/service.py:disk_low-unmonitored-docker-data-root`
- 경로: `agentbox/service.py:296`(진입점), `agentbox/service.py:428`(전파), `agentbox/sandbox.py:361`(전파), `agentbox/sandbox.py:269`(도달점)

**설명.** `AgentBox.disk_low()`(`service.py:130-137`)는 `{self.settings.home, self.settings.db_path.parent}`에 대해서만 `shutil.disk_usage(p).free < min_free_bytes`를 확인한다. 반면 컨테이너의 `/workspace` 쓰기 레이어(overlay2 `upperdir`)와 스냅샷 이미지(`c.commit`)는 Docker 데몬의 `DockerRootDir`(보통 `/var/lib/docker`)에 쌓인다. 또한 `settings.disk_limit`(`AGENTBOX_DISK`)은 overlay2가 `xfs + pquota`일 때만 동작해 기본값이 빈 문자열(`''`)이고, `write_file`·`exec`는 승인 없이 에이전트가 반복 호출할 수 있다. 만약 배포 환경에서 `settings.home`과 `/var/lib/docker`가 같은 파일시스템에 있으면 `disk_low()`가 함께 감지하지만, 별도 파티션·볼륨으로 분리되어 있으면 `disk_low()`가 전혀 감지하지 못한다.

**주장하는 근본 원인.** `disk_low()`가 Docker `DockerRootDir` 경로를 검사 대상에 넣지 않고(컨테이너 안에서 컨트롤 플레인이 돌 때는 `/var/lib/docker`가 마운트되어 있지도 않음), 기본 설정에서 컨테이너별 `storage_opt`(`disk_limit`)가 꺼져 있다.

**막힌 지점.**

- 단일 루트 파티션에 `settings.home`과 `/var/lib/docker`를 함께 두는 배포에서는 `shutil.disk_usage(settings.home).free`가 Docker 쓰기 레이어 증가도 그대로 반영한다.
- `/var/lib/docker`를 별도 디스크·볼륨으로 분리했는지, 또는 `xfs + pquota`와 `AGENTBOX_DISK`를 켰는지는 운영 호스트 구성에 따라 다르다.

**검증 계획.** 운영 호스트에서 `df -P <AGENTBOX_HOME> /var/lib/docker`로 두 경로가 같은 파일시스템인지, 또는 `AGENTBOX_DISK`가 설정되어 있는지 확인한다. 컨트롤 플레인이 컨테이너 안에서 돌면서 `/var/lib/docker`가 다른 볼륨에 있다면 호스트 측 디스크 경로를 함께 마운트해 `disk_low()`에서 확인하거나 `xfs + pquota` 기반 `AGENTBOX_DISK`를 설정한다.

**부모 실측 (일회용 컨테이너, 에이전트 예산 밖).**

- 실제 일회용 데스크톱 샌드박스에서 `settings.disk_limit`은 `''`(`storage_opt` 미적용), 컨테이너 `/workspace`는 `DockerRootDir=/var/lib/docker` 아래 `overlay` 마운트이며, `AgentBox.disk_low()`는 `settings.home`과 `settings.db_path.parent`만 검사함을 확인했다(`agents/parent-live/artifacts/disk_low_live.out`).

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** AgentBox.disk_low checks free disk space strictly via shutil.disk_usage(self.settings.db_path.parent). In deployments where the agentbox database volume (AGENTBOX_HOME) and Docker's data root (/var/lib/docker) reside on separate filesystems, container layer growth and docker commit snapshot images (up to 50 per sandbox) consume Docker storage without decreasing free space on db_path.parent. The 507 guard never trips, allowing agents to exhaust host Docker disk, cause daemon failures, and prevent administrative log_human operations which fail closed with 503.

**claimed_root_cause** The disk guard in AgentBox.disk_low (service.py:421-437) assumes all disk growth occurs on the filesystem containing db_path.parent. However, Docker container writable layers and commit images (sandbox.py:356-370) grow inside Docker's data root (e.g. /var/lib/docker). In deploy/docker-compose.yml, AGENTBOX_HOME (/var/lib/agentbox) is a separate bind mount. When db_path.parent and Docker data root are on distinct partitions, or when an admitted exec runs dd/fallocate for up to exec_timeout (since AGENTBOX_DISK is empty by default so containers have no storage_opt size quota), host Docker storage can be completely filled without triggering disk_low.

**trace**

- `agentbox/service.py:296` (entrypoint, AgentBox.call_tool) — Agent calls an admitted tool (e.g. exec writing large files to /workspace, or write_file triggering snapshot).
- `agentbox/service.py:428` (propagation, AgentBox.disk_low) — disk_low evaluates shutil.disk_usage(s.db_path.parent).free against s.min_free_bytes; because Docker storage is on a separate filesystem, db_path.parent free space remains high and disk_low returns False.
- `agentbox/sandbox.py:361` (propagation, SandboxManager.snapshot) — c.commit commits container writable layer into a new Docker image in Docker data root, accumulating up to snapshot_quota (50) images per sandbox.
- `agentbox/sandbox.py:269` (sink, SandboxManager._run_container) — Container has no storage_opt disk quota (disk_limit is empty by default), allowing unrestricted accumulation of data in Docker's storage root until the host filesystem is exhausted.

**blockers**

- Simulating separate filesystem mounts for AGENTBOX_HOME and Docker root (/var/lib/docker) along with live docker commit image accumulation requires access to a host Docker daemon and multiple mount points, which is unavailable in the isolated sandbox.
- Exhausting host Docker disk on live test infrastructure is destructive and forbidden under audit execution boundaries; confirming complete host exhaustion requires an operator-owned multi-volume test deployment.

**validation_plan.local** On a dedicated non-production host running Docker with AGENTBOX_HOME on a loopback mount or separate partition from /var/lib/docker: (1) configure min_free_bytes=256MB, (2) run an agent script that creates files in /workspace and triggers snapshots up to snapshot_quota, (3) verify that disk_low continues returning False while Docker data root disk usage increases until /var/lib/docker is exhausted.

**validation_plan.deployment** Check host partition layout in production deployments to verify whether /var/lib/docker and AGENTBOX_HOME are on separate volumes, and monitor Docker daemon root volume free space independently of the application database volume.


</details>
