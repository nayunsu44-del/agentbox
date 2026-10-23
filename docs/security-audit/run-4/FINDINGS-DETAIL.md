# 확정 findings 상세 (run-4)

기준 커밋 `9805d91`. 아래는 `findings.json`의 `confirmed` 레코드를 그대로 옮긴 것이다.

## F1. Unauthenticated request bodies are fully read, JSON-decoded and multipart-spooled before the principal dependency rejects the request

- 지문: `agentbox/api.py:preauth-request-body-read-before-principal`
- 심각도: **중간** (가능성 높음, 영향 중간)
- 신뢰도: high
- 관련 경로: `agentbox/api.py`

**설명.** agentbox's body routes declare a request-body model - or a File(...) list - together with Depends(principal) / human_only / screen_human (agentbox/api.py:175, 206, 216, 251, 277). In FastAPI's request handler the body is read and JSON-decoded - and on the upload route streamed through request.form() and spooled - before solve_dependencies resolves any of those dependencies, so an unauthenticated client decides how many bytes the control plane buffers, decodes and writes to TMPDIR before it is told 401. Nothing in the tree bounds that work: the only middleware is _NoFraming (api.py:63-80, registered at 113), the serve entry point passes no request-size or concurrency limit to uvicorn (agentbox/cli.py:127), and the shipped Caddy front end has no request_body directive (deploy/Caddyfile:5). The caps that do exist - max_upload_bytes per file (config.py:57, enforced inside the endpoint at api.py:278-283) and LOGGED_ARGS_MAX (service.py:37-38) - run only after a principal exists. Starlette's multipart parser bounds part cardinality (1000 files/fields) and 1 MiB for non-file fields, but not file-part bytes.

**근본 원인.** Authentication dependencies run after FastAPI's body-parsing stage, and nothing in front of the app - ASGI middleware, uvicorn options, or the bundled Caddy reverse proxy - enforces a maximum request-body size, so unauthenticated work scales with the attacker's body size instead of with the negligible work needed to reject an unauthenticated request.

**의도된 동작.** Requests that cannot yet be authenticated should be rejected before their body is buffered, decoded or written to disk, and bodies above a documented cap should be refused with 413 regardless of credential state.

**전파 경로.**
- `agentbox/api.py:174` (entrypoint, POST /sandboxes, and every sibling body route: /sandboxes/{sid}/restore (205-206), /sandboxes/{sid}/tools/{tool} (215-216), /approvals/{aid} (250-251), /sandboxes/{sid}/files (276-277)) — A lower-trust network client with no token reaches a route that declares both a body (CreateSandbox) and Depends(human_only). Declaring the body is what makes FastAPI's handler stage read and JSON-decode the whole request body before any dependency is solved (verified in the installed fastapi 0.161.1 get_request_handler source: body read/decode block precedes the solve_dependencies call).
- `agentbox/api.py:115` (propagation, principal() - first credential check for the JSON API; human_only and screen_human build on it) — principal() compare_digest's the bearer token (119), looks up an agent token (121) and raises 401 at 117/124. It runs only after the body stage, so no principal exists while the body is buffered and decoded.
- `agentbox/api.py:277` (propagation, POST /sandboxes/{sid}/files multipart body) — files: list[UploadFile] = File(...) makes the handler call request.form() before screen_human runs; Starlette streams the whole multipart body and rolls every file part past the 1 MiB spool threshold into a SpooledTemporaryFile under the control plane's TMPDIR.
- `agentbox/api.py:278` (propagation, per-file cap applied after parsing and after authentication) — limit = settings.max_upload_bytes with await f.read(limit + 1) at 281-283 executes only inside the endpoint, i.e. after the whole body has been spooled and only when a principal was already accepted, so it cannot bound pre-auth work.
- `agentbox/api.py:113` (sink, the only middleware installed on the app (no body-size gate on the way into FastAPI's body stage)) — _NoFraming is the last app-owned code a request passes, and it only appends response headers. With cli.py:127 and deploy/Caddyfile:5 adding no limit either, the attacker-chosen body becomes control-plane heap and temp-disk state before principal()/screen_human can reject it.

**재현과 관측 결과.**

- 공격자 관점: An unauthenticated network client that never holds a token sends bodies of its choosing to routes it knows will answer 401, or to the upload route, and lets the control plane read, decode and spool them. The attacker's spend is the bytes it uploads, while the server retains about twice that in heap per in-flight body (measured), with no per-request and no concurrency bound in the shipped configuration.
- 관측: Installed stack: fastapi 0.161.1, starlette 1.9.0, uvicorn 0.54.0. POST /sandboxes with a 16,777,216-byte JSON body and no Authorization returned 401, but the app had consumed all 16,777,216 bytes before emitting http.response.start and Request.json() had decoded 16,777,216 bytes; peak RSS grew 32,768 KiB (2.0x the body). /sandboxes/{sid}/tools/exec, /sandboxes/{sid}/restore and /approvals/{aid} behaved identically with 4,194,304-byte bodies - all bytes consumed and decoded before the 401. POST /sandboxes/{sid}/files with one 4,194,304-byte part and no cookie returned 401 after consuming all 4,194,442 bytes; at that moment the SpooledTemporaryFile (max_size 1,048,576) had rolled to a real temporary file holding 4,194,184 bytes in TMPDIR, the endpoint's 50 MiB per-file cap never ran, and the temporary file was removed when the form closed (no residue afterwards). A control GET /healthz returned 200 with 0 body bytes consumed. The installed multipart parser carries max_files/max_fields = 1000 and max_part_size = 1 MiB, but max_part_size is applied only to non-file fields, so a 4 MiB file part passed untouched.

**조건.**
- authentication_level: None: no Authorization header and no session cookie are required for the buffering; every tested path returned 401 only after the body had been consumed.
- network_routing: The client can reach the control plane through the shipped Caddy front end (compose publishes 443/80 and forwards bodies without a size directive), or directly when agentbox serve is used.
- environmental_dependency: Impact scales with the memory and TMPDIR of the single uvicorn process that also serves the human approval queue and the audit chain; the compose service sets no mem_limit, so exhausting the process takes the approval path down with it (pending approvals, 300 s default, age toward timeout while the operator restarts).

**수정 방향.** Reject oversized bodies before FastAPI's body stage and before any authentication work: install an ASGI middleware beside _NoFraming that answers 413 when the declared Content-Length already exceeds the cap and counts streamed bytes for chunked bodies, aborting at the cap; keep the application/JSON cap above the largest legitimate body (write_file content is bounded by max_write_bytes = 1 MiB, so a 64 KiB JSON cap would break authenticated tool calls) and give the multipart route an aggregate body cap from a new setting (default e.g. 64 MiB for the whole request, not per file); and add request_body { max_size ... } to deploy/Caddyfile so the shipped proxy refuses the same oversized bodies before they reach the process.

`python` // agentbox/api.py
```python
# from starlette.requests import ClientDisconnect

class _BodyLimit:
    """FastAPI가 본문을 읽기 전에 크기 상한을 강제한다 (인증 전, 보안 검수 run-4 v01)."""

    def __init__(self, app, json_max: int, upload_max: int):
        self.app, self.json_max, self.upload_max = app, json_max, upload_max

    def _cap(self, scope) -> int:
        return self.upload_max if scope.get("path", "").endswith("/files") else self.json_max

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cap = self._cap(scope)
        declared = None
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
        if declared is not None and declared > cap:
            return await Response("요청 본문이 너무 큼", status_code=413)(scope, receive, send)
        seen = 0

        async def limited():
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > cap:
                raise ClientDisconnect()   # 스트리밍 본문이 상한을 넘으면 연결을 끊는다
            return message

        return await self.app(scope, limited, send)

    # _NoFraming 등록 옆에:
    app.add_middleware(_BodyLimit, json_max=settings.max_body_bytes,
                       upload_max=settings.max_upload_body_bytes)
```

`python` // agentbox/config.py
```python
    # FastAPI가 본문을 읽기 전에 거부할 요청 본문 상한. write_file 인자(max_write_bytes)보다 커야 한다.
    max_body_bytes: int = field(default_factory=lambda: int(_env("AGENTBOX_MAX_BODY", str(4 * 1024 * 1024))))
    # 업로드 경로의 요청 전체 상한 (파일 하나가 아니라 한 요청)
    max_upload_body_bytes: int = field(
        default_factory=lambda: int(_env("AGENTBOX_MAX_UPLOAD_BODY", str(64 * 1024 * 1024))))
```

`python` // deploy/Caddyfile
```python
{$AGENTBOX_SITE} {
	request_body {
		max_size 64MB
	}
	reverse_proxy agentbox:8765
}
```

## F2. Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent)

- 지문: `agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets`
- 심각도: **낮음** (가능성 중간, 영향 낮음)
- 신뢰도: high
- 관련 경로: `agentbox/api.py`, `agentbox/preview.py`, `agentbox/sandbox.py`, `agentbox/service.py`

**설명.** For a gated exec the "system-computed impact" table is produced by SandboxManager._expand / _walk and preview_command. _expand hands the already-unquoted rm operand to sh as $1 and iterates over $1 unquoted, so the operand is word-split on IFS and each fragment is pathname-expanded before the [ -e ] existence test; results are newline-framed and re-split in Python, and _walk frames find output the same way. preview_command turns an empty match list into "삭제 시도 (현재 존재하지 않음)" and every returned line into a "삭제" row. The rm itself later runs through bash -c with the original quoting, so the computed path set and the executed path set differ: an agent whose workspace target contains a space obtains approval for a deletion the card describes as an apparent no-op, or for a card that lists unrelated decoy files, while the real file is deleted. Reproduced with the verbatim scripts: the card for a lone rm of an existing "final report.docx" showed exactly one row, "삭제 시도 (현재 존재하지 않음)", and no note.

**근본 원인.** The preview path transport is not a lossless representation of a filesystem path. sandbox.py:559 iterates $1 unquoted under the default IFS, so an operand that shlex already unquoted (preview.py:33-44) is re-split into words and each word is expanded again before the existence test; matches are framed with printf "%s\n" and re-split by splitlines() (sandbox.py:562), and _walk's find | head output is split the same way (sandbox.py:565-569). preview.py:90-91 maps an empty expansion to the "does not currently exist" row and preview.py:96-98 maps each returned line to a deletion row, so a split operand both hides the real target and can manufacture paths the command will never touch. The executed command keeps its quoting (sandbox.py:411), so the card and the effect diverge.

**의도된 동작.** The affected list shown beside the approval must name exactly the paths the stored command will act on, so approving the card is equivalent to approving the effect: a path that exists must never be reported as nonexistent, and a path must never be listed as deleted unless the command deletes it.

**전파 경로.**
- `agentbox/api.py:215` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — The agent posts tool=exec with body.args.command under its own sandbox token.
- `agentbox/service.py:318` (propagation, AgentBox._call_tool) — For a REQUIRE_APPROVAL decision (default_policy.yaml:12-16 routes rm to require_approval) the preview is computed while the approval is created, before any human sees it.
- `agentbox/service.py:215` (propagation, AgentBox._preview) — exec previews delegate to SandboxManager.preview with the raw command string.
- `agentbox/sandbox.py:573` (propagation, SandboxManager.preview) — preview_command runs with expand=_expand and walk=_walk bound to the running container.
- `agentbox/preview.py:89` (propagation, preview_command rm branch) — Each rm operand (quotes already consumed by _split_segments, preview.py:33-44) is expanded once through the container callback.
- `agentbox/sandbox.py:559` (propagation, SandboxManager._expand) — The operand is passed as $1 and iterated unquoted, so the shell word-splits it on IFS and globs the fragments before [ -e "$p" ]; the surviving words are what get tested.
- `agentbox/sandbox.py:562` (propagation, SandboxManager._expand return) — Matches are framed one per line and re-split with splitlines(), so a name containing a newline arrives as two or more fake paths.
- `agentbox/preview.py:90` (propagation, preview_command affected rows) — An empty expansion becomes the "삭제 시도 (현재 존재하지 않음)" row and each returned line becomes a deletion row; the result is stored with the approval and rendered as the system-computed impact.
- `agentbox/sandbox.py:411` (sink, SandboxManager.exec after approval) — After the human approves, decide() snapshots (service.py:412) and _run_tool passes the stored command unchanged (service.py:126) to exec, which runs it verbatim through bash -c; the quoting is intact there, so the file the table called nonexistent is actually deleted.

**재현과 관측 결과.**

- 공격자 관점: The sandbox agent wants to delete /workspace/final report.docx but wants the card not to say so, so it submits exec rm "final report.docx". The card describes the target as "삭제 시도 (현재 존재하지 않음)" - an apparently already-failed no-op - and with decoy names present it lists files that will not be touched, while the approved command deletes the real file.
- 관측: Case B: affected=[{path: "final report.docx", effect: "삭제 시도 (현재 존재하지 않음)"}], notes=[], real target exists: true. Case C (decoys present): affected=[{path: "final", effect: "삭제"}, {path: "report.docx", effect: "삭제"}] while the real target still exists and is never listed. Newline case: expand("*") -> ["a", "b", "ok.txt"] for files "a\nb" and ok.txt, and the old find framing returned ["dir with space", "dir with space/inner", "name.txt"]. Sink: sh -c 'rm "final report.docx"' exited 0 and the directory went from [final report.docx, notes.txt] to [notes.txt]. Case A (revalidation): "rm notes.txt; mv important /tmp/important" produced the rm row AND the per-segment note, so the run-3 omission defect is fixed. The proposed fix was also executed against the same fixtures: with IFS= and NUL framing expand returned ["final report.docx"] and a single "a\nb", and find -print0 | head -z kept "dir with space/inner\nname.txt" whole. Everything ran inside tools/sbx.py v06.

**조건.**
- authentication_level: A sandbox agent token (or prompt-injected code running as uid 1000 inside that sandbox) submits the rm; the default policy routes rm to require_approval, so the approval card is the only control between it and the deletion.
- user_interaction: A human opens the pending approval in the /ui/approvals card or agentbox approve and presses approve, relying on the system-computed impact table rather than re-reading the raw command.
- data_state: The rm operand names an existing /workspace path containing whitespace (space or tab) or a newline; the agent can produce that state itself, since creating a new file with write_file needs no approval.
- system_configuration: Stock default_policy.yaml, where exec commands containing rm route to require_approval (default_policy.yaml:12-16).

**수정 방향.** Make both preview transports lossless. In _expand, disable IFS word splitting (IFS=) so the operand is tested as one word while pathname expansion still happens, and frame results with NUL instead of newline; in _walk, use find -print0 with head -z and split on NUL. Then one match is one path: the "does not currently exist" row is emitted only when the path really is absent, and no row names a path the command will not touch. Add a regression test that pushes names containing a space, a tab and a newline through both the non-recursive and the recursive branch and asserts the returned list equals the fixture paths.

`python` // agentbox/sandbox.py
```python
def _expand(self, c, pattern: str) -> list[str]:
    """컨테이너 안에서 glob만 펼친다. 명령 치환은 일어나지 않는다."""
    script = ('cd /workspace; IFS=; for p in $1; do if [ -e "$p" ] || [ -L "$p" ]; then printf "%s\\0" "$p"; fi; done')
    res = c.exec_run(["sh", "-c", script, "_", pattern], user=AGENT_UID, demux=True)
    out = (res.output[0] or b"").decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]
```

`python` // agentbox/sandbox.py
```python
def _walk(self, c, path: str, limit: int) -> list[str]:
    res = c.exec_run(["sh", "-c", 'cd /workspace; case "$1" in -*) set -- "./$1" "$2";; esac; find "$1" -print0 2>/dev/null | head -z -n "$2"',
                      "_", path, str(limit)],
                     user=AGENT_UID, demux=True)
    out = (res.output[0] or b"").decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]
```

## F3. Unauthenticated GET /static/novnc/* runs docker create plus a full /usr/share/novnc tar extraction on every request while home/novnc/core/rfb.js is absent, with no single-flight

- 지문: `agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight`
- 심각도: **낮음** (가능성 중간, 영향 낮음)
- 신뢰도: high
- 관련 경로: `agentbox/api.py`, `agentbox/sandbox_desktop.py`

**설명.** api.py:355-356 registers GET /static/novnc/{path:path} with no Depends(), principal, cookie or ticket and calls box.sandboxes.extract_novnc(novnc_dir) at api.py:358 before it resolves or validates the requested path. extract_novnc (sandbox_desktop.py:146-169) has one guard: it returns True when dest/core/rfb.js exists (148). While that marker is absent, every request runs self.client.containers.create(desktop_image, ["true"], network_mode="none") (152), joins the whole /usr/share/novnc archive into memory with b"".join(stream) (156-157), extractall()s it into the control plane's data directory (163-166) and removes the container (160-161). There is no lock, no in-flight marker and no negative cache, so every concurrent caller passes the line-148 check and duplicates the daemon work: measured in the approved sandbox with the Docker client stubbed, six concurrent unauthenticated GETs made six containers.create calls, and twelve concurrent GETs made twelve. The claimed concurrent 500/FileExistsError outcome is fixture-dependent rather than universal: it reproduces (1 x 200, 5 x 500 FileExistsError on '<home>/novnc/core') only when the served tar has no directory members, because tarfile's own os.makedirs(upperdirs) in _extract_member is unguarded; with a directory-complete archive of the kind containers.get_archive('/usr/share/novnc') produces, all six and all twelve concurrent requests returned 200 while still performing six and twelve creates. Failures are still uncaught and unbounded in time: a truncated or corrupt archive raised ReadError outside the narrow ImageNotFound/NotFound/APIError handlers, producing 500 on every request, three creates for three requests and a marker that never appears, and the route also pays the create before it answers 404 (three unauth GETs for /static/novnc/does-not-exist.js each made one create). Once one extraction succeeds the marker makes later requests cheap, so the duplication is confined to the pre-marker window and to broken states.

**근본 원인.** An unauthenticated static-asset route performs Docker-daemon work and an archive extraction behind a check-then-act test on a single marker file, with no lock, no in-flight flag and no negative cache; exceptions outside the narrow docker-error handlers escape as a 500 without publishing the marker or any bounded negative state, so the expensive state persists and the work is repeatable by any anonymous client.

**의도된 동작.** Static assets should not require per-request daemon work: the extraction should happen once (at startup or on the first authenticated desktop route) under a lock that lets one caller do it while the others wait or observe the result, and a failed extraction should leave a bounded negative state instead of being retried by every request. /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.

**전파 경로.**
- `agentbox/api.py:355` (entrypoint, GET /static/novnc/{path:path}) — The route decorator adds no Depends() and the handler at 356 takes only the path, so it is exempt from the human, desktop-link and agent principals used everywhere else and is reachable by any network client; deploy/Caddyfile:4-5 exposes it through a bare reverse_proxy with no auth, rate limit or body limit.
- `agentbox/api.py:358` (propagation, extract_novnc called on every request) — The handler calls box.sandboxes.extract_novnc(novnc_dir) before resolving or validating path (360-362), so the only thing that keeps a request cheap is the marker file the function itself is supposed to create.
- `agentbox/sandbox_desktop.py:148` (propagation, the sole guard is a marker-file existence check) — if (dest / "core" / "rfb.js").exists(): return True - a check-then-act test performed outside any lock, with no in-flight marker and no negative cache, so N concurrent callers all proceed to the sink.
- `agentbox/sandbox_desktop.py:152` (sink, containers.create + get_archive + extractall) — Each request that finds no marker creates a container from the desktop image (152), pulls the whole /usr/share/novnc tar into memory with b"".join(stream) (156-157), extracts it into settings.home (162-166) and removes the container (161).

**재현과 관측 결과.**

- 공격자 관점: An unauthenticated client issues GETs to /static/novnc/core/rfb.js (or any path under that prefix), early in a deployment's life and in parallel, so the first-time extraction happens under its timing instead of a real user opening the desktop page, and so one marker miss is multiplied by the number of simultaneous requests.
- 관측: With home/novnc deleted, one unauthenticated GET returned 200, made 1 containers.create call and wrote home/novnc/core/rfb.js; the next GET made 0 create calls and returned 200 (marker hit). After deleting the tree, six concurrent unauthenticated GETs made 6 create calls, and in a second run twelve concurrent GETs made 12 create calls; with a directory-complete archive all of those responses were 200 and no exception was raised. With an archive that has no directory members, the same six-request burst returned one 200 and five 500s with FileExistsError: [Errno 17] File exists: '<home>/novnc/core' while still making 6 creates. Three unauthenticated GETs for /static/novnc/does-not-exist.js, each with the tree deleted first, made 3 more create calls and returned 404 each time. With a truncated archive, three sequential unauthenticated GETs each made another containers.create call and returned 500 ReadError: unexpected end of data with the marker still absent, and four concurrent requests against a truncated archive made 4 creates and 4 x 500.

**조건.**
- authentication_level: None - the route requires no principal, cookie or ticket.
- system_configuration: The desktop image is present (otherwise create raises ImageNotFound and the route is cheap) and home/novnc/core/rfb.js is absent: a fresh install before anyone opened a desktop page, or a state left behind by a failed or partial extraction. Nothing else in the tree calls extract_novnc, so the marker is created by this unauthenticated route on first use.
- timing_dependency: Two or more requests must be in flight together to duplicate the daemon work; a single request duplicates nothing, and the first success publishes the marker and ends the window for later requests.

**수정 방향.** Extract once, under a lock, outside the request path: do it at startup or on the first authenticated desktop route, guard it with a per-directory lock plus an in-flight event so concurrent callers wait for the winner, publish the marker only after a successful extraction, and treat any failure as a bounded negative state (a timestamped failure marker that short-circuits the route for a cooldown). /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.

`python` // agentbox/sandbox.py
```python
        self.client = docker.from_env()
        self._lock = threading.Lock()
        self._novnc_lock = threading.Lock()   # single-flight for extract_novnc
```

`python` // agentbox/sandbox_desktop.py
```python
    def extract_novnc(self, dest: Path) -> bool:
        marker = dest / "core" / "rfb.js"
        if marker.exists():
            return True
        with self._novnc_lock:            # one extraction per process
            if marker.exists():           # a waiter re-checks after the winner finished
                return True
            try:
                c = self.client.containers.create(self.settings.desktop_image, ["true"], network_mode="none")
            except (ImageNotFound, APIError):
                return False
            try:
                stream, _ = c.get_archive("/usr/share/novnc")
                out = b"".join(stream)
            except (NotFound, APIError):
                return False
            finally:
                try:
                    c.remove(force=True)
                except APIError:
                    pass
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                with tarfile.open(fileobj=io.BytesIO(out)) as tf:
                    members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
                    tf.extractall(dest.parent, members=members, filter="data")
            except (OSError, tarfile.TarError):
                shutil.rmtree(dest, ignore_errors=True)   # never serve a half tree
                return False
            return marker.exists()
```

`python` // agentbox/api.py
```python
    @app.get("/static/novnc/{path:path}")
    def novnc(path: str):
        root = novnc_dir.resolve()
        # 정적 파일은 요청 경로에서 컨테이너를 만들지 않는다. 시작 시 한 번만 꺼낸다.
        if not (root / "core" / "rfb.js").is_file():
            raise HTTPException(404)
        f = (root / path).resolve()
        if not f.is_relative_to(root) or not f.is_file():
            raise HTTPException(404)
        return FileResponse(f)
```

## F4. A GUI input queued on gui_lock across a human handback executes with no open burst, so its changes get no snapshot and no gui_changes row

- 지문: `agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback`
- 심각도: **중간** (가능성 중간, 영향 중간)
- 신뢰도: high
- 관련 경로: `agentbox/api.py`, `agentbox/gui_bursts.py`, `agentbox/service.py`

**설명.** AgentBox decides whether a GUI input needs a snapshot before it acquires gui_lock. While a human holds the desktop a takeover lease exists, so GuiBursts.needs_snapshot returns False and the input blocks on gui_lock instead of opening a burst. If the human hands the desktop back while that input is queued, the input runs with a lease check that now passes and no burst open: it writes as uid 1001, calls mark_input, and its fresh input timestamp makes needs_snapshot False for every later input until 60 s of input silence (gui_snapshot_idle) or 600 s after the last snapshot (gui_snapshot_interval). Those inputs produce no snapshot, no burst, and no gui_changes row; the only recovery point predates the human takeover, and the file effects of the inputs are never diffed or attributed.

**근본 원인.** The burst decision is taken outside the lock that serializes execution: service.py:343 evaluates _needs_snapshot (gui_bursts.py:52-63, which returns False while a non-stale lease or pending takeover exists) before _run_tool acquires gui_lock at service.py:136, and the only re-check under the lock (_check_control, service.py:152-161) validates the stale-lease/lease/pending-takeover state, never burst presence. _handback_locked (service.py:528-543) releases the lease (542) and calls forget_input (543) while still holding gui_lock, so the queued input resumes into a state where its earlier premise is gone and nothing takes a snapshot; mark_input (service.py:139) then suppresses the next burst decision.

**의도된 동작.** Every GUI input that executes must be covered by an open burst bound to a snapshot taken before that input, and each burst must close into a gui_changes record (service.py:261-264 fails closed when a burst baseline cannot be opened; gui_bursts.py:157-162 re-timers lifecycle paths for exactly this reason). A burst decision taken before waiting on a lock must be re-validated after the lock is acquired.

**전파 경로.**
- `agentbox/api.py:215` (entrypoint, POST /sandboxes/{sid}/tools/{tool} -> AgentBox.call_tool) — Agent token from principal; default_policy.yaml has default: allow and no rule for click/type/key, so GUI inputs are approval-free, are audited as tool_request, and take the ALLOW branch.
- `agentbox/service.py:343` (propagation, AgentBox._call_tool (ALLOW branch)) — _needs_snapshot is evaluated before any lock; while a takeover lease is present _over_snapshot_quota is skipped too and GuiBursts.needs_snapshot returns False, so no snapshot is taken and no burst is opened.
- `agentbox/service.py:136` (propagation, AgentBox._run_tool (GUI branch)) — gui_lock is acquired afterwards without a timeout, so an input that already decided 'no burst needed' can sit queued while the human's handback holds the same lock.
- `agentbox/service.py:152` (propagation, AgentBox._check_control) — The only re-check after acquiring gui_lock handles a stale lease, a live lease and the pending-takeover marker; burst presence and the earlier needs_snapshot result are never re-validated.
- `agentbox/service.py:542` (propagation, AgentBox._handback_locked) — While gui_lock is still held, the human handback releases the lease; the queued input then acquires the lock with no lease and no pending marker, so _check_control passes.
- `agentbox/service.py:543` (propagation, AgentBox._handback_locked) — forget_input only drops the input timestamp; the handback opens no burst, so the resumed input's decision premise is gone but nothing forces a snapshot.
- `agentbox/service.py:139` (propagation, AgentBox._run_tool (GUI branch)) — The resumed input executes the GUI action and calls bursts.mark_input although no burst is open.
- `agentbox/gui_bursts.py:62` (propagation, GuiBursts.needs_snapshot) — The fresh input timestamp makes the next decision False, so later inputs run burstless until gui_snapshot_idle of silence or gui_snapshot_interval since the last snapshot.
- `agentbox/gui_bursts.py:113` (sink, GuiBursts._finish) — Only an open burst is ever diffed and logged as gui_changes; no burst exists for these inputs, so their /workspace changes are never recorded.

**재현과 관측 결과.**

- 공격자 관점: An agent that wants to change the desktop without a gui_changes row and without a fresh recovery point keeps issuing GUI inputs while a human holds the desktop, so one of them is queued on gui_lock when the human hands back, and then keeps clicking/typing immediately afterwards.
- 관측: The queued click executed with status 200 executed and needs_snapshot False taken while the lease was still present and no burst open; snapshots stayed 1 and gui_changes stayed at the single row the takeover wrote for the seed burst, while the click plus three following clicks (all 200) added 4 files (5 files total). All four burst decisions were False, so no new snapshot or burst appeared. The control run with the same four clicks inside an open burst logged gui_changes added=4 for snap_1 when the burst closed. The only artificial element is a pause inside the handback's audit append (a real SQLite write), which widens the natural window; the ordering it produces is one the code allows.

**조건.**
- authentication_level: A sandbox agent token (agt_...); GUI tools are default-allow (default_policy.yaml default: allow) and need no human approval.
- timing_dependency: The single in-flight GUI input must take its burst decision while the takeover lease exists and then acquire gui_lock after the handback released the lease. A tight loop of click/type calls during the takeover (each 423) raises the hit rate; the window is the handback's lock-held section (audit write plus lease release), which SQLite/audit contention widens.
- user_interaction: The human must hand the desktop back through handback, logout, or pause/restore/delete via end_desktop, because that path is the one that holds gui_lock across the lease release.
- data_state: A snapshot taken within gui_snapshot_interval (default 600 s) exists, so after the burstless input the fresh mark_input timestamp keeps later inputs from opening a burst; the queued input itself needs only the lease.

**수정 방향.** Decide the GUI burst requirement under the same lock that serializes GUI execution: after gui_lock is acquired in _run_tool, re-evaluate needs_snapshot and take the snapshot / open the burst there, and fail closed with reset_timers if no burst is open. Key the decision on burst presence rather than only on input timestamps, and make the handback path force the next input to open a new burst instead of only forgetting the timestamp. Regression test: hold gui_lock with an input queued, release the lease inside the lock, release the lock, and assert the input never calls mark_input or executes without an open burst.

`python` // agentbox/service.py
```python
if tool in GUI_TOOLS:
    with self.desktop.gui_lock(sid):
        self._check_control(sid)
        if tool in GUI_INPUT:
            if self.bursts.needs_snapshot(sid):   # must be re-decided here, not at _call_tool:343
                self._snapshot(sid, tool, f"before {tool}", {})
            if not self.bursts.is_open(sid):
                self.bursts.reset_timers(sid)   # next input re-decides and opens a burst
                raise SandboxError("GUI 구간이 열려 있지 않아 GUI 입력을 실행하지 않음. 잠시 뒤 다시 호출할 것")
            self.bursts.mark_input(sid)
```

`python` // agentbox/gui_bursts.py
```python
def is_open(self, sid: str) -> bool:
    """입력이 실행될 때 열린 구간이 있는가. 구간 없이 실행하면 바뀐 것이 기록되지 않는다."""
    with self._lock:
        return sid in self._gui_burst
```

## F5. Agent tool input still reaches the append-only audit log uncapped through approval previews and tool error strings

- 지문: `agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap`
- 심각도: **중간** (가능성 높음, 영향 중간)
- 신뢰도: high
- 관련 경로: `agentbox/api.py`, `agentbox/audit.py`, `agentbox/service.py`

**설명.** The new _logged_args cap (service.py:181-194) bounds only the two audit copies that pass through it (tool_request at 295-296, tool_execute at 413-414). The same agent-controlled strings still reach audit.append uncapped through two other sinks on the same request path. (1) For an approval-requiring call the payload appended at service.py:330-333 carries the preview dict verbatim (line 332); _preview returns sandbox.preview's preview_command, which copies the whole raw exec command (preview.py:131) and appends one note per command segment with no count cap (preview.py:125, only 'affected' is truncated at 126-128), and when _preview raises, the failure note embeds str(SandboxError) - that is the raw agent path from safe_path (service.py:319-320, sandbox.py:156). (2) For read_file, which the default policy allows without approval, the same SandboxError text is stored as tool_error payload.error (service.py:360-362). Neither the tool route (api.py:216; ToolCall.args is an unconstrained dict at api.py:51) nor the shipped reverse proxy (deploy/Caddyfile:5) bounds the body, and AuditLog.append inserts json.dumps(payload) with no size check (audit.py:183). Audit rows are append-only (audit.py:35-38), so every retained byte is permanent; at disk-full the audit-writing paths fail closed with 503.

**근본 원인.** _call_tool caps only the two _logged_args mirrors (service.py:295-296, 413-414). The approval_requested payload passes preview through unchanged (service.py:330-333) while _preview copies the raw command and one note per segment (service.py:213-226, preview.py:125,131), and the SandboxError handler at service.py:360-362 logs str(e) untruncated although safe_path (sandbox.py:156) embeds the agent raw path. audit.append imposes no length bound of its own.

**의도된 동작.** Every payload that reaches the append-only audit log is bounded before the insert regardless of the producing call site: error strings, preview command, notes and affected paths are truncated to a fixed budget, the note count is capped, and the tool-args body is rejected above a small limit.

**전파 경로.**
- `agentbox/api.py:216` (entrypoint, POST /sandboxes/{sid}/tools/{tool}) — Agent-token route; ToolCall.args (api.py:51-52) is parsed from the JSON body with no size limit, so the argument size equals what the agent sends.
- `agentbox/service.py:295` (propagation, tool_request record) — Records args through the capped _logged_args, then evaluates policy; the capped copy is not the only path the arguments take.
- `agentbox/service.py:318` (propagation, _preview producer) — For exec, sandbox.preview returns preview_command's full raw command; for an invalid workspace path, safe_path raises with the raw path and the handler at 319-320 turns str(e) into a preview note; raw args also go to ApprovalStore.create at 324.
- `agentbox/service.py:330` (propagation, approval_requested audit append) — The payload carries the preview dict minus the capture image with no truncation of command, notes or affected entries (line 332), written before any human is involved.
- `agentbox/service.py:361` (propagation, SandboxError handler) — The untruncated str(e) is appended as payload.error; read_file and write_file need no approval, so this row is written on the first request.
- `agentbox/audit.py:183` (sink, AuditLog.append INSERT) — json.dumps of the masked payload is inserted into the append-only audit table with no length or count bound.

**재현과 관측 결과.**

- 공격자 관점: A prompt-injected agent sends one oversized tool argument and picks whichever tool gives the largest uncapped echo into the audit log.
- 관측: tool_request stayed bounded by _logged_args: 16,543 B for the two oversized-argument requests, and roughly 10.9 KB (not capped, because it fits under the 64 KiB LOGGED_ARGS_MAX) for the 10,003-byte exec request. The other sinks were not bounded: read_file with a 131,072-byte path outside /workspace returned 400 with a 131,115-byte message and wrote a 131,142-byte tool_error row with no approval; delete_file with a 262,144-byte path outside /workspace wrote a 262,342-byte approval_requested row whose single preview note began '미리보기 실패: 허용되지 않은 경로: /etc/AAAA…' (approval row: 262,156 B args, 262,244 B preview); exec with a 10,003-byte, 2001-segment command wrote a 96,207-byte approval_requested row carrying the full 10,003-byte preview.command and 2,001 notes (approval row: 10,018 B args, 96,109 B preview). DELETE FROM audit raised 'audit log is append-only'. With the page cap as a full-disk stand-in the append raised AuditWriteError 'database or disk is full' and the following tool call failed closed with 503.

**조건.**
- authentication_level: Any valid agent token for one sandbox; the human token is not needed.
- system_configuration: Default policy: delete_file always requires approval, non-allowlisted exec requires approval, while read_file and write_file are allowed, so the tool_error variant needs no approval at all.
- user_interaction: None: approval_requested rows are written before any human sees the request, and the read_file variant needs no approval.

**수정 방향.** Bound payloads at the sink and at the producers: one recursive bounder inside AuditLog.append (string truncation plus list/dict cap) applied before compute_hash so verify() stays consistent, truncate the preview command/notes/affected and the SandboxError text before they are appended, and reject oversized tool-args bodies at the route with a request_body limit in the shipped proxy as defense in depth.

`python` // agentbox/audit.py
```python
AUDIT_STR_MAX = 4096
AUDIT_LIST_MAX = 200

def _bound(v):
    if isinstance(v, str):
        return v if len(v) <= AUDIT_STR_MAX else v[:AUDIT_STR_MAX] + f"...({len(v)} bytes)"
    if isinstance(v, dict):
        return {k: _bound(x) for k, x in list(v.items())[:AUDIT_LIST_MAX]}
    if isinstance(v, list):
        return [_bound(x) for x in v[:AUDIT_LIST_MAX]]
    return v

# in append(), before compute_hash(prev_hash, record):
payload = _bound(self._mask(payload or {}))
```

`python` // agentbox/service.py
```python
AUDIT_TEXT_MAX = 512

def _audit_text(s: Any) -> str:
    t = str(s)
    return t if len(t) <= AUDIT_TEXT_MAX else t[:AUDIT_TEXT_MAX] + f"...({len(t)} bytes)"

# _preview failure note and exec command, before they are appended/created:
notes = [f"미리보기 실패: {_audit_text(e)}"]
preview["command"] = _audit_text(preview.get("command"))
preview["notes"] = [_audit_text(n) for n in (preview.get("notes") or [])][:200]
preview["affected"] = (preview.get("affected") or [])[:200]

# SandboxError handler:
except SandboxError as e:
    short = _audit_text(e)
    self.log_best_effort(sid, tool, "tool_error", {"request": req_id, "error": short})
    raise ServiceError(400, short) from e
```

## F6. A restore racing a delete resurrects the deleted sandbox row and re-authorizes the agent token the delete revoked

- 지문: `agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token`
- 심각도: **낮음** (가능성 낮음, 영향 중간)
- 신뢰도: medium
- 관련 경로: `agentbox/api.py`, `agentbox/sandbox.py`, `agentbox/service.py`

**설명.** DELETE /sandboxes/{sid} and POST /sandboxes/{sid}/restore each perform an unlocked read-modify-write on the same sandboxes row. If a DELETE completes between the restore's creation of the replacement container and the restore's final status write, the delete reports success and audits 'sandbox_delete', but the restore's last write puts status='running' and the new container_id back on the row. Neither operation rewrites token_hash, and revocation is expressed only as status!='deleted', so the agt_ token the delete revoked resolves to that sid again and its tool calls execute in the replacement container. The snapshots row also survives (delete removes only images), and the running replacement keeps the snapshot image in use, so the best-effort image removal raises and is swallowed. The control plane therefore reports a completed deletion while the sandbox, its /workspace and its agent authority are live again.

**근본 원인.** Lifecycle operations take no per-sandbox lock and re-read nothing. Service.restore_sandbox and Service.delete_sandbox (service.py:462-475) call SandboxManager.restore and SandboxManager.delete (sandbox.py:387-401, 320-332); each reads the row once with _rec, acts, and writes status/container_id unconditionally through _set, which is a bare UPDATE with no status predicate (sandbox.py:234-237). SandboxManager.restore never checks status=='deleted', so its final _set (sandbox.py:398) overwrites the delete's status write (sandbox.py:326) and reinstates the record. Revocation of the agent token is expressed only as status!='deleted' (sandbox.py:216, 221), so the overwritten status silently re-authorizes the original token hash.

**의도된 동작.** _container (sandbox.py:225-232) and the token lookups (sandbox.py:211-223) treat status=='deleted' as final: a deleted sandbox is unusable and its agent token is invalid. DELETE is the revocation contract (service.py:471-475 logs sandbox_delete, ends the desktop, deletes the container, drops captures). No later or concurrent lifecycle call may reinstate the record, re-point it at a container, or make the revoked token valid again.

**전파 경로.**
- `agentbox/api.py:206` (entrypoint, POST /sandboxes/{sid}/restore) — sync human_only route hands the client-supplied snapshot_id to box.restore_sandbox and runs in the Starlette threadpool with no serialization against other lifecycle calls
- `agentbox/service.py:465` (propagation, AgentBox.restore_sandbox) — calls SandboxManager.restore outside any lock, after end_desktop has already run
- `agentbox/sandbox.py:388` (propagation, SandboxManager.restore) — reads the row with _rec, which returns deleted rows too, and never checks status
- `agentbox/sandbox.py:393` (propagation, SandboxManager.restore) — force-removes the row's old container (NotFound swallowed), so the row's stale container_id no longer exists
- `agentbox/sandbox.py:397` (propagation, SandboxManager.restore) — starts the replacement container from the snapshot image; from this point the new container exists while no lock protects the row
- `agentbox/api.py:211` (propagation, DELETE /sandboxes/{sid}) — second human request for the same sid runs as a separate threadpool worker, so delete_sandbox executes concurrently with an in-flight restore
- `agentbox/sandbox.py:326` (propagation, SandboxManager.delete) — marks the row deleted (unconditional UPDATE), after removing the old container_id the restore already removed
- `agentbox/sandbox.py:330` (propagation, SandboxManager.delete) — snapshot image removal fails because the restore's new running container uses the image; APIError is swallowed, so the image and its snapshots row survive
- `agentbox/sandbox.py:398` (propagation, SandboxManager.restore) — final _set overwrites the deleted status with status='running' and the replacement container_id
- `agentbox/sandbox.py:216` (propagation, SandboxManager.token_matches) — only rejects status=='deleted', so the original agent token hash is accepted again
- `agentbox/sandbox.py:221` (sink, SandboxManager.sandbox_for_token) — resolves the revoked token back to the sid, which api.principal turns into an agent principal (api.py:121-123)

**재현과 관측 결과.**

- 공격자 관점: Holder of the agt_ token whose authority the human tried to revoke with DELETE. It needs no new credential and takes no action: after the overlapping restore the same token maps to the sid again and its tool calls return 200. The overlap itself requires two human-issued requests (restore and delete) whose timing the agent cannot control, so this is a failed revocation contract rather than a directly attacker-triggered race.
- 관측: Race run (delete parked inside the post-create window): delete_sandbox returned without error after status had become 'deleted' and token_matches and sandbox_for_token reported the token invalid; the parked restore then returned normally. Read-back: status 'running', container_id c2 present and alive, sandboxes.token_matches(sid, old_token)=true, sandbox_for_token(old_token)=sid, snapshot rows still 1, the snapshot image still present (delete's image removal raised because c2 runs it), and box.call_tool(sid, 'list_dir', {'path': '/workspace'}) returned 200 {'status': 'executed', 'result': {'path': '/workspace', 'listing': '...'}}. Audit sequence: sandbox_created, snapshot_request, snapshot, restore_request, sandbox_delete, restored, tool_request, policy_decision, tool_result. Sequential control: ImageNotFound 'no such image: agentbox-snap:sb_9df2e832-snap_3e1280c2', final status 'deleted', token invalid. Alternative schedule (delete before the replacement container exists): delete removed the image, the restore raised ImageNotFound, final status 'deleted', token invalid - so this ordering does not resurrect and bounds the vulnerable window.

**조건.**
- authorization_role: Both requests need the human token or a browser session with scope '*'; the agent never issues them, but it holds the agt_ token whose revocation DELETE implements and needs no new credential, so the failure is a revocation/TOCTOU defect rather than an attacker-triggered request.
- timing_dependency: The DELETE must complete its row read, status write and image-removal attempt inside the window that opens when the restore's replacement container has been created (sandbox.py:397) and closes at the restore's status write (sandbox.py:398), and the restore must be preempted in that window. This window is a few milliseconds of SQLite/thread scheduling, not the whole restore: in the measured alternative schedule where the DELETE lands during the long container-start portion, the delete removes the snapshot image first, the restore then fails with ImageNotFound, and the row stays deleted with the token invalid. So the overlap is reachable but narrow.
- data_state: The sandbox has at least one snapshot row; DELETE never removes snapshots rows (sandbox.py:327-332 only tries to remove images) and restore accepts any row of that sid.
- system_configuration: No special runtime or container capability is needed: the resurrection is decided entirely in the SQLite row and the token lookups. The daemon fact that matters (images.remove refusing while a running container holds the image) is what real Docker does; the harness models it, and even if the image were removed the running replacement and the surviving snapshots row would still leave the sandbox resurrected.

**수정 방향.** Serialize all lifecycle transitions per sandbox and make deletion final at the point of the check. Take one per-sid lifecycle lock in AgentBox (reuse the _snap_locks map with a distinct key) around pause/resume/snapshot/restore/delete so delete and restore cannot interleave, and have SandboxManager.restore re-read the row under that lock and refuse status=='deleted' before it removes the old container or starts the replacement. The two methods below are the decisive pair for this race; the same lock should wrap pause_sandbox/resume_sandbox/snapshot_sandbox as well, since pause's unconditional _set(status='paused') has the same shape. Regression case: drive restore and delete concurrently with the harness and assert that the row is either deleted with the old token invalid and no replacement container, or still not deleted only when no delete was observed.

`python` // agentbox/service.py
```python
    def _lifecycle_lock(self, sid: str) -> threading.Lock:
        with self._busy_lock:
            return self._snap_locks.setdefault("lifecycle:" + sid, threading.Lock())

    def restore_sandbox(self, sid: str, snap_id: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle_lock(sid):
            self.log_human("restore_request", sid, _with_session({"snapshot_id": snap_id}, session))
            self.end_desktop(sid, "sandbox_restored")
            rec = self.sandboxes.restore(sid, snap_id)
            self.bursts.reset_timers(sid)
            self.log_human("restored", sid, _with_session({"snapshot_id": snap_id, "container_id": rec["container_id"]}, session))
            return rec

    def delete_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> None:
        with self._lifecycle_lock(sid):
            self.log_human("sandbox_delete", sid, _with_session({}, session))
            self.end_desktop(sid, "sandbox_deleted")
            self.sandboxes.delete(sid)
            self.drop_captures(sid)
```

`python` // agentbox/sandbox.py
```python
    def restore(self, sid: str, snap_id: str) -> dict[str, Any]:
        rec = self._rec(sid)
        if rec["status"] == "deleted":   # 삭제는 되돌릴 수 없다: 지운 샌드박스의 행·토큰은 되살리지 않는다
            raise SandboxError(f"삭제된 샌드박스는 되돌릴 수 없음: {sid}")
        snaps = {s["id"]: s for s in self.list_snapshots(sid)}
        if snap_id not in snaps:
            raise SandboxError(f"이 샌드박스의 스냅샷이 아님: {snap_id}")
        try:
            self.client.containers.get(rec["container_id"]).remove(force=True)
        except NotFound:
            pass
        tpl = self.template_of(sid)
        c = self._run_container(tpl, snaps[snap_id]["image"], rec["source_dir"], f"agentbox-{sid}")
        self._set(sid, container_id=c.id, status="running")
        if tpl.desktop:
            self._wait_display(c)
        return self.get(sid)
```

## F7. Unauthenticated failed POST /login writes one permanent hash-chained audit row per attempt, with no rate limit, aggregation or retention

- 지문: `agentbox/web.py:unauthenticated-login-failure-audit-growth`
- 심각도: **낮음** (가능성 높음, 영향 낮음)
- 신뢰도: high
- 관련 경로: `agentbox/audit.py`, `agentbox/service.py`, `agentbox/web.py`

**설명.** web.py:130-140 serves POST /login with no principal and no cookie requirement. On a token mismatch it calls box.log_human("ui_login_failed", None, {}) at 136; service.py:590-594 forwards that to audit.append, which takes the single process-wide audit lock, runs BEGIN IMMEDIATE, reads the previous chain hash, inserts a row and commits (audit.py:162-185). Nothing rate-limits, deduplicates, aggregates, caps or prunes these rows: api.py:113 registers _NoFraming as the only middleware, deploy/Caddyfile:4-6 reverse-proxies /login with no rate or body limit, and audit.py contains no DELETE, VACUUM or retention code. Removal is not merely unimplemented but blocked: the audit_no_delete trigger (audit.py:37-38) rejects DELETE and verify() rejects any id gap (audit.py:233-234), so pruning rows later breaks the integrity check the operator relies on. The only precondition is same_origin (web.py:132), which returns True when the Origin header is absent (api.py:131-133), so a plain HTTP client reaches the write. Locally reproduced at the ASGI layer with the real AuditLog/AgentBox/handler: one wrong-token POST added exactly 1 ui_login_failed row, 250 such POSTs added 250 durable rows at ~11.5 ms each, and 6 concurrent clients sustained ~270 rows/s while raising the latency of an ordinary agent tool_request append from ~4.6-5.5 ms to ~36-40 ms. The same handler has the inverse defect: a non-ASCII token makes secrets.compare_digest raise TypeError at web.py:134, so the request returns a bare 500 with 0 rows recorded and the client also chooses which attempts enter the chain.

**근본 원인.** An unauthenticated, attacker-paced durable write into the append-only security record: the failed-login path uses the same serialized hash-chained append that gates tool executions, with no per-source or global rate limit, no aggregation, and no retention or compaction for the rows it creates - and the append-only triggers plus verify()'s contiguity check leave no legitimate way to remove them afterwards.

**의도된 동작.** Anonymous authentication failures should be rate-limited and aggregated before they reach the audit chain (for example one "N failures since T" summary per source per interval), so one unauthenticated client cannot unilaterally grow the operator's security record or monopolize the audit lock every other append and read needs; the audit store should have a documented retention/compaction scheme that keeps chain verifiability (signed checkpoints plus archived segments). A malformed credential should be compared as bytes (or rejected on an ASCII check) so it becomes a recorded 401/400 instead of an unrecorded 500.

**전파 경로.**
- `agentbox/web.py:131` (entrypoint, POST /login form handler) — def login(request: Request, token: str = Form(...)) has no principal, session or cookie requirement; the only precondition is the same_origin call at 132, and same_origin (api.py:131-133) returns True when the Origin header is absent.
- `agentbox/web.py:136` (propagation, token mismatch branch) — A wrong token falls through the compare_digest at 134 to box.log_human("ui_login_failed", None, {}) and then renders the error page at 139; a non-ASCII token raises TypeError at 134 before this line and returns 500 with nothing recorded.
- `agentbox/service.py:590` (propagation, log_human -> audit.append) — log_human forwards the event to self.audit.append(actor="human", event=event, sandbox_id=sid, payload=payload) at 592; an AuditWriteError would become a 503, but on success the row is durable in SQLite.
- `agentbox/audit.py:180` (sink, INSERT INTO audit under the process-wide lock) — append() takes self._lock at 162, BEGIN IMMEDIATE at 163, reads the last hash at 165, inserts the row at 179-184 and commits at 185; every other audit append (including tool_request/tool_result) and every human read or verify() waits on the same lock.

**재현과 관측 결과.**

- 공격자 관점: An unauthenticated client posts the login form with a wrong token as fast as the server answers, adding one durable audit row and one acquisition of the global audit lock per request, for as long as it likes.
- 관측: Independent reproduction matched and extended the candidate: 1 wrong-token POST added exactly 1 ui_login_failed row; 250 further wrong-token POSTs added 250 rows at ~11.5 ms per request (~86/s) with no rejection, cap or 429 at any point; 6 concurrent clients reached ~270 rows/s. Latency of a normal agent tool_request audit.append rose from a 4.6-5.5 ms baseline to 36-40 ms while the login flood ran, because both take audit.py's single lock. A non-ASCII token returned 500 (TypeError: comparing strings with non-ASCII characters is not supported) and added 0 rows, so the same client can also keep its attempts out of the chain.

**조건.**
- authentication_level: None - a wrong form token and no cookie; no Origin header required.
- system_configuration: The control plane is reachable through the shipped Caddy proxy, and AGENTBOX_HOME/agentbox.db persists across restarts with no pruning path.
- data_state: The audit table is append-only at the database level (audit_no_update/audit_no_delete triggers) and verify() requires contiguous ids, so rows written by an anonymous client are permanent.
- timing_dependency: The serialized append bounds the rate (~86 rows/s from one client, ~270 rows/s with 6 concurrent clients) but never the total number of rows.

**수정 방향.** Rate-limit and aggregate failed logins before the audit append: a per-client-address token bucket plus a global cap, recording a compacted 'N failures since T' summary per window instead of one row per attempt (never dropping the fact that failures happened). Give the audit store a retention scheme that preserves chain verifiability (signed checkpoints plus archived segments) so operator disk growth is bounded and auditable. Compare credentials as bytes, or reject non-ASCII input explicitly, so a malformed credential is a recorded 400/401 rather than an unrecorded 500, and keep the 'audit before action' rule intact for tool paths.

`python` // agentbox/web.py
```python
    @app.post("/login", include_in_schema=False)
    def login(request: Request, token: str = Form(...)):
        if not same_origin(request.headers):
            raise HTTPException(403, "다른 출처의 요청")
        # 바이트로 비교한다: 비ASCII 문자열은 compare_digest가 TypeError를 내서 500이 되고,
        # 그 실패는 감사 로그에도 안 남아 공격자가 기록 여부를 고를 수 있게 된다.
        given = token.strip().encode("utf-8", "replace")
        if not secrets.compare_digest(given, human_token.encode()):
            # 주소별 초당 몇 건만 즉시 남기고, 나머지는 세었다가 다음 창에 요약 1건으로 남긴다
            if _login_failures.record(request.client.host if request.client else "unknown"):
                try:
                    box.log_human("ui_login_failed", None, {"aggregated": _login_failures.dropped()})
                except ServiceError:
                    pass
            return render(request, "login.html", error="사람 토큰이 아님 (에이전트 토큰으로는 들어갈 수 없습니다)")
        return start_session(request, "/ui", "token")
```

