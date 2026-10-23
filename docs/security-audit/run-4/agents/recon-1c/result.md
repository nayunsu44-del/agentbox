recon-1c report: entry surfaces, copies and sinks at 9805d91. All paths are repo-relative to src-audited. I read the source only: nothing was executed and no files were written.

## 1. HTTP and browser (FastAPI, `agentbox/api.py`, `agentbox/web.py`)
- **Auth model is unchanged from run-3.**
  - `principal` checks the bearer token: the human token via `compare_digest`, or the agent token via a hash lookup that excludes deleted sandboxes (api.py:115-124, sandbox.py:218-223).
  - `screen_principal` accepts a header or a cookie, and applies `same_origin` only on the cookie path; a missing Origin is still allowed (api.py:131-147).
  - `screen_human` requires scope `*` (api.py:149-155). `desktop_human` accepts `*` or the sandbox id (api.py:157-163).
- **New since run-3:** the `_NoFraming` middleware adds XFO and frame-ancestors headers to HTTP responses only (api.py:63-80, 113).
- **Routes an agent token can reach:**
  - GET `/sandboxes/{sid}` for its own sandbox; this exposes the host path in `source_dir` (api.py:183-187).
  - POST tools (api.py:215-221).
  - GET `/approvals/{aid}`, which runs the global `expire_stale` and the close of idle GUI bursts first (api.py:230-241, service.py:375-377).
  - GET `desktop/state` (api.py:325-330).
  - POST `/approvals/{aid}` is refused, but each attempt appends an `approval_forbidden` audit row containing the URL `aid` (api.py:251-259).
- **Unauthenticated routes:**
  - `/`, `/login` GET/POST, `/static/htmx.min.js` (vendored htmx 2.0.11), `/static/novnc/*` (extracts from the image on demand, api.py:355-363), `/healthz` (api.py:368-371), `/sandboxes/{sid}/desktop?ticket=` (api.py:308-318).
  - FastAPI's default `/docs`, `/redoc` and `/openapi.json` are not disabled (api.py:111). `/docs` loads its JS from a CDN on the same origin as the cookie UI, and no CSP is set.
  - Each failed POST `/login` writes a `ui_login_failed` audit row with no authentication and no rate limit; a request with no Origin passes the check (web.py:379-389).
  - A non-ASCII token makes `compare_digest` raise TypeError, which becomes a 500 (api.py:119, web.py:383).
- **Human JSON API:** lifecycle routes (api.py:174-212), approvals (api.py:224-262), audit (api.py:265-273). A negative `limit` on `/audit` bypasses `min(limit, 5000)`, because SQLite treats `LIMIT -1` as no limit (api.py:266-269).
- **Human browser routes:**
  - Upload: multipart, each file read into memory up to the 50 MB limit; the number of files is not capped (api.py:276-286).
  - Outbox list and download, with an RFC5987 `filename*` (api.py:288-298).
  - Desktop ticket (api.py:301-306) and takeover/handback (api.py:332-341).
  - Web UI fragments (web.py:413-529).
- **Rendering:** Jinja autoescape plus `finalize=_shown`, which applies `escape_controls` to string outputs only (web.py:282-286, 343; display.py:12-21).
  - The set it escapes is C0, C1, LRM, RLM, U+202A-202E and U+2066-2069. It does not include U+061C, U+2028/2029 or zero-width characters.
  - Non-string values render via `str()` (Python repr).
  - Agent-controlled strings reach `_approvals.html:8,10,14,16,26`, `_outbox.html:5-7` (filename goes into `data-text`, then into a browser Notification body, base.html:75), `_audit.html:5-6` and `describe()` (web.py:295-333).
- **Proxy:** `--behind-tls-proxy` uses `forwarded_allow_ips=AGENTBOX_TRUSTED_PROXIES or "*"` (cli.py:124-126). `request.base_url` (Host or forwarded headers) is written into the MCP config shown at create time (web.py:430-434).

## 2. Protocol: WebSocket / RFB relay (`agentbox/desktop_ws.py`, new module)
- **Route checks:** cookie session for the sid, `same_origin`, mode is `view` or `control`, then `may_connect`; view mode is always allowed (api.py:343-353, desktop.py:335-339).
- **`relay`** performs no authentication itself; the module docstring says so (desktop_ws.py:1-5). It:
  - builds argv with `vnc_command` and starts `docker exec -i -u desktop … socat - EXEC:x11vnc -inetd …` (sandbox_desktop.py:131-144, desktop_ws.py:26-28);
  - re-checks `may_connect` after `add_conn` (desktop_ws.py:41-43);
  - forwards browser bytes to x11vnc stdin with no rate or size limit (desktop_ws.py:46-57);
  - re-validates the session every 30 s (`session_watch`, desktop_ws.py:67-80).
- The x11vnc flags do not include `-noremote` or `-safer` (sandbox_desktop.py:138-139). x11vnc runs as non-root, which by default leaves remote-control commands such as `gone:` and `accept:` available to any X client holding the cookie, i.e. uid 1001.

## 3. Files, archives and container output (attacker-controlled input to the control plane)
- **Exec:** streamed through `_Head`, capped at 64 KB (sandbox.py:84-100, 404-423).
- **Container calls with neither a timeout nor an output cap** (`exec_run` buffers all output):
  - `list_dir` `ls -la` (sandbox.py:425-432)
  - `exists`/`is_dir` (sandbox.py:458-461, 521-523)
  - `outbox_list` `find -printf`, which is also polled by the UI every 3 s and rendered without a cap (sandbox.py:525-535, web.py:479-488, sandbox.html:35)
  - preview `_expand` (sandbox.py:557-562); `_walk` is capped by `head -n` (sandbox.py:564-569)
- **Parsers:**
  - `_parse_outbox` (sandbox.py:103-124)
  - `_parse_manifest`: 8 MB cap, root `find` under a 30 s timeout (gui_state.py:186-198, sandbox.py:372-381)
  - `_parse_ps` reads root `ps`; the `args` field is attacker-controlled (gui_state.py:207-219, sandbox_desktop.py:52-62)
  - window pids come from client-declared `_NET_WM_PID` (sandbox_desktop.py:59-61)
- **Preview:** the affected list is built from container filenames split on `\n`, so a filename containing a newline injects fake rows (sandbox.py:561-569). `preview_command` calls `expand(op)` once per `rm` operand and `walk` once per match, with no cap on the number of operands; the `limit` truncation happens only after the loop (preview.py:257-267, 295-297).
- **Write paths:**
  - Upload and write go through a base64 chunked temp file, then `mv -f` as uid 1000 (sandbox.py:463-476, 489-519).
  - `clean_name` allows bidi characters, quotes and leading dots/dashes (sandbox.py:41-49).
  - Outbox read: `[ -f ] && [ ! -L ]`, then `head` under a 30 s timeout (sandbox.py:537-554).
  - `extract_novnc`: tar with `filter="data"`, links skipped (sandbox_desktop.py:146-169).
- **Desktop start script (root, every start and restore):** resets the desktop home from `/usr/local/share` (new, agentbox-desktop-start:51-54). As root it also runs `rm -f /tmp/.X0-lock /tmp/.X11-unix/X0`, `mkdir -p /tmp/.X11-unix && chmod 1777` (which follows a symlink), and redirects `2>/tmp/xvfb.log` and `>/tmp/xfce.log`. All of these target `/tmp`, which the agent can pre-populate and which persists in snapshots (agentbox-desktop-start:46, 55, 68, 76). Whether this is exploitable depends on the host's `fs.protected_symlinks` and `fs.protected_regular` settings.

## 4. CLI, env and config
- **Settings:** all `AGENTBOX_*` variables (config.py:28-69). `AGENTBOX_DOCKER_CLI` becomes argv[0] of the relay (sandbox_desktop.py:134). `AGENTBOX_POLICY` is loaded with `yaml.safe_load` (policy.py:187-190). `AGENTBOX_DB` (config.py:84-86).
- **Human token:** written, then chmod'd, leaving a umask window (config.py:97-99). A human token from the environment shorter than 8 characters is not registered for masking (audit.py:133-135).
- **Serve gates:** `bind_problem` (cli.py:68-74) and `runtime_problem`, which still matches only the literal `"runc"` (cli.py:77-84). The `uvicorn agentbox.api:create_app` factory path skips both (api.py:376-378).
- **Terminal output:** `_safe` is applied to approval and audit output (cli.py:33-35, 184-209, 262-296) and to the agent log (cli.py:355-365). These print raw: the server `detail` in `_check` (cli.py:47-54), `cmd_list source_dir` (cli.py:166), and LLM error `r.text[:500]` via a traceback (agent.py:343-344, 384-385).

## 5. Plugins, dependencies and CI
- Dependencies use unpinned `>=` ranges (pyproject.toml:155-165).
- CI is read-only `contents` and runs tests only (.github/workflows/ci.yml:190-259).
- The control-plane image copies the docker CLI and mounts `docker.sock` (deploy/Dockerfile, docker-compose.yml:121-125). Caddy reverse-proxies Host through unchanged (Caddyfile).

## 6. Cloud events / IAM
None in source.

## 7. Model context and tool arguments
- **Arguments:** `ToolCall.args` is `dict[str, Any]` with no request body size limit (api.py:51-52). Arguments are coerced with `str()` and `_int` (service.py:123-150, 597-601). GUI input goes to `click`, `type_text` (≤2000 characters) and `key` (`_KEY_RE`) (sandbox_desktop.py:94-129). The policy uses the same `str(args.get("command"))` as execution (policy.py:192-217). GUI tools default to allow (default_policy.yaml).
- **Stored copies of agent arguments and results:**
  - `approvals.args`: raw, unmasked, unbounded (approvals.py:299-309).
  - `approvals.preview`: includes the full command (preview.py:300; fallback at service.py:320).
  - `approvals.result`: full stdout/content, unmasked, returned to the agent and the human (approvals.py:341-346, api.py:240).
  - Audit `tool_request` args are capped at 64 KB / 16 KB head (service.py:181-194, 295-296). But:
    - `approval_requested` stores the preview, including the full `command` and unbounded per-segment notes (service.py:330-333).
    - `tool_error` stores the full `str(e)` (service.py:360-362, 347).
    - `safe_path` puts the entire raw `path` into its SandboxError (sandbox.py:156), and the 400 response echoes it (service.py:362).
  - Masking applies to string values only, not dict keys (audit.py:137-147). It runs on the already-truncated `args_head`, so a secret cut at the 16 KB boundary can partly survive. `mask_text`, `json.dumps` and the hash all run on full-size strings, the last two under the global audit lock (audit.py:160-186).
- **Agent loop / MCP:** container output is returned to the LLM verbatim (agent.py:289-299, mcp_server.py:83-165).

## 8. Mobile / deep-link
None. The closest equivalent is the one-time ticket URLs `/login?ticket=` (web.py:371-377) and `/sandboxes/{sid}/desktop?ticket=` (api.py:308-318).

## 9. Local IPC
- Docker socket via the SDK, with root `exec_run` for setup, manifest and ps (sandbox.py:302, 376-378; sandbox_desktop.py:55).
- `docker exec` subprocess carrying RFB (desktop_ws.py:26-28).
- X11 cookie in `/home/desktop/.Xauthority` (agentbox-desktop-start:63-66).
- `kill -KILL` as desktop (sandbox_desktop.py:64-67).
- SQLite with default file mode; it holds the unmasked approval args and results (approvals.py:296).
- MCP over stdio.

## Baseline corrections (run-3 → now)
- `tool_pool` is at api.py:103.
- Container flags: sandbox.py:243-265.
- Snapshot quota: service.py:243-248, 298-302.
- The source_dir overlap check now compares by `samefile`, and the bind is NonRecursive (sandbox.py:127-144, 274-282).
- Sessions and tickets carry a `gen` fingerprint, so rotating the human token revokes them (desktop.py:153-155, 199-205).
- Pending-approval cap of 20, and captures are dropped (service.py:44, 97-109, 312-316).
- GUI bursts are bound to `container_id` (gui_bursts.py:68, 115-119). Bursts fail closed on open (service.py:260-264). Bursts are ended on pause/restore/delete (service.py:444-475).
- X execs are timed at 15 s (sandbox_desktop.py:26, 45-50).
- Approval table warns per segment (preview.py:291-294).
- `audit.recent` is used for the UI, and CLI paging covers the 5000-row limit (audit.py:209-217, cli.py:255-260).

## Changed since run-3 / refactor seams worth hunting
1. `AgentBox._call_tool` / `safe_path` → `tool_error`: the full agent-supplied path goes into a permanent audit row, a parallel path around the e63922c cap (service.py:360-362, sandbox.py:156).
2. `_call_tool` → `approval_requested`: `preview["command"]`, unbounded `notes` and the preview-failure text are logged uncapped (service.py:318-333, preview.py:294, 300).
3. `preview_command`: one docker exec per `rm` operand and per match, with no count cap or timeout, in a tool thread before approval (preview.py:257-267, sandbox.py:557-569).
4. `GuiBursts.open` is unlocked and assumes the caller holds `_snap_locks`. `AgentBox.decide → _snapshot` (an approved GUI input, e.g. via the snapshot quota) runs without it, so a racing `open` can overwrite an open burst that is never closed (service.py:250-257, 411-412; gui_bursts.py:65-77).
5. `pause_sandbox`: `bursts.end`, then `sandboxes.pause`, with no `gui_lock` or snap lock held. A GUI input in that gap opens a burst that cannot be closed on the paused container (`close_failed`, no stray kill) (service.py:444-448, gui_bursts.py:157-162).
6. `restore_sandbox` / `SandboxManager.restore`: no `status == 'deleted'` check. It sets status to `running`, so the old agent token hash becomes valid again if snapshot-image removal failed (sandbox.py:320-332, 387-401).
7. Synchronous burst closes in human threads: `takeover` calls `bursts.close` while holding `gui_lock`, and `end_desktop`/`pause_sandbox` call `bursts.end`. Each is a chain of agent-influenced docker execs of up to about 30+15+15+15+30 s (service.py:508-516, 446, 581; gui_bursts.py:100-135).
8. `gui_strays.from_exec`: anything descended from a docker-exec root is exempt from the kill. Combined with the x11vnc relay lacking `-noremote` (`gone:`/`accept:` spawn commands under the relay), this is a candidate stray-kill bypass (gui_state.py:241-249, sandbox_desktop.py:138-139).
9. `outbox_list` / `list_dir` / `_expand`: buffered with no timeout or cap. `outbox_list` is polled every 3 s and rendered in full (sandbox.py:425-432, 525-535; web.py:479-488).
10. Unauthenticated audit appends: every failed POST `/login` (web.py:384-387), plus the agent's `approval_forbidden` rows (api.py:252-258). Separately, the desktop start script's root `/tmp` operations run against agent-planted state that is restored from snapshots (agentbox-desktop-start:46, 55, 68, 76).
