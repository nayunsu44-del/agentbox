recon-1b report: principals, authority and controls (run-4, commit 9805d91)

All references are to the audited tree at `src-audited/`. I wrote nothing and ran nothing. I did not judge whether anything is reachable live.

## 1. Lower-trust principals and their designed actions

- **Agent token** `agt_…` (one per sandbox). Created at `sandbox.py:290`, stored as an unsalted sha256 at `sandbox.py:80-81,316`, looked up at `sandbox.py:218-223`, which excludes deleted sandboxes. It can:
  - call tools on its own sandbox (`api.py:315-321`);
  - `GET /sandboxes/{own}` (`api.py:283-287`);
  - `GET /approvals/{aid}` on its own sandbox, which returns only id, status, result and decided_at (`api.py:330-341`);
  - `GET …/desktop/state` (`api.py:425-430`).
  - Trying `POST /approvals` gets a 403 and an `approval_forbidden` audit row (`api.py:350-359`).
  - It has no expiry and no rotation. Deleting the sandbox is the only way to revoke it.
- **Desktop-link session** (scope = one sid). It comes from a per-sandbox ticket (`api.py:401-418`). It can load the desktop page, state, takeover/handback and the WS for that sid only (`api.py:257-263`, `desktop.py:162-167`). All web UI routes reject it (`api.py:249-255`, `web.py:96-97`).
- **Code inside the sandbox**:
  - uid 1000 `agent` runs exec and file tools (`sandbox.py:34,411-412`).
  - uid 1001 `desktop` runs X, GUI tools and x11vnc. It is in the agent group (`images/desktop/Dockerfile:26-32`). The X cookie is desktop-only (`agentbox-desktop-start:26-30`).
  - The control plane also runs root execs inside the container: the setup copy (`sandbox.py:297-302`), the manifest `find` (`sandbox.py:376-378`) and `ps` with the default user (`sandbox_desktop.py:55`).
  - Everything the container outputs is attacker data: `_parse_ps` (`gui_state.py:38`), `_parse_manifest` (`gui_state.py:17`), `_parse_outbox` (`sandbox.py:103-124`), outputs from `_expand`/`_walk` (`sandbox.py:557-569`), screenshot bytes (`sandbox_desktop.py:84-92`), and the RFB stream to noVNC in the admin origin.
- **MCP stdio server and `agent.py` loop**: they hold an agent token from env (`mcp_server.py:37-55`, `agent.py:76-83`). `cmd_agent` refuses a token starting with `hum_` (`cli.py:340-341`). This is cosmetic only: a custom `AGENTBOX_HUMAN_TOKEN` without that prefix passes.
- **Unauthenticated network clients** can reach:
  - `/healthz` (`api.py:468-471`);
  - `/static/novnc/*` (`api.py:455-463`). It calls `extract_novnc`, which creates a Docker container while novnc has not been extracted yet (`sandbox_desktop.py:146-169`).
  - `/`, `/login` (GET and POST) and `/static/htmx.min.js` (`web.py:118-161`).
  - A failed `POST /login` writes a `ui_login_failed` audit row on every attempt. There is no rate limit, and a missing Origin passes (`web.py:130-139`, `api.py:231-233`).

## 2. Authentication at each entry surface

- **JSON API**: `principal` accepts only `Authorization: Bearer`. The human token is compared with `compare_digest`; anything else falls through to the agent-token hash lookup (`api.py:215-224`). `human_only` is at `api.py:226-229`.
- **Browser routes**: `screen_principal` (`api.py:238-247`).
  - If an Authorization header is present it takes precedence, with no Origin check.
  - Otherwise it uses the cookie via `session_scope` plus `same_origin`. `same_origin` lets a missing Origin through and compares Origin against the Host header.
- **Cookie**: HttpOnly, SameSite=Strict, Secure when TLS or scheme is https (`desktop.py:58-60`, `api.py:235-236`, `cli.py:102`).
- **Sessions**: 12 h, stored hashed, with a scope and a gen fingerprint (`desktop.py:130-167`).
- **Tickets**: 60 s, one-time, stored hashed, scope must match (`desktop.py:111-128`). They are issued only to the human token (`api.py:401-406`, `web.py:153-156`).
- **Ticket redemption** happens on GET `/login?ticket` (`web.py:122-127`) and GET `/sandboxes/{sid}/desktop?ticket` (`api.py:408-418`).
- **Token rotation**: the gen value is a PBKDF2 hash of the human token (`desktop.py:53-55`). Sessions and tickets with an old gen are purged at start and refused per request (`desktop.py:99-105,126,157`).
- **WebSocket**: cookie, scope, `same_origin` and mode check; a control connection needs the lease (`api.py:443-453`).
- **Web login**: token form compared with `compare_digest` (`web.py:130-140`).
- **Logout** needs a same-origin POST (`web.py:142-151`).

## 3. Per-resource authorization and scope

- **Human**: a single admin with no tenancy. Any human principal can act on every sandbox and approval.
- **Agent scope** is checked by `p.sandbox_id != sid` at `api.py:285,317,337,427`. Before checking existence, the agent gets 403 for another sandbox. For approvals it gets 404 when the approval is missing and 403 when it belongs to another sandbox (`api.py:333-338`).
- **Scope `*` versus sid share one namespace.**
  - `desktop.py:126,165`: a `*` ticket is honoured at `/sandboxes/*/desktop`. That grants nothing new.
  - The reverse depends on sandbox ids never being `*`. Ids are `sb_`+hex (`sandbox.py:273`), and a ticket is issued only after `_desktop(sid)` succeeds (`api.py:403`).
- **File paths**:
  - `safe_path` limits paths to `/workspace` or `/source` (`sandbox.py:147-156`), and writes to `/workspace` (`sandbox.py:452-456`).
  - Reads follow symlinks as uid 1000.
  - `clean_name` applies to upload and outbox names (`sandbox.py:44-49`).
  - `capture_path` checks the id is alphanumeric (`service.py:91-95`).
- **`source_dir`** is human-chosen. The only check is overlap with the home directory and the DB directory (`sandbox.py:280-282`). The bind is non-recursive (`sandbox.py:127-132`).

## 4. Process, browser, workload, CI, model/tool and IPC authority

- **Control plane holds `docker.sock`**, which is host root (`deploy/docker-compose.yml:27`).
  - The image has no USER (`deploy/Dockerfile:17`).
  - It runs the docker CLI as a subprocess for VNC, using argv lists (`sandbox_desktop.py:131-144`, `desktop_ws.py:20-28`).
- **Container flags** (`sandbox.py:243-265`): `network_mode=none`, `cap_drop ALL` plus 5 added caps, `no-new-privileges`, limits, `init`. There is no userns and no custom seccomp.
- **Runtime choice**: `sandbox.py:172-182`. The refusal applies only to the literal string `runc` (`cli.py:77-84`), so `io.containerd.runc.v2` set via `AGENTBOX_RUNTIME` gets past it.
- **Policy gate**: `policy.py:192-217`, `simple_programs` (`policy.py:128-161`), `has_bash_comment` (`policy.py:85-125`).
  - `default: allow` (`default_policy.yaml:10`). So `read_file`, `write_file`, `list_dir` and all GUI tools are allowed with no rule.
  - The allowlist (`default_policy.yaml:25-27`) includes programs that write: `touch`, `mkdir`, and `file -C`.
- **Approval executor**: `service.decide` (`service.py:389-428`).
  - It claims atomically (`approvals.py:82-89`), snapshots, then runs the stored agent args.
  - It runs on the shared Starlette threadpool, not `tool_pool`, and does not count against `_busy` or `_snap_locks`.
- **Browser side**:
  - Jinja autoescape plus `finalize=_shown`, which applies control and bidi escaping (`web.py:33-37,94`).
  - Anti-framing middleware (`api.py:163-180,213`).
  - There is no `script-src` CSP. noVNC is served same-origin from the desktop image (`api.py:455-463`), so container-controlled RFB is parsed in the admin origin.
- **CI** (`.github/workflows/ci.yml`): `contents: read` permission, runs on `pull_request`, no secrets, uses the gha build cache.

## 5. Privilege changes, confirmation, revocation, recovery and fallback

- **Takeover and handback**:
  - `service.py:503-543`; lease handling in `desktop.py:189-208`.
  - `_takeover_wanted` blocks new GUI calls for 60 s (`service.py:505-507,163-167`).
  - A handback without a session, sent with the human-token header, is forced (`api.py:438-441`, `service.py:532`).
  - An idle lease is reclaimed by the agent's own GUI call (`service.py:152-161`, `desktop.py:179-187`).
- **Revocation paths**:
  - Logout: `service.py:567-577`.
  - WS re-check every 30 s: `desktop_ws.py:67-80`.
  - `close_all` on delete or restore: `service.py:579-587`, `desktop.py:274-280`.
  - Leftover leases from a previous run are logged as `server_restart` (`service.py:555-565`).
- **Fail-closed audit**: `log_human` raises 503 (`service.py:590-594`). Audit is append-only through triggers (`audit.py:35-38`).
  - Some events are best-effort writes instead: tool results, `desktop_disconnect`, burst records (`service.py:366-372`).
- **AP-2 snapshots**:
  - `_needs_snapshot`, quota and `_snapshot` are at `service.py:230-265`.
  - The fail-closed burst open is at `service.py:260-264`.
  - Pending approvals are capped at 20 (`service.py:312-316`).
  - Expiry is at `service.py:375-387`.
- **Lifecycle methods** are at `service.py:444-475`. Since the refactor, `api.py` and `web.py` both call them inside `guard`.
- **Uncaught failure in restore**: in `sandbox.restore` (`sandbox.py:387-401`), the old container is removed first. An `APIError` from `_run_container` is not caught there, so the record points at a container that no longer exists and the response is a 500.

## 6. Source-visible controls versus deployment facts

- **Visible in source**: everything above.
- **Depends on deployment**:
  - Strength of the runtime (gVisor or Kata versus runc).
  - Trusted proxies: `forwarded_allow_ips` defaults to `*` (`cli.py:124-126`).
  - The proxy keeps the Host header, which `same_origin` needs (`deploy/Caddyfile:5`).
  - Port 8765 is not published (`docker-compose.yml:29-30`).
  - The path namespace is the same in the control-plane container and on the host. The `source_dir` checks `is_dir` and `overlaps` run in the container's filesystem, but the host daemon binds the host path with the same name. Only `AGENTBOX_HOME` is guaranteed to be identical.
  - The noVNC version in the desktop image.
  - Whether the human token file was created with a race-free mode: it is written, then chmod'ed (`config.py:97-99`).
  - Whether the `uvicorn agentbox.api:create_app --factory` path (`api.py:476-478`) is used. It skips the bind and runtime checks and does not force the Secure cookie flag.

## Changed since run-3 / refactor seams worth hunting

1. **TOCTOU in `GuiBursts.needs_snapshot`** (`gui_bursts.py:58`). It returns no-snapshot while a lease or a pending takeover exists, assuming `_check_control` (`service.py:152-161`) will then return 423. That check runs later, under `gui_lock`. If the human hands back, or the takeover fails (409, 503, or the audit write fails), in between, the GUI input runs with no snapshot or burst. `forget_input` (`service.py:543`) does not undo the decision already made.
2. **`AgentBox.pause_sandbox`** (`service.py:444-448`) calls `bursts.end` without holding `_snap_locks` or `gui_lock`. A concurrent GUI input can reopen a burst just before the pause. Closing it on the paused container then fails, so strays are not killed.
3. **`AgentBox.restore_sandbox`** (`service.py:462-469`) runs `end_desktop` before `sandboxes.restore` validates `snap_id`. It also does not catch `APIError` after removing the container.
4. **`desktop_ws.relay`** (`desktop_ws.py:18-101`) assumes the route has already done authentication. It calls the blocking `vnc_command`, docker lookups and SQLite on the event loop. It does not re-check the lease for view connections.
5. **`SandboxManager._expand` and `_walk`** (`sandbox.py:557-569`), which `preview.py` calls on agent input, have no `_timed` and no output cap. `list_dir` and `outbox_list` (`sandbox.py:425-432,525-535`) are also unbounded. `preview_command` assumes the caller bounds these.
6. **`DesktopTools.screenshot` and `_x`** (`sandbox_desktop.py:45-50,84-92`) buffer the full `exec_run` output for up to 15 s.
   - Possible chain: a uid-1001 symlink at `~/.cache/agentbox-shot.png` pointing to `/dev/zero` could exhaust control-plane memory. The same path also runs inside `_capture` during approval requests.
   - `struct.unpack` raises a non-`SandboxError` exception when the PNG is short.
7. **`service.decide`** (`service.py:389-428`) runs approved tools outside `tool_pool`, `_busy` and `_snap_locks`.
8. **Unauthenticated, unbounded audit growth** through `web.login` (`web.py:134-138`), plus the unauthenticated Docker `containers.create` reached via `api.novnc` → `extract_novnc`.
9. **`desktop.redeem` / `session_scope`**: the scope namespace shared between `*` and sids, and the new `gen` purge (`desktop.py:99-105,118-160`). Worth revalidating against the run-3 rejected claim.
10. **`DesktopTools.kill_processes` and `gui_strays`** (`sandbox_desktop.py:64-67`, `gui_state.py:53-89`). The `ps` parsing moved modules; the N-1 partial mitigation is unchanged in substance.
