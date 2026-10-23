## recon-1a report: product, stack, and local operation (run-4, tree 9805d91)

**Scope.** I read the source only, from `/tmp/claude-0/-home-user-agentbox/bc796aa2-37b4-5f3d-a870-3de255943f83/scratchpad/src-audited/`. I wrote nothing, ran no target code, and used neither the network nor Docker. The tree descends from 8e4db9e. Since then, 16 files under `agentbox/`, `images/` and `deploy/` changed (+1033/−592). New files: `desktop_ws.py`, `display.py`, `gui_bursts.py`, `gui_state.py`, `preview.py`, `sandbox_common.py`, `sandbox_desktop.py`.

### 1. Product, users, operators, trust-sensitive actions

The run-3 summary is confirmed. agentbox is a FastAPI + SQLite control plane. It runs agent tools in Docker sandboxes, puts risky calls behind human approval, and keeps a hash-chained audit log (`service.py:1-9`, `audit.py:1-7`).

**Principals**
- **Human token `hum_…`**
  - Comes from env, or is generated once into `home/human_token` with mode 0600 (`config.py:88-100`).
  - Compared with `compare_digest` (`api.py:115-124`). `human_only` is at `api.py:126-129`.
- **Browser session cookie**
  - HttpOnly, SameSite=Strict, Secure behind TLS (`desktop.py:58-60`).
  - Stored as SHA-256 with a `scope` and a token fingerprint `gen` (pbkdf2) (`desktop.py:34-42,53-55,148-167`).
  - Public id is `hs_`+32 bits (`desktop.py:133`).
  - Guards: `screen_human` needs scope `*` (`api.py:149-155`); `desktop_human` accepts `*` or the matching sid (`api.py:157-163`).
  - `same_origin` lets requests with no Origin header through (`api.py:131-133`).
- **Tickets**: `tkt_`, 60 s, one-time, scope = sid or `*` (`desktop.py:111-128`). Issued by `api.py:301-306` (per sandbox) and `web.py:153-156` (UI).
- **Agent token `agt_…`**
  - One per sandbox, stored as a hash (`sandbox.py:218-223,290`).
  - Can call tools on its own sandbox (`api.py:215-221`), read its own sandbox (`api.py:183-187`), read its own approval with a reduced field set (`api.py:236-240`), and read desktop state (`api.py:325-330`).
  - Trying to approve is logged and returns 403 (`api.py:251-259`).
- **In-container code**
  - uid 1000 runs exec and the file tools (`sandbox.py:34,411-412`).
  - uid 1001 `desktop` runs the X session and GUI tools, and is in the agent group (`images/desktop/Dockerfile:15,96`; `sandbox_desktop.py:30-31,45-47`).
  - Container output is parsed by `_parse_outbox` (`sandbox.py:103-124`), `_parse_manifest` and `_parse_ps` (`gui_state.py:17-50`), and `desktop_processes` (`sandbox_desktop.py:52-62`).

**Trust-sensitive actions**
- Approve/deny (`service.py:389-428`), with an atomic `claim` (`approvals.py:332-339`).
- Create, pause, resume, snapshot, restore and delete a sandbox (`service.py:431-475`).
- File import and export (`service.py:478-500`).
- Desktop takeover and handback (`service.py:503-543`).
- Login and logout (`web.py:122-151`).

### 2. Languages, frameworks, runtimes, deployment

- **Stack**: Python ≥3.11; fastapi, uvicorn, websockets, jinja2, python-multipart, docker, httpx, pyyaml, mcp; setuptools build (`pyproject.toml`). Entry scripts are `agentbox = agentbox.cli:main` and `agentbox-mcp`.
- **Deployment modes**
  - `agentbox serve`, which binds 127.0.0.1 by default (`cli.py:387`).
  - `bind_problem` refuses a non-loopback bind without TLS, a proxy flag, or `--insecure` (`cli.py:68-74,92-100`).
  - `runtime_problem` refuses only the literal `"runc"` when the server is exposed, unless `--allow-runc` / `AGENTBOX_ALLOW_RUNC` is set (`cli.py:77-111`).
  - Behind a proxy, uvicorn trusts forwarded headers from `AGENTBOX_TRUSTED_PROXIES`, default `"*"` (`cli.py:124-126`).
  - The bare `create_app()` factory skips all of these checks (`api.py:376-378`).
  - Compose: Caddy plus a control-plane container that mounts `docker.sock` and listens on 0.0.0.0 with `--behind-tls-proxy` (`deploy/docker-compose.yml:24-51`, `deploy/Dockerfile:23`).
- **Runtime selection** prefers kata-fc, then kata-qemu-firecracker, then runsc, then runc (`sandbox.py:73,172-182`).
- **Container flags**
  - `network_mode=none`; non-recursive read-only `/source` bind.
  - `cap_drop ALL` plus CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID; `no-new-privileges`.
  - mem/cpu/pids limits; optional `storage_opt` (`sandbox.py:127-132,243-265`).
  - The desktop image resets the `desktop` home on every start; this is new (`images/desktop/agentbox-desktop-start:117-123`).
- **Settings and limits**: snapshot quota 50, GUI idle 60 s / interval 600 s, tool concurrency 4, approval timeout 300 s, upload 50 MB (`config.py:30-69`). Other limits: `PENDING_APPROVALS_MAX=20` (`service.py:44`); audit argument cap of 64 KB, keeping the first 16 KB (`service.py:37-38,180-194`).

### 3. Entry points and subsystem boundaries

- **HTTP JSON API** (`api.py:174-371`). `/static/novnc/{path}` and `/healthz` need no authentication. On an unauthenticated request, `extract_novnc` creates a container whenever the noVNC files are missing (`api.py:355-363`, `sandbox_desktop.py:146-169`).
- **Web UI**: Jinja2 with `finalize=_shown` applying `escape_controls` (`web.py:33-37,94`), htmx, and the `_NoFraming` middleware (`api.py:63-80,113`).
- **Desktop WebSocket route** (`api.py:343-353`) authenticates by cookie session, `same_origin`, mode, and `may_connect`, then calls `desktop_ws.relay` (`desktop_ws.py:18-101`).
- **Tool flow**: `call_tool` (concurrency 429, `_snap_locks`) → `_call_tool` (audit → policy → quota → approval or snapshot → `_run_tool`) (`service.py:268-364`). Tools run on a 32-thread `tool_pool` (`api.py:103,219`).
- **Policy**: allowlist `only_commands`, `has_bash_comment`, `>`/`$` gate (`policy.py:85-161,192-217`). The default policy allows `mkdir`/`touch` and allows every non-exec tool through `default: allow` (`default_policy.yaml:9-33`).
- **Preview**: `preview.preview_command` with injected `expand`/`walk` (`preview.py:66-131`). The callbacks are `sandbox.py:557-574`.
- **GUI bursts**: `GuiBursts` (`gui_bursts.py:23-169`) with pure helpers in `gui_state.py`.
- **Other entry points**: MCP stdio server (`mcp_server.py`), LLM loop (`agent.py`), CLI (`cli.py:382-458`).

### 4. Offline build and test commands (not run)

- **Install**: `pip install -e '.[test]'` (`.github/workflows/ci.yml:30`). It needs a package index unless the dependencies are already installed; locally all ten are importable.
- **Docker-free unit tests**: `python -m pytest -q tests/test_unit.py tests/test_m2_unit.py tests/test_m4_unit.py` (`ci.yml:31`), with `pythonpath = .` from `pytest.ini`.
  - Writes: pytest `tmp_path` (SQLite DBs), `.pytest_cache/` and `__pycache__/` in the tree.
  - Inputs: hard-coded policy strings, a fake `ps`/manifest/outbox byte stream, the default policy (`tests/test_m2_unit.py:110-130,204-230`).
- **Full suite**: `python -m pytest -q -rs`. The acceptance tests (`test_acceptance.py`, `test_m2/m3/m4_acceptance.py`, `test_agent.py`) skip when there is no Docker daemon (`tests/test_acceptance.py:16-20`).
  - They set `AGENTBOX_HOME=tmp_path/data` (`tests/test_acceptance.py:28`), but they still create containers and snapshot images on the host daemon.
  - The desktop tests also need the `agentbox-desktop:0.1` image (`tests/test_m2_acceptance.py:33`).
- **Image build**: `docker build -t agentbox-desktop:0.1 images/desktop` (`images/desktop/Dockerfile:3`) needs apt and the network.
- **Default write location at runtime**: `./data`, relative to the current directory (`config.py:29`). It holds `agentbox.db`, `human_token`, `captures/`, `novnc/` and `sources/<sid>`.

### 5. Comparable software

No comparable product is source-grounded. The visible components are MCP via FastMCP/MCPServer (`mcp_server.py:28-33`), RFB through x11vnc `-inetd` + socat + noVNC (`sandbox_desktop.py:131-144`), and gVisor/Kata named as runtimes (`sandbox.py:73`; `README.md:27-46`).

### 6. Local limits on execution

- Python 3.13.16 and all dependencies are importable. `/usr/bin/docker` and `/var/run/docker.sock` exist on this host, but the brief forbids using the Docker daemon, so the acceptance tests and live app checks need a parent with Docker access.
- I could not confirm locally which runtimes the daemon has, whether gVisor is present, or whether the image is built (run-3 recorded runc only).

### Changed since run-3 / refactor seams worth hunting

1. **`AgentBox.delete_sandbox`** (`service.py:471-475`) runs log → `end_desktop` → `sandboxes.delete` → `drop_captures`. It never expires or finishes the sandbox's pending approvals. Separately, `end_desktop` ignores a failed `handback` (`service.py:583-587`), and `DesktopControl.close_all` (`desktop.py:274-280`) then removes the lease without writing a `human_handback` record.
2. **`pause_sandbox`, `restore_sandbox` and `delete_sandbox` now run `bursts.end`/`close`** synchronously, as docker exec calls on the human request thread (`service.py:444-475`, `gui_bursts.py:100-111,157-162`). The same happens in `takeover`, under `gui_lock` (`service.py:514`). This partly reopens the v11 concern about unrelated threads blocking on a stuck container.
3. **`restore_sandbox` holds no `gui_lock` or `_snap_locks`** between `end_desktop` and `sandboxes.restore` (`service.py:462-469`). A tool call that is already running can open a burst on the old container. The only guard is `GuiBursts._finish`'s `container_id` check (`gui_bursts.py:113-119`).
4. **Shared-lock coupling in `GuiBursts`.** It shares `AgentBox._busy_lock` and receives `_takeover_pending` as a callback (`service.py:89`). It also mutates `_gui_input_at`/`_gui_snap_at` without a lock (`gui_bursts.py:43-50,164-166`). `close_idle` treats a missing input time as idle (`gui_bursts.py:144`), and `forget_input` on handback triggers exactly that.
5. **`AgentBox._snapshot` fail-closed (d915713)** (`service.py:250-265`). It is reached from the allow path, from `decide` (no `_snap_locks`, no concurrency cap, `service.py:411-418`) and from `import_file` with `tool=None` (`service.py:487`).
6. **`desktop_ws.relay` assumes the caller already checked authentication** (`desktop_ws.py:1-4,18-101`). `session_watch` re-checks only the cookie session every 30 s. It does not re-check whether the sandbox still exists or the lease state for view connections. The route's `same_origin` accepts a missing Origin (`api.py:347`).
7. **`DesktopTools` mixin** (`sandbox_desktop.py:39-62`) relies on the host class's `_require_running`/`template_of`. `kill_processes` runs as the `desktop` user and the pid list comes from `gui_strays`, which parses container-controlled `ps` output (`gui_state.py:52-89`).
8. **`SandboxManager.preview` uses `_container`, not `_require_running`.** Its `_expand`/`_walk` callbacks have no `_timed` deadline (`sandbox.py:557-574`). The same is true of `exists`, `is_dir`, `list_dir` and `outbox_list` (`sandbox.py:425-535`). All of these run in tool or human threads.
9. **`display.escape_controls`** is now the single filter for both `cli._safe` and `web._shown` (`display.py:13-21`, `cli.py:33-35`, `web.py:33-37`). Worth checking whether every container-derived string reaches it, for example `_short` truncation inside `describe` (`web.py:40-84`), and that no template bypasses it.
10. **Unauthenticated `/static/novnc/{path}`** calls `extract_novnc`, which creates a Docker container per request while the image or files are missing, then runs `tarfile.extractall(filter="data")` (`api.py:355-363`, `sandbox_desktop.py:146-169`). Also, `GET /ui/verify` writes an audit row as a side effect of a GET (`web.py:271-280`).
