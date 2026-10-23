## recon-1d: local execution and deployment visibility (run-4, `9805d91`)

All paths are relative to the src-audited worktree. I wrote no files, ran no target code and did not touch the network or the Docker daemon. On the host I only ran tool and package probes (`command -v`, `python3 -s -c import …`).

### 1. Offline tests and fixtures usable inside `tools/sbx`

- **CI's Docker-free set** (`.github/workflows/ci.yml:32`): `tests/test_unit.py`, `tests/test_m2_unit.py`, `tests/test_m4_unit.py`. Suggested command: `sbx <id> python3 -m pytest -q -p no:cacheprovider --rootdir /target /target/tests/test_unit.py …`. `pytest.ini:3` sets `pythonpath=.`, and `-p no:cacheprovider` is needed because `/target` is read-only.
- **Trust-boundary fixtures that are already there:**
  - Policy lexer and bash-comment tests: `test_unit.py:30-46,146-230`.
  - Hash chain, tamper and masking: `test_unit.py:47-100,263-316`.
  - Outbox parser against hostile names: `test_unit.py:179-210`.
  - `gui_strays` with a synthetic ps table: `test_unit.py:318`.
  - Terminal control-character escaping: `test_unit.py:232`, `:347`.
  - Fake `_Sandboxes` and `_Audit` that drive `GuiBursts`/`AgentBox` with no Docker: `test_m2_unit.py:89-136`.
  - Fake container for the `_x` / manifest / ps deadline: `test_m2_unit.py:203-229`.
  - `DesktopControl` tickets, sessions, scope and leases on a `tmp_path` SQLite: `test_m2_unit.py:14-58`, `test_m4_unit.py:13-118`.
  - `bind_problem` / `runtime_problem` / `is_loopback`: `test_m4_unit.py:122-168`.
- **Pure-function seams that can take new harnesses:** `preview.preview_command(command, limit, expand, walk)` with stub callables (`preview.py:67`); `gui_state._parse_manifest`/`diff_manifest`/`_parse_ps`/`gui_strays` (`gui_state.py:17-89`); `display.escape_controls`; `policy.decide`; `sandbox.safe_path`/`clean_name`/`_parse_outbox`/`overlaps`.
- **sbx caveat:** `jinja2` and `markupsafe` exist only in `/root/.local`, which is not mounted, and sbx sets `PYTHONNOUSERSITE=1`. So `agentbox.web`, and through it `agentbox.api` and `agentbox.desktop_ws`, cannot be imported inside sbx. `conftest.py:8-12` tolerates this. Everything else is importable from host `/usr`: fastapi, starlette, docker, httpx, mcp 2.3.0, uvicorn, websockets and multipart from `/usr/local/lib/python3.13/dist-packages`, and yaml from `/usr/lib/python3/dist-packages`.
- `test_m4_unit.py:189-203` (`sudo -n mount --bind`) skips inside sbx. It must not run outside sbx (see item 3).

### 2. Processes that can run on an isolated loopback (sbx `--network none` keeps `lo`)

- `agentbox.mcp_server` (stdio): talks to `AGENTBOX_URL` (`mcp_server.py:37-40`). It can be pointed at a stub HTTP server on 127.0.0.1 inside the same sbx.
- The `agentbox.agent` loop: set `AGENTBOX_LLM_BASE_URL` to a loopback stub (`agent.py:144-149`). `ToolClient` goes to a stub control plane.
- `api.build` cannot run without the Docker daemon, because `SandboxManager.__init__` calls `docker.from_env()` and `client.info()` (`sandbox.py:162,173`). It also needs jinja2. Two ways forward: parent-live, or a monkeypatched fake `SandboxManager` plus jinja2 mounted read-only.
- The real control plane, desktop WS relay (`docker exec` via the CLI, `sandbox_desktop.py:285-298`) and `extract_novnc` (`sandbox_desktop.py:306`) all need `docker.sock`, so they are parent-live only.

### 3. Prohibited for this run

- Dependency fetches:
  - `pip install -e '.[test]'` / `pip install .` (`ci.yml:31,46`; `deploy/Dockerfile:12`).
  - `docker pull buildpack-deps:noble-curl` (`ci.yml:47`).
  - `docker build images/desktop`, which runs `apt-get update` (`images/desktop/Dockerfile:17`).
  - `docker compose up --build`, which pulls `docker:27-cli`, `python:3.13-slim` and `caddy:2` (`deploy/Dockerfile:5,7`; `docker-compose.yml:33`).
- Publishing and shared state:
  - `docker/build-push-action` with the gha cache (`ci.yml:50-56`).
  - Caddy ACME certificate issuance and binding host 80/443 (`docker-compose.yml:37-40`; `Caddyfile:4`).
  - git push / gh.
- Paid provider APIs: `agentbox agent`, whose defaults are `https://api.openai.com/v1` and `https://api.anthropic.com` and which reads `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` (`agent.py:145-148`; `cli.py:346-349`).
- Docker daemon and host state:
  - `agentbox serve|create|delete|restore|snapshots`, `uvicorn agentbox.api:create_app --factory` (`api.py:376`), and every acceptance test (`test_acceptance.py`, `test_m2/m3/m4_acceptance.py`, `test_agent.py`). These create containers and `agentbox-snap` images; `test_acceptance.py:281-289` also spawns `serve`.
  - The bind-mount tests that edit the host mount table: `test_m4_unit.py:189-203`, `test_m4_acceptance.py:191-216`.
- `demo/run_demo.sh`: it runs `rm -rf "$AGENTBOX_HOME"` using an inherited `AGENTBOX_HOME` (`run_demo.sh:16,36`), then starts a server and containers.
- Side writes: any CLI call made without `AGENTBOX_HOME` writes `./data/human_token` into the cwd (`config.py:29,93-99`), and `create --env-file` writes a file (`cli.py:156-159`).

### 4. Deployed controls that source cannot establish (needs_validation if decisive)

- **Which runtime actually runs.** Selection order is `_RUNTIME_PREFERENCE` (`sandbox.py:73,172-182`), overridable by `AGENTBOX_RUNTIME`. Source cannot show that a runtime named `runsc`/`kata-*` really is gVisor or Kata. `runtime_problem` only rejects the literal `"runc"` (`cli.py:80`), so `AGENTBOX_RUNTIME=io.containerd.runc.v2`, which exists on this host, passes the exposed-mode check.
- **Daemon-side hardening:** seccomp/AppArmor profile, userns-remap, cgroup v1 vs v2 memory/pids enforcement, and the xfs+pquota storage behind `storage_opt` (`sandbox.py:263-264`). With `AGENTBOX_DISK` empty, the writable layer and `docker commit` growth have no disk cap.
- **Proxy trust.** Caddy's handling of client-supplied `X-Forwarded-*` and `Host`. uvicorn 0.54 runs with `forwarded_allow_ips="*"` (`cli.py:126`). Whether port 8765 is reachable from anything other than Caddy (`expose`, `docker-compose.yml:29-30`).
- **Factory path:** uvicorn's own proxy-header defaults under `create_app`.
- **Desktop image contents:** unpinned apt versions of x11vnc, xdotool and socat (`images/desktop/Dockerfile:17-23`) and the behaviour of `x11vnc -viewonly`.
- **Python version:** `tarfile` `filter="data"` (`sandbox_desktop.py:320`) needs Python ≥3.11.4, but `requires-python` is only `>=3.11` (`pyproject.toml:7`).
- **Data-dir same-path mount and host file permissions:** `human_token` is written, then chmodded (`config.py:98-99`).

### 5. Final active source path per mode (where the repo fixes it)

- **`agentbox serve`** (console script `pyproject.toml:24`, or `__main__.py`): `cli.main` (`cli.py:382`) → `cmd_serve` (`cli.py:87-127`) → `api.build` (`api.py:83-373`) → `uvicorn.run`. Defaults are 127.0.0.1:8765 (`cli.py:387-388`). The `bind_problem` gate is at `:96-98` and the `runtime_problem` gate at `:104-109`.
- **Compose:** `deploy/Dockerfile:17` runs `serve --host 0.0.0.0 --behind-tls-proxy`, and `AGENTBOX_BEHIND_TLS_PROXY=1` is also set (`docker-compose.yml:22`). The effects are:
  - `secure_cookie` is forced on (`cli.py:102`).
  - `proxy_headers` uses `AGENTBOX_TRUSTED_PROXIES`, which compose does not set, so it is `"*"`.
  - The runc refusal applies unless `AGENTBOX_ALLOW_RUNC` is set (`:25`).
  - The code that runs is a pip-installed copy of `agentbox/` (`Dockerfile:12`), not `/src`.
  - Caddy forwards with `reverse_proxy agentbox:8765`.
- **Bare factory:** `api.create_app` (`api.py:376-378`) skips both serve-time gates. `secure_cookie` then comes only from the environment (`config.py:69`).
- **MCP:** `mcp_server:main` (`:168`). Which server class it uses depends on the installed SDK (`:28-33`), so the repo does not fix this mode. Locally mcp 2.3.0 selects `MCPServer`.
- **Demo:** `PYTHONPATH=$ROOT`, so it runs repo source, with `AGENTBOX_POLICY=demo/policy.yaml` (`run_demo.sh:19-20,38`).

### 6. Can the local platform enforce the required sandbox?

`tools/sbx` (`docker run`, lines 30-55) covers most of it:

- **Covered:**
  - Empty, allowlisted environment (`-e` only).
  - `--network none`.
  - `--read-only` root, with `/usr` and `/target` mounted read-only.
  - Uid 65534, `cap-drop ALL`, no-new-privileges.
  - 512m memory with no swap, 1 CPU, 64 pids, 32 MiB file size, 256 open files.
  - Wall clock: 120 s inside the container, 140 s on the client, then `docker rm -f`.
- **Gaps:**
  - **No cumulative disk limit.** `/scratch` is a bind mount on host ext4 with about 29 GB free. Only per-file size is capped.
  - `/dev/shm` (64 MiB tmpfs by default) and `/dev/mqueue` stay writable outside `/scratch`.
  - There is no `--pull never`. If `ubuntu:24.04` is not already on the host, the daemon will fetch it over the network.
  - `agents/<id>/scratch` does not exist yet for any agent, so sbx refuses to start (`:21-26`).

Host tools: `unshare`, `prlimit`, `systemd-run`, `setpriv` and `timeout` are present; `bwrap`, `nsjail` and `runsc` are missing. The host is cgroup v1 and runs as root.

**Verdict:** target-controlled execution is blocked on the disk limit until the parent adds one. Options are a size-capped tmpfs scratch charged to the memory cgroup, or a quota'd or loop-mounted scratch filesystem. The parent should also add `--pull never` and a `--tmpfs /dev/shm:size=…` cap, or note that they are accepted.

### 7. Parent-side promotion

`run-metadata.json` says "Promotion uses tools/promote.py", but `docs/security-audit/run-4/tools/` contains only `sbx`. None of the required controls exist:

- path-confined, no-follow descriptor traversal (`openat` with `O_NOFOLLOW`)
- `O_NONBLOCK` plus `fstat` to confirm a regular file
- no-follow traversal of every destination parent
- `O_CREAT|O_EXCL` destination creation
- per-file and cumulative size caps

Scratch files cannot be used as evidence until this exists. Until then, evidence must be sbx stdout captured by the parent.

### Changed since run-3 / refactor seams worth hunting

1. **`desktop_ws.relay`** (`desktop_ws.py:18-101`) assumes the caller already checked the session, origin and `may_connect` (`api.py:343-353`). `same_origin` still accepts a missing `Origin` (`api.py:131-133`). The session is only re-checked every `recheck` seconds.
2. **`AgentBox.pause_sandbox`** (`service.py:444-448`) runs `bursts.end` and then `pause` without holding `_snap_locks`. Unlike restore and delete, it does not call `end_desktop`, so takeovers and connections survive the pause.
3. **`restore_sandbox`/`delete_sandbox` vs `call_tool`** (`service.py:462-475` vs `:281-284`): the lifecycle ops do not take the per-sandbox snapshot lock. A concurrent `_snapshot`/`bursts.open` can bind a burst to the replaced container. `SandboxManager.restore` (`sandbox.py:387-401`) removes the old container before the new one is created.
4. **`preview_command`, `_expand`, `_walk`** (`preview.py:88-115`; `sandbox.py:557-569`): one `docker exec` per operand, uncapped, with no `_timed` and unbounded `exec_run` output. They run in `_call_tool` before the approval exists (`service.py:318`).
5. **`outbox_list`, `list_dir`, `exists`, `is_dir`** (`sandbox.py:425-535`): no container-side timeout and fully buffered output. Compare `_Head` in `exec`.
6. **`GuiBursts.close_idle`/`_finish` and `gui_strays.from_exec`** (`gui_bursts.py:113-155`; `gui_state.py:58-65`): processes descended from a ppid-0 exec are exempt from the stray kill.
7. **`DesktopTools.extract_novnc`** (`sandbox_desktop.py:300-323`): no lock against concurrent extraction, the whole archive is held in memory, and the Python-version dependency on `filter=` noted in item 4 applies.
8. **`runtime_problem` / `_detect_runtime`** (`cli.py:77-84`; `sandbox.py:172-182`): only the literal `"runc"` is rejected, and unknown runtimes fall back to runc.
9. **`create_app` factory path and compose `forwarded_allow_ips="*"`** (`api.py:376`; `cli.py:126`): the factory skips the serve-time gates, and compose trusts proxy headers from any address.
10. **`Settings.human_token` and `cmd_create --env-file`** (`config.py:98-99`; `cli.py:157-159`): the secret is written before the chmod, so it exists briefly with umask permissions.
