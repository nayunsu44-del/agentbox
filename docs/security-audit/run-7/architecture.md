# agentbox architecture summary (run-7)

Source ref: `3580df0` (`main`, after PR #26 merge). Profile `standard`, focused follow-up on the delta `530b29e..3580df0`, owner budget 15 subagent invocations. No reconnaissance agent was spent: the parent read the full diff of the six non-merge commits (`7dbda9e`, `5bb3c17`, `d4e956e`, `79d8211`, `ccaf367`, `a0a186c`). **Line numbers in section 0 are exact at `3580df0`. Section 1 is the run-6 delta (`530b29e` numbers). Sections 2-6 are the run-4/run-6 baseline and only describe code the delta did not change.**

## 0. Run-7 delta `530b29e..3580df0` (exact line numbers at `3580df0`)

### 0.1 `7dbda9e` — fixes for run-6 F1-F3 and hardening N1-N3 (not audited before this run)

- **F1 GUI burst container binding (`gui_bursts.py`, `service.py`).** `GuiBursts.covers(sid)` (`gui_bursts.py:72-83`) returns `True` when `gui_snapshot_interval <= 0`; otherwise `False` if no burst, else `burst.get("container_id") == self.sandboxes.get(sid)["container_id"]` (any exception → `False`). `restore_sandbox` (`service.py:625-635`) now calls `self.bursts.end(sid, "sandbox_restored")` after `self.sandboxes.restore` (`service.py:630`; `end` = `close` + `reset_timers`, `gui_bursts.py:186-195`). `restore_sandbox` holds `_lifecycle(sid)`; `call_tool`/`_snapshot` do not.
- **F2 audit index and batched verify (`audit.py`).** `CREATE INDEX IF NOT EXISTS idx_audit_sandbox_id ON audit (sandbox_id, id)` (`audit.py:38`). `_VERIFY_BATCH = 200` (`audit.py:337`). `_verify_live(anchor, prev, expected, total)` (`audit.py:339-369`) loops: under `self._lock` re-reads `latest_anchor` (returns `None` if it changed) and fetches the next 200 rows `WHERE id > cursor`, then runs `check_chain` outside the lock. `verify()` (`audit.py:371-379`) retries forever while `_verify_live` returns `None`. `verify_archives()` (`audit.py:381-`) checks archives, then calls `_verify_live` once and fails if the anchor changed.
- **F3 preview braces/tilde (`preview.py`, `sandbox.py`).** `preview_command` adds a note when the command contains `$`, `` ` ``, `<(`, `eval `, `{` or `~` (`preview.py:88-89`); an unmatched `rm` operand with `{…}` or a leading `~` shows `삭제 시도 (중괄호·틸드 확장 — 명령 원문 확인)` (`preview.py:111-114`). `_expand(c, pattern, limit)` (`sandbox.py:600-610`) runs dash `sh -c` with `case "$1" in "~") pat="$HOME";; "~/"*) pat="$HOME/${1#~/}";; *) pat="$1";; esac; for p in $pat; …| head -z -n "$2"` and `limit+1`. Execution still uses `bash -c` (`sandbox.py:437-451`).
- **N1 origin scheme and HSTS (`api.py`, `web.py`, `deploy/Caddyfile`).** `secure_cookie(request)` (`api.py:221-223`) = `settings.secure_cookie or request.url.scheme in ("https","wss")`. `same_origin(req_or_headers)` (`api.py:225-235`): empty/missing `Origin` → `True`; `netloc != Host` → `False`; if `secure_cookie(...)` and `Origin` scheme is not `https` → `False`. Callers pass the request/WebSocket (`api.py:244`, `api.py:454`, `web.py:177`, `web.py:187`). `cli.py:102` sets `secure_cookie` when `--tls-*` or `--behind-tls-proxy`. `deploy/Caddyfile:8` adds `Strict-Transport-Security "max-age=31536000"`.
- **N2 container output caps (`sandbox.py`, `sandbox_desktop.py`).** New `_exec_head(c, argv, user, workdir)` (`sandbox.py:422-435`) streams with `exec_create`/`exec_start(stream=True, demux=True)` into two `_Head` buffers, falling back to `c.exec_run` + `_truncate` when `client.api` is absent. `exec` (`sandbox.py:437-451`) and `list_dir` (`sandbox.py:453-461`, now `_timed(_READ_TIMEOUT, "ls","-la","--",p)`) use it. `outbox_list` (`sandbox.py:564-574`) pipes `find … -printf '%s\t%T@\t%f\0' | head -c _OUTBOX_CAP` (512 KiB, `sandbox.py:41`) under `_timed(_READ_TIMEOUT)`; `_parse_outbox` (`sandbox.py:110-133`) skips malformed records. `screenshot` (`sandbox_desktop.py:113-123`) runs `mkdir -p dirname && rm -f SHOT && scrot -o -z SHOT && [ -f SHOT ] && [ ! -L SHOT ] && head -c 16MiB+1 SHOT` as the `desktop` user and rejects output over `_SHOT_MAX` (`sandbox_desktop.py:37`).
- **N3 Docker data root (`sandbox.py`, `service.py`).** `_detect_runtime` stores `self.docker_root = Path(info["DockerRootDir"])` (`sandbox.py:179-183`). `disk_low()` (`service.py:461-485`) takes `min(free(db_path.parent), free(docker_root))`; `OSError` on `docker_root` is ignored (the path is the daemon's path and may not exist, or may be a different filesystem, inside the control-plane container).

### 0.2 `5bb3c17` — refactor ("no behaviour change" claim to verify)

- `GuiBursts.human_active(sid)` (`gui_bursts.py:55-57`) = `(desktop.lease(sid) and not desktop.is_stale(sid)) or self._takeover_pending(sid)`; `_takeover_pending` is `AgentBox._takeover_pending` passed into the constructor (`service.py:99`, `gui_bursts.py:24-30`). Used by `needs_snapshot` (`gui_bursts.py:59-`) and `decide` (`service.py:545`), replacing two inline copies.
- `_request_approval(sid, tool, args, actor, req_id, decision)` (`service.py:413-449`) is the former inline `REQUIRE_APPROVAL` branch of `_call_tool`: pending cap (20) → `_preview` (exceptions become a note) → `bound_payload(preview)` → agent `disk_low()` recheck (507) → `_capture` → `approvals.create` → capture file write → `approval_requested` audit (on `AuditWriteError`: claim FAILED, drop capture, 503).
- Test doubles moved to `tests/conftest.py`; `tests/test_m2_unit.py` and `tests/test_m5_unit.py` reuse them.
- Unchanged and relevant: `_check_control` (`service.py:173-182`, called with `gui_lock` held), `_gui_locked` (`service.py:190-198`), `_snapshot` (`service.py:300-326`), `call_tool` (`service.py:329-352`, `_snap_locks` for `SNAPSHOT_TOOLS`), `_call_tool` (`service.py:354-411`), `decide` (`service.py:520-575`).

### 0.3 `d4e956e`, `79d8211`, `ccaf367`, `a0a186c` — IF-1 agent instruction files

- **New module `agentbox/instruction_files.py` (imports nothing from agentbox).**
  - `_NAMES` (`:27-40`, lower-case file names: `claude.md`, `claude.local.md`, `agents.md`, `agents.override.md`, `agent.md`, `gemini.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.goosehints`, `copilot-instructions.md`, `.mcp.json`), `_DIRS` (`:43-52`: `.claude`, `.cursor`, `.windsurf`, `.clinerules`, `.continue`, `.gemini`, `.codex`, `.roo`), `_GITHUB_DIRS` (`:55`: `instructions`, `prompts`, `chatmodes` under `.github`).
  - `_norm(name)` (`:66-76`): `unicodedata.normalize("NFKC", name).casefold()`, then `split(":", 1)[0]`, then `rstrip(". ")`.
  - `_parts(path)` (`:79-92`): `posixpath.normpath(raw.strip())`, `PurePosixPath(...).parts` minus `/`, each part split on `\`, each piece `_norm`ed; empty, `.` and `..` pieces dropped (backslash `..` is never resolved).
  - `kind(path)` (`:95-108`): last part in `_NAMES`, or any earlier part in `_DIRS`, or `.github/<_GITHUB_DIRS>/…` with at least one more part. The last part alone is never matched against `_DIRS` (so `kind("/workspace/.claude")` is `None`; `scan` calls `kind(rel + "/_")` for directories).
  - `mark_read(result)` (`:115-121`) sets `instruction_file`/`notice` from `kind(result["path"])` (the requested, `safe_path`-normalised path; no link resolution).
  - `with_notice(res, text)` (`:124-137`): if `res["notice"]`, wraps `text` in `[<notice> … 'agentbox-data <tag>' …]\n<<<agentbox-data <tag> 시작>>>\n<text>\n<<<agentbox-data <tag> 끝>>>` with `tag = secrets.token_hex(8)` redrawn while `tag in text`.
  - `paths_in_words(words)` (`:140-147`): words whose `strip("'\"")` value has a `kind`.
  - `scan(root)` (`:150-193`): DFS with `os.scandir`, `SCAN_MAX_ENTRIES=200_000`, `SCAN_MAX_HITS=200`, `SCAN_MAX_SECONDS=10.0` checked per entry inside the `scandir` iteration; unreadable dir or `is_dir` error → `complete=False`; does not follow links; instruction directories recorded once as `rel/`.
- **Service (`service.py`).**
  - `_run_tool` (`service.py:133-147`): `exec` result gets `instruction_files` + `notice` when `IF.paths_in_words(command_words(command))` hits (no boundary wrapping); `read_file` result goes through `IF.mark_read`.
  - `_summary` (`service.py:218-233`) keeps `instruction_files` / `instruction_file` flags in `tool_result`.
  - `_resolved(sid, tool, args)` (`service.py:235-247`): only for `write_file`/`delete_file`; calls `SandboxManager.resolve`; any exception → `None` ("judge by the requested path"). `_policy_args` (`service.py:249-251`) passes `{**args, "resolved_path": real}` to `policy.decide` only (`service.py:369`); stored approval args, audit args and execution use the original `args`.
  - `_preview` (`service.py:253-289`) for `write_file`/`delete_file` calls `_resolved` **a second time**, adds `{"path": real, "effect": "링크를 따라간 실제 대상"}` when `real != p`, and when `IF.kind(p) or IF.kind(real)` adds a note and `out["instruction_file"] = k` (approval card then renders the full content).
  - `create_sandbox` (`service.py:577-597`): after `sandboxes.create` and the `sandbox_created` record, runs `IF.scan(rec["source_dir"])` synchronously on the request thread (no `_lifecycle`), logs `instruction_files_found` (best effort) when there are hits or `complete` is `False`, returns `instruction_files` and `instruction_files_complete`.
  - `import_file` (`service.py:643-662`): if `IF.kind(name)`, logs `instruction_files_found` (`via: import`) and returns `instruction_file`.
  - `export_file` (`service.py:664-672`): `file_exported` record gets `instruction_file`.
  - New `AgentBox.outbox(sid)` (`service.py:674-681`): `sandboxes.outbox_list(sid)` plus `instruction_file` per name; used by `GET /sandboxes/{sid}/outbox` (`api.py:394-396`) and the UI fragment (`web.py:273-280`).
  - `FOUND_PATH_MAX = 512` and `_found_payload(via, paths, complete)` (`service.py:778-786`): `{"via", "count", "paths" (each cut to 512 chars + "…"), "complete"}`; the audit row still goes through `bound_payload`.
- **Sandbox (`sandbox.py`).** New `SandboxManager.resolve(sid, path)` (`sandbox.py:487-496`): `_require_running`, `safe_path`, `c.exec_run(_timed(_READ_TIMEOUT=30, "realpath", "-m", "--", p), user=agent)`; non-zero exit or output not starting with `/` raises `SandboxError`. `write_file` (`sandbox.py:502-515`) writes `{p}.agentbox-tmp-<hex>` in chunks then `mv -f -- tmp p`; `delete_file` (`sandbox.py:517-525`) `rm -f -- p` after `-d`/`-e` checks. `upload` uses `clean_name` (`sandbox.py:46-51`: no `/`, `\`, C0, DEL; ≤200 bytes).
- **Policy (`policy.py`, `default_policy.yaml`).** `PATH_TOOLS = {list_dir, read_file, write_file, delete_file}` (`policy.py:23`). In `Policy.decide` (`policy.py:214-254`, first matching rule wins) a rule with `match.instruction_files` matches only path tools whose `args["path"]` or `args["resolved_path"]` is a string with a `kind`; other match keys in the same rule are ignored. `command_words(command)` (`policy.py:82-84`) strips quotes and `\;&|()<>` from `_words`. Default policy is `version: 4` with rule order `rm-curl-needs-approval` → `instruction-file-write-needs-approval` (`tool: write_file`) → `delete-file-needs-approval` → `read-only-exec` (allowlist includes `mkdir`, `touch`, `realpath`, `readlink`) → `exec-needs-approval`; `default: allow`. Policy files do not check `version`.
- **Readers of results.** `agent.py:118-126` `ToolClient.call_text` and `mcp_server.py:119-125` `read_file` both return `with_notice(res, content + ("\n…(잘림)" if truncated))`; `exec` and `list_dir` results are returned without a boundary (`notice` is a JSON field of the exec result). MCP `instructions` string adds a "file contents are data" sentence (`mcp_server.py:46-52`).
- **Sinks (human-facing).**
  - Web: Jinja autoescape + `finalize=_shown` (`web.py:35-39`, `escape_controls(keep_newlines=True)` for `str` only), new filter `oneline` (`web.py:42-44`, `keep_newlines=False`). `describe()` handles `instruction_files_found` (`web.py:89-100`, `_short` collapses whitespace).
  - `_created.html:4-13` (list via `| oneline`, first 20, incomplete notice), `_outbox.html:5-10` (badge, `data-notify`/`data-text` attributes with `f.name`, `href=…{{ f.name | urlencode }}`, `download="{{ f.name }}"`), `_approvals.html:9-13` (when `a.preview.instruction_file and a.args.content is string`: full content in `<pre class="instruction-content" style="max-height:480px">`; the pending list is polled every 2 s on `index.html:25` for all sandboxes and `sandbox.html:25`), `sandbox.html:52-58` upload JS (`textContent` with `x.path` and `x.instruction_file`).
  - Download response `api.py:398-404`: `Content-Disposition: attachment; filename*=UTF-8''<quote(name)>`, `nosniff`.
  - CLI: `_safe` = `escape_controls(keep_newlines=False)` (`cli.py:33-35`); `cmd_create` prints up to 10 found paths (`cli.py:142-150`); `_show_approval` prints every content line through `_safe` when `pv["instruction_file"]` (`cli.py:208-217`).

### 0.4 Trust-boundary picture for the delta

```text
 untrusted source folder (host)            human browser / CLI
   │  IF.scan (request thread, 10 s,        ▲  _created.html | oneline, _outbox.html badge/download,
   │  200k entries, 200 hits)               │  _approvals.html full content <pre> (2 s poll), cli _safe,
   ▼                                        │  web.describe(instruction_files_found)
 create_sandbox ──► audit instruction_files_found (bound_payload, count)
   │
 agent (prompt-injected) ── tool call ──► _call_tool
   │                                        ├─ _policy_args ─► SandboxManager.resolve (realpath -m, 30 s, agent uid)
   │                                        │                   └─ failure → resolved_path absent (fail-open to requested path)
   │                                        ├─ Policy.decide v4: match.instruction_files on path | resolved_path
   │                                        ├─ _request_approval: cap → _preview (resolve again) → bound_payload → disk_low → capture → row → audit
   │                                        └─ _run_tool: write_file (tmp + mv -f, follows dir links at mv time),
   │                                                       read_file → mark_read(requested path), exec → paths_in_words notice
   ▼
 results ──► agent.py / mcp_server.py with_notice (random tag boundary) ──► LLM
 outbox ──► AgentBox.outbox() (instruction_file flag) ──► UI / JSON API / download (filename*)
```

Key questions for the delta: (a) is the target judged by policy (resolved once at decide time) the same object the later `mv`/`rm` touches, including after approval wait; (b) can `resolve()` failure be induced to fall back to the requested path; (c) does name normalisation match what downstream file systems/browsers/agents treat as the same name, without over-matching ordinary names; (d) do new sinks escape attacker-chosen names/content and stay cheap to render; (e) did the refactor or the run-6 fixes weaken any previously verified gate.

## 1. Run-6 delta (PRs #24 and #25, `530b29e` line numbers; see run-6 architecture for detail)

- `_BodyLimit` pre-read credential gate, `/login` 64 KiB anonymous cap, Caddy per-route `request_body`, compose `mem_limit`, uvicorn `limit_concurrency`.
- `DesktopControl` split `_db_lock` → `_lock`; desktop WebSocket SQLite/Docker/audit calls via threadpool; shielded disconnect logging.
- `_snapshot` opens a GUI burst only after `_check_control` under `gui_lock`; `decide` refuses approved GUI input during a lease or pending takeover.
- `TOOL_ARG_MAX` 16 KiB, `_relex_changes`, `PREVIEW_CALLS_MAX=40`, `NOTES_MAX=50`, `_PREVIEW_TIMEOUT=10`, `bound_payload(preview)` and `disk_low` recheck before pending approval rows.
- `retention.prune` keeps the archive when the anchor committed.

## 2. Product, principals, protected resources

agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.

- **Human token** `hum_…` (one shared admin secret): full JSON API. **Browser cookie session** scope `*`: full UI. **Desktop-link session** scope = one sandbox. **Agent token** `agt_…` per sandbox: tools on its own sandbox; lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools, `resolve`) and uid 1001 `desktop` (X session, GUI tools, screenshot). Every container output is attacker data to the control plane.
- **Source folder**: chosen by the human, copied to `/workspace`; its file names, links and contents are attacker data (IF-1 threat model: received folders and imported files).
- **Recipients of the outbox**: the human and the human's other coding agents, which auto-read instruction files by name.
- **Unauthenticated network clients**: `/`, `/login`, static, `/static/novnc/*`, `/healthz`, ticket redemption.

Protected resources: human approval authority; host filesystem and Docker daemon; other sandboxes; restore points; audit-log integrity; control-plane availability; and, new in IF-1, the integrity of what the human downloads from the outbox (no unapproved instruction file) and the agent's ability to tell file data from instructions.

## 3. Stack, deployment, host for this run

Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (loopback default), compose + Caddy with `--behind-tls-proxy`, bare `create_app`. Container flags: `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + a few caps, no-new-privileges, limits, default seccomp, runc on this host.

Host for this run: Kiro Web Linux sandbox (Amazon Linux 2023 kernel, cgroup2 threaded with cpuset/cpu/pids only, every tool call is a fresh sandbox, only `/projects/sandbox` persists). Docker Engine 25.0.16 is started per call in a private mount namespace (`tools/sbx.py` for agents; `.scratch/dk.sh` for parent-live). Images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1` (built from `images/desktop` at `3580df0`), `agentbox-audit-sbx:1` (ubuntu 24.04 + python3.12 + target deps). Agent-run code goes only through `tools/sbx.py` (no network, read-only `/target`, writable `/scratch`, uid 65534, 512 MiB via RLIMIT_DATA, 1 CPU via cpuset, 64 pids, 120 s). Unit-test baseline in the sandbox: 270 passed, 1 skipped, 1 failed (`test_m4_unit.py::test_overlap_sees_bind_mount_alias`, needs `sudo`; the known overlap failure, not a finding).

## 4. Entry surfaces and important paths

- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `call_tool` (agent `disk_low` 507, `close_idle`, per-sandbox concurrency 4, `_snap_locks` for snapshot tools) → `_call_tool` (16 KiB arg cap → `tool_request` audit → `policy.decide(_policy_args)` → quota → `_request_approval` or `_snapshot` → `_run_tool`) on the 32-thread `tool_pool`.
- **Approvals**: `decide`: atomic claim → `approval_decision` audit → GUI `human_active` refusal → `_snapshot` → `tool_execute` audit → `_run_tool(stored args)` (no re-resolution of links, no re-evaluation of policy).
- **Lifecycle**: pause/resume/snapshot/restore/delete serialised by `_lifecycle`.
- **GUI bursts**: `needs_snapshot` (skips when `human_active`), `open` (fail-closed baseline bound to `container_id`), `covers` (container-bound), `close`/`_finish`, `close_idle`, `end`.
- **Files**: `read_file` (`head -c`, `_timed`), `write_file` (tmp + `mv -f`), `delete_file`, `list_dir` (`_exec_head`), `resolve`, upload (`clean_name`), outbox list (`head -c 512 KiB`, `_timed`) and read.
- **Rendering**: Jinja autoescape + `finalize=_shown`; `oneline`; `_NoFraming`; CLI `_safe`.
- **Audit**: hash chain + triggers, `mask_text`, `bound_payload`; `log_human` fails closed; `log_best_effort` swallows `AuditWriteError`; batched `verify`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime |
| Agent → approval gate (exec) | `TOOL_ARG_MAX` + allowlist `simple_programs` + `_relex_changes` + `>`/`$` gate |
| Agent → approval gate (instruction-file writes) | `match.instruction_files` on requested path and `resolved_path` (one `realpath -m` at decide time); default rule only for `write_file` |
| Agent → approval gate (GUI) | none by design (README N-1); burst snapshot, `covers()` with container binding, `gui_changes`, stray kill |
| Agent → recipient agents (outbox) | outbox badge, approval for instruction-file writes, `file_exported` flag |
| Source folder → agent | `IF.scan` record and create card; `mark_read` notice + `with_notice` random boundary; exec notice by name |
| Agent → human UI/CLI | autoescape, `_shown`, `oneline`, `_safe`, `_short` |
| Agent → control-plane availability | `_BodyLimit`, `TOOL_ARG_MAX`, preview caps, `_Head`/`_exec_head`, `_OUTBOX_CAP`, `_SHOT_MAX`, snapshot quota, pending cap 20, `disk_low` (DB + Docker root) |
| Human create request → scan | `SCAN_MAX_*` limits (per entry, not per blocking `scandir` call) |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin` (scheme checked only when `secure_cookie`), HSTS in Caddy |

## 6. Out of scope (documented limitations, README "알려진 한계")

Name-only instruction-file detection and display-not-block; `exec` glob/variable reads without notice; GUI approval bypass (N-1); the LLM-provider data path; audit-log external anchor. Report them only with a new angle.
