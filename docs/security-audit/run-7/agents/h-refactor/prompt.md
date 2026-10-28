You are hunter `h-refactor` in run-7 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

# architecture.md (verbatim)

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

# Assigned coverage units

[
 {
  "coverage_id": "Behaviour%20preservation%20of%20the%205bb3c17%20refactor%3A%20GuiBursts.human_active%20%28gui_bursts.py%3A55-70%29%20used%20by%20needs_snapshot%20and%20decide%20%28service.py%3A545%29%2C%20_request_approval%20split%20out%20of%20_call_tool%20%28service.py%3A354-449%29%2C%20unchanged%20_check_control%2F_gui_locked%2F_snapshot%2Fcall_tool%20gates%20%28service.py%3A173-198%2C%20300-352%29%2C%20and%20the%20shared%20test%20doubles%20%28tests%2Fconftest.py%2C%20tests%2Ftest_m2_unit.py%2C%20tests%2Ftest_m5_unit.py%29::The%20refactor%20claims%20no%20behaviour%20change.%20Invariant%3A%20for%20every%20tool%20and%20actor%2C%20the%20approval%20order%20%28pending%20cap%20-%3E%20preview%20-%3E%20bound_payload%20-%3E%20disk_low%20recheck%20-%3E%20capture%20-%3E%20row%20-%3E%20audit%29%20and%20its%20failure%20handling%2C%20the%20arguments%20stored%2C%20previewed%2C%20logged%20and%20executed%2C%20and%20the%20GUI%20burst%20decisions%20%28needs_snapshot%2C%20decide%20refusal%20under%20a%20lease%20or%20pending%20takeover%2C%20_snapshot%20opening%20only%20after%20_check_control%20under%20gui_lock%2C%20covers%29%20are%20identical%20to%20530b29e%2B7dbda9e%2C%20and%20the%20run-3..run-6%20GUI%20and%20argument%20fixes%20still%20hold%3B%20the%20conftest%20doubles%20do%20not%20hide%20a%20regression%20the%20old%20per-file%20doubles%20would%20have%20caught.::agentbox%2Fservice.py%23_call_tool%2F_request_approval%2Fdecide%2F_snapshot%2F_check_control%20%2B%20agentbox%2Fgui_bursts.py%23human_active%2Fneeds_snapshot%20%2B%20tests%2Fconftest.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding",
  "surface": "Behaviour preservation of the 5bb3c17 refactor: GuiBursts.human_active (gui_bursts.py:55-70) used by needs_snapshot and decide (service.py:545), _request_approval split out of _call_tool (service.py:354-449), unchanged _check_control/_gui_locked/_snapshot/call_tool gates (service.py:173-198, 300-352), and the shared test doubles (tests/conftest.py, tests/test_m2_unit.py, tests/test_m5_unit.py)",
  "boundary": "The refactor claims no behaviour change. Invariant: for every tool and actor, the approval order (pending cap -> preview -> bound_payload -> disk_low recheck -> capture -> row -> audit) and its failure handling, the arguments stored, previewed, logged and executed, and the GUI burst decisions (needs_snapshot, decide refusal under a lease or pending takeover, _snapshot opening only after _check_control under gui_lock, covers) are identical to 530b29e+7dbda9e, and the run-3..run-6 GUI and argument fixes still hold; the conftest doubles do not hide a regression the old per-file doubles would have caught.",
  "subsystem": "agentbox/service.py#_call_tool/_request_approval/decide/_snapshot/_check_control + agentbox/gui_bursts.py#human_active/needs_snapshot + tests/conftest.py",
  "attack_class": "AI-AND-LLM.md#Action-confirmation and approval binding",
  "starting_paths": [
   "agentbox/service.py",
   "agentbox/gui_bursts.py",
   "agentbox/desktop.py",
   "agentbox/approvals.py",
   "agentbox/audit.py",
   "tests/conftest.py",
   "tests/test_m2_unit.py",
   "tests/test_m5_unit.py"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "AI-AND-LLM.md#Core discipline",
   "AI-AND-LLM.md#Action-confirmation and approval binding",
   "AI-AND-LLM.md#Universal moves",
   "AI-AND-LLM.md#Validation rules",
   "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy",
   "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Pending-action and user-presence confusion",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps"
  ],
  "excluded_blocks": [
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Cache, artifact, and workspace trust mixing",
    "reason": "Test doubles are reviewed only for whether they mask a behaviour change; CI trust is out of scope."
   }
  ],
  "prior_status": "new"
 }
]

## Prior-run records linked to these units (changed source: revalidate, do not assume)

Since run-6 (audited at 530b29e, all 11 units closed, nothing deferred), commit 7dbda9e fixed run-6 F1-F3 and hardening N1-N3 without an audit, 5bb3c17 refactored the GUI-control and approval-request code claiming no behaviour change, and d4e956e/79d8211/ccaf367/a0a186c added IF-1 (agent instruction files). An owner-run single-pass review of IF-1 at ccaf367 found 7 confirmed (2 Medium, 5 Low), 3 Info and 5 needs_validation items; a0a186c fixed the 7 confirmed and 2 needs_validation items (U+017F/fullwidth NFKC+casefold, NTFS `::$DATA`). Do NOT re-report those fixed root causes; report only bypass variants of the fixes and new defects the fixed code introduced. The single-pass review judged `log_best_effort` observation records as not conflicting with the fail-closed audit principle; re-report that only with new evidence. For each prior record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can. A prior rejected claim may be re-reported only with changed evidence. README 'known limitations' (name-only detection and display-not-block, exec glob/variable reads without notice, GUI approval bypass N-1, LLM-provider data path, audit external anchor) are not findings unless you bring a new angle.

- `agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease` — run-5 confirmed low: GUI burst opened during a human takeover lets the control plane kill the human's processes and charge human edits to the agent
  Root cause (run-5 wording): Burst open/close in _snapshot (service.py:261-276) is not serialized with takeover (gui_lock) and is not conditioned on the lease. GuiBursts.needs_snapshot (gui_bursts.py:61) checks the lease only before a multi-second commit, and decide (service.py:467) does not check it at all. The HumanControl handlers in call_tool (service.py:373-381) and decide (service.py:477-480) leave the burst that _snapshot just opened in _gui_burst. A baseline taken during the lease is later used for stray kill and change attribution.
- `agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention` — run-5 confirmed medium: One agent exec call writes a pending approval row about 45x its body size, getting past the PR #20 disk guard in a single step
  Root cause (run-5 wording): The disk guard is only a threshold check at call entry (service.py:282). The REQUIRE_APPROVAL branch then calls _preview (service.py:332), and preview_command appends one note per unrecognised segment with no count bound (preview.py:125). The 200-item cap at preview.py:127-128 applies only to 'affected'. approvals.create (approvals.py:56-57) stores json.dumps(args) and json.dumps(preview) unbounded. bound_payload is applied only to the audit copy (AuditLog.append) and to finished rows (_finish, service.py:406-411), never when the pending row is created. The agent request body is capped only by the global 8 MiB AGENTBOX_MAX_BODY, and there is no per-argument size limit before policy and preview.

## Parent notes

- You own one unit: the 5bb3c17 refactor. Your time box is larger than other hunters'. Read the exact refactor diff read-only with `git -C /projects/sandbox/.scratch/src-audited show 5bb3c17 -- agentbox tests` (and `git -C ... diff 530b29e 3580df0 -- agentbox/service.py agentbox/gui_bursts.py` for the combined effect with 7dbda9e and IF-1); never check out or modify the worktree. The parent's architecture section 0.2 lists the moved code.
- Compare `GuiBursts.human_active` with the two inline expressions it replaced (lease truthiness, `is_stale`, `_takeover_pending` identity: is `self._takeover_pending` in GuiBursts the same bound method as `AgentBox._takeover_pending`, evaluated at the same time?). Check that `needs_snapshot` and `decide` still refuse at the same moments, and that `_check_control` (which also hands back stale leases) is not replaced by `human_active` anywhere it mattered.
- Compare `_request_approval` with the old inline branch line by line: order, exceptions, return values, `req_id`, `actor`, what is stored vs logged; and confirm the IF-1 commits that came after (`_preview` now calls `_resolved`) did not break the order (e.g. preview now runs a container exec before the disk_low recheck).
- Check tests/conftest.py doubles: does any double now short-circuit a gate (e.g. `human_active`, `resolve`) so tests pass while production differs? Run the unit suites in the sandbox.
- A claim that needs the real desktop image or real Docker ordering goes in as needs_validation with an exact plan; the parent runs it live.

- Contract reminder: each unit's `reviewed_paths` MUST be the exact sorted set union of its `checks[*].reviewed_paths`.

# Selected attack-class blocks (verbatim)

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

<!-- AI-AND-LLM.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Prompt injection alone is not a finding. Require a code-level boundary failure: content reaches another principal's context, invokes authority the requester lacks, discloses data they cannot read, or drives a sink they cannot reach directly.
- Model output, memory, tool descriptions, and MCP responses are untrusted inputs. Point to the code that grants authority, trusts output, writes durable state, or feeds a sink.
- A guardrail prompt is not a security boundary. Count only deterministic checks, resource-scoped authorization, isolation, binding, and constrained credentials.
- State the attacker, affected principal, effective execution identity, resource, exact action, authority used, and observable impact. An intentional direct request to use the requester's existing authority is not a delegation defect merely because a model executes it.
- Authorization and action binding are separate controls. Attacker-controlled content that causes an action under an affected principal's valid authority is an action-binding failure when that principal did not intentionally request or approve the exact action.
- Classify every candidate as `confirmed` only after source evidence and bounded local validation establish the boundary and result. Use `needs_validation` when a required provider, deployment, model, renderer, or identity behavior is not observable locally.
```

<!-- AI-AND-LLM.md#Universal moves -->
## Universal moves (apply across the above)

- Draw four maps first: each execution identity, each capability, every writable context or memory source, and each output destination. Then connect the principal at the start to the authority at the end.
- Start at side-effecting tools and work backward through dispatcher, schema, confirmation, model context, retrieval, and ingestion. Start at durable memory reads and trace every writer.
- Compare direct, queued, retry, resume, batch, and delegated paths for the same action. The strongest gate must apply after arguments are final and before every side effect.

<!-- AI-AND-LLM.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the crossed boundary and observable result: attacker, affected principal or shared resource, execution identity, target, and unauthorized or unrequested action or disclosure.
2. For confused-deputy authority claims, prove the tool lacks requester-and-resource authorization and that the attacker cannot perform the same action normally. For action-binding claims, instead prove attacker-controlled content caused an action under the affected principal's authority that the principal did not intentionally request or approve. Valid generic authorization does not establish that intent.
3. For memory or retrieval claims, cite both the attacker-controlled write and the later cross-principal read or privileged decision. A shared record without a reachable consumer is not enough.
4. For action binding, establish the intentional request or normalized approved object, if any, and compare it with the object the handler uses. Confirm a locally observable unrequested action, mutation, duplicate, or authority change without extending the test into harmful execution. For schema disagreement, compare the normalized validated object with the handler's object.
5. For MCP identity claims, verify the authenticated connection, request correlation, tool namespace, and effective credential. Mark `needs_validation` if external server identity or deployment routing is required.
6. Return `confirmed` findings only with a complete source trace and meaningful result. Return `needs_validation` for a specific unresolved boundary fact and state the bounded local or owner-observed check needed to resolve it.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Pending-action and user-presence confusion -->
**Pending-action and user-presence confusion**
Notification, widget, shortcut, share sheet, biometric prompt, or deferred operation authorizes a different action than displayed, executes after expiry, or uses another profile's pending state. Bind confirmation to normalized action, resource, account, and current foreground state.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps -->
**Quota-accounting scope and reset gaps**
Accounting uses attacker-influenceable IP, route, tenant, key prefix, task ID, or other dimension, allowing one principal's work to escape its intended budget or consume another principal's allocation. Review integer overflow, distributed races, retries, reconnects, and account switching.

# Excluded blocks

- `SUPPLY-CHAIN-AND-RELEASE.md#Cache, artifact, and workspace trust mixing`: Test doubles are reviewed only for whether they mask a behaviour change; CI trust is out of scope.

# Core hunting method (verbatim)

```text
## Defensive vulnerability-finding method

Your goal is to find source-grounded security invariant failures and the smallest fix,
not to expand harm beyond the boundary result. Stay within source review and bounded local execution.
Do not contact deployed endpoints, provider APIs, registries, identity systems,
message brokers, shared services, or other users. Use local dummy data only.

READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity,
authorization, normalization, state, derived copies, and the final sink. Read sibling,
legacy, batch, retry, cancellation, migration, and error paths that produce the same
effect. Compare sibling controls for equivalence, not only presence, and compare what
one component guarantees with what the next component assumes.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest affected dummy record, wrong return value, process-integrity
   effect, or locally observable shared-resource effect.
6. State a source-level change and regression case that enforce the invariant.

DEPTH BOUND: trace only paths that can reach your assigned boundary or whose
guarantees that boundary relies on. Stop a line of investigation as soon as the
invariant is settled either way, and record the result in your structured output —
a covered, candidate, or blocked disposition, or an `uncovered` entry — instead of
continuing to search.

TEST SAD PATHS AND DISAGREEMENTS. Check absent, empty, zero, negative, maximum,
over-limit, duplicate, mixed encoding, stale, revoked, reordered, concurrent,
partially migrated, failed dependency, and rollback state only where the interface
accepts them. Compare canonicalization and units at every parser or policy handoff.
For multi-step issues, treat each output as a prerequisite and do not assume a later
boundary. If any prerequisite is not established, record a blocker.

When a proposed high or critical candidate reveals a reusable root cause, search paths
owned by the assigned coverage IDs for lexical, structural, and logical variants.
Consolidate the same root cause, but establish each variant's conditions and impact
independently. Do not investigate peer-owned units. Return a variant with no current
coverage unit as `uncovered`.

USE THE NARROWEST LOCAL CHECK THAT SETTLES THE CLAIM. Target-controlled builds,
tests, processes, browsers, emulators, fuzzers, and fixture processing may run only
inside the parent-approved OS-enforced sandbox. It must disable external networking,
start from an empty allowlisted environment, expose target and tools read-only, permit
writes only to your scratch directory, and apply low CPU, memory, process, file-size,
disk, and wall-clock limits. Isolated loopback is allowed only for a local fixture.
If any control is unavailable, do not execute: return needs_validation with that exact
blocker. Prefer an existing unit test, minimal function harness, dummy-tenant service
call, small malformed fixture, deterministic race schedule, or locally rendered policy.
Do not install or fetch tools.

Record the exact input, command, limits, and minimum result. For the environment,
record only allowlisted variable names and safe non-secret values needed to reproduce
the check. Never capture the ambient environment, inherited variables, credentials,
authentication state, or unrelated host paths. The target-controlled process writes
only in scratch. After the sandbox and all its processes terminate, only trusted
parent-side code may promote predeclared scratch-relative files, following the
promotion procedure block included verbatim in this prompt. You and target code never
write retained artifacts. If promotion is unavailable or fails for decisive evidence,
return needs_validation with the exact promotion blocker.
Never stress availability, invoke a live target, use a real credential, publish an
artifact, or continue past the minimum observed effect.

A deployment, browser, provider, broker, OS, proxy, package, secret, or identity fact
outside source is not proof either way. If one such fact is decisive, return a
needs_validation record with the exact missing observation and safe owner-observed check.
```

```text
Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker.
```

# Core validation rules (verbatim)

```text
## Candidate gate

1. A candidate needs a complete repository-relative source trace and evidence for the
   claimed root cause, including the strongest source-visible control.
2. A proposed confirmed record needs a bounded local observed result, meaningful impact
   across a stated boundary, complete conditions, and no visible preventing layer.
3. Do not strengthen a crash into code execution, ordinary work into shared availability,
   or a same-principal action into privilege gain.
4. If a required fact is not source-visible or locally observable, use
   needs_validation. Name exact blockers; do not give it severity or speculative completion.
5. A missing best practice with no affected principal/resource is excluded or hardening,
   not a finding. A candidate disproved by source is not needs_validation.
6. Use the same source-derived fingerprint for the same root cause in every state.
   It must match `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` and must not include a line,
   wave, agent, severity, or verdict.
7. Return an empty candidate array when nothing survives these gates.
```

# Exclusions and peer-owned units

Carried same-source prior confirmed exclusions: none (no unit is same-source).

Peer-owned coverage IDs (do not investigate these; report a different boundary you notice under `uncovered`):
- `Completeness%20of%20the%207dbda9e%20fixes%20for%20run-6%20F1-F3%20and%20N1-N3%3A%20GuiBursts.covers%20container_id%20check%20and%20restore_sandbox%20bursts.end%20%28gui_bursts.py%3A72-83%2C%20service.py%3A625-635%29%3B%20idx_audit_sandbox_id%20and%20batched%20_verify_live%20outside%20_lock%20%28audit.py%3A38%2C%20337-400%29%3B%20_expand%20~%2F%7B%20handling%20and%20head%20-z%20-n%20cap%20plus%20preview%20notes%20%28sandbox.py%3A600-626%2C%20preview.py%3A88-114%29%3B%20same_origin%20scheme%20check%20and%20HSTS%20%28api.py%3A221-235%2C%20web.py%3A177%2C187%2C%20cli.py%3A102%2C%20deploy%2FCaddyfile%3A8%29%3B%20_exec_head%2C%20outbox%20head%20-c%2C%20screenshot%20link%2Fsize%20checks%20%28sandbox.py%3A41%2C%20422-461%2C%20564-574%2C%20sandbox_desktop.py%3A37%2C%20113-123%29%3B%20DockerRootDir%20and%20disk_low%20%28sandbox.py%3A179-183%2C%20service.py%3A461-485%29::Each%20run-6%20fix%20must%20close%20its%20root%20cause%20for%20all%20variants%20without%20introducing%20a%20new%20defect%3A%20no%20GUI%20input%20runs%20under%20a%20burst%20whose%20baseline%20belongs%20to%20another%20container%3B%20verify%28%29%20cannot%20hold%20AuditLog._lock%20for%20long%2C%20load%20the%20table%2C%20loop%20forever%2C%20or%20report%20a%20broken%20chain%20as%20intact%3B%20the%20rm%20preview%20does%20not%20show%20a%20real%20target%20as%20absent%20without%20a%20warning%3B%20a%20cross-scheme%20Origin%20is%20refused%20whenever%20cookies%20are%20secure%20%28including%20behind%20the%20TLS%20proxy%20and%20when%20secure_cookie%20is%20off%20by%20configuration%29%3B%20no%20container%20reader%20buffers%20unbounded%20output%20or%20follows%20an%20attacker%20link%3B%20disk_low%20sees%20the%20filesystem%20that%20holds%20container%20layers%20and%20snapshot%20images%20or%20fails%20closed%20when%20it%20cannot.::agentbox%2Fgui_bursts.py%23covers%2Fend%20%2B%20agentbox%2Fservice.py%23restore_sandbox%2Fdisk_low%20%2B%20agentbox%2Faudit.py%23_verify_live%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_exec_head%2Flist_dir%2Foutbox_list%2F_detect_runtime%20%2B%20agentbox%2Fpreview.py%23preview_command%20%2B%20agentbox%2Fsandbox_desktop.py%23screenshot%20%2B%20agentbox%2Fapi.py%23same_origin%2Fsecure_cookie%20%2B%20deploy%2FCaddyfile::ATTACK-CLASSES.md%23Business%20logic` (owner h-fixes)
- `Human-facing%20sinks%20for%20attacker-chosen%20instruction-file%20names%2C%20paths%20and%20content%3A%20_created.html%20%28oneline%29%2C%20_outbox.html%20%28badge%2C%20data-notify%2Fdata-text%2C%20href%20urlencode%2C%20download%20attribute%29%2C%20_approvals.html%20full-content%20%3Cpre%3E%20polled%20every%202%20s%20%28index.html%3A25%2C%20sandbox.html%3A25%29%2C%20sandbox.html%20upload%20JS%2C%20web._shown%2F_oneline%2Fdescribe%28instruction_files_found%29%20%28web.py%3A35-100%29%2C%20cli._safe%2Fcmd_create%2F_show_approval%20%28cli.py%3A33-35%2C%20142-150%2C%20208-217%29%2C%20api.outbox_file%20Content-Disposition%20%28api.py%3A398-404%29::Every%20new%20sink%20must%20pass%20attacker%20strings%20through%20autoescape%20plus%20_shown%2Foneline%20%28web%29%20or%20_safe%20%28CLI%29%3A%20no%20markup%20or%20attribute%20injection%2C%20no%20bidi%2Finvisible%20reordering%2C%20no%20fake%20rows%20or%20lines%2C%20no%20header%20injection%3B%20and%20rendering%20up%20to%2020%20pending%20full-content%20approval%20cards%20per%20sandbox%20%281%20MiB%20each%29%20every%202%20s%20must%20not%20freeze%20the%20human%20UI%20or%20the%20control%20plane.::agentbox%2Ftemplates%2F_created.html%20%2B%20agentbox%2Ftemplates%2F_outbox.html%20%2B%20agentbox%2Ftemplates%2F_approvals.html%20%2B%20agentbox%2Fweb.py%23_shown%2F_oneline%2Fdescribe%20%2B%20agentbox%2Fcli.py%23_safe%2Fcmd_create%2F_show_approval%20%2B%20agentbox%2Fapi.py%23outbox_file::AI-AND-LLM.md%23Insecure%20output%20rendering` (owner h-if-notice-sinks)
- `Instruction-file%20name%20classification%3A%20instruction_files._norm%2F_parts%2Fkind%20%28instruction_files.py%3A26-108%29%20and%20every%20caller%20%28policy.Policy.decide%20%3A214-232%2C%20service._preview%2F_run_tool%2Fimport_file%2Fexport_file%2Foutbox%2C%20IF.scan%2C%20paths_in_words%29::kind%28%29%20must%20classify%20a%20name%20as%20an%20instruction%20file%20whenever%20a%20downstream%20file%20system%2C%20archive%20tool%2C%20browser%20download%2C%20or%20coding%20agent%20would%20treat%20it%20as%20one%20of%20_NAMES%2F_DIRS%2F.github%20dirs%2C%20and%20must%20not%20flag%20ordinary%20names%20so%20often%20that%20normal%20writes%20go%20to%20approval.%20Check%20residual%20bypasses%20after%20a0a186c%3A%20combining%20marks%2C%20NFD%2FNFC%2FNFKD%20forms%2C%20default-ignorable%20characters%2C%20other%20case%20foldings%2C%208.3%20short%20names%2C%20names%20a%20browser%20rewrites%20on%20download%20%28download%20attribute%2C%20Content-Disposition%20filename%2A%29%2C%20trailing%20characters%20other%20than%20dot%2Fspace%2C%20and%20path%20splitting%20of%20backslash%20and%20%27..%27.::agentbox%2Finstruction_files.py%23_norm%2F_parts%2Fkind%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fapi.py%23outbox_file::ATTACK-CLASSES.md%23Resource%20and%20file%20handling` (owner h-if-kind)
- `Policy%20target%20versus%20write%20target%20for%20instruction%20files%3A%20service._resolved%2F_policy_args%2F_preview%20%28service.py%3A235-289%29%2C%20SandboxManager.resolve%20%28sandbox.py%3A487-496%29%2C%20write_file%20tmp%2Bmv%20and%20delete_file%20%28sandbox.py%3A502-525%29%2C%20Policy.decide%20match.instruction_files%20with%20resolved_path%20%28policy.py%3A214-232%29%2C%20default_policy.yaml%20version%204%20rule%20order%2C%20decide%28%29%20executing%20stored%20args%20%28service.py%3A520-575%29::An%20agent-caused%20write%20or%20delete%20must%20not%20land%20in%20an%20instruction%20file%20or%20instruction%20directory%20without%20approval.%20Invariant%3A%20the%20object%20policy%20judged%20%28requested%20path%20or%20the%20single%20realpath%20-m%20at%20decide%20time%29%20is%20the%20object%20mv%2Frm%20finally%20touches%2C%20including%20directory%20links%20as%20the%20last%20component%2C%20links%20changed%20between%20decide%20and%20execution%20or%20during%20the%20approval%20wait%20%28by%20allowlisted%20exec%2C%20write_file%2C%20GUI%20tools%20or%20concurrent%20calls%29%2C%20and%20resolve%28%29%20failures%20%28timeouts%2C%20errors%2C%20concurrency%29%20cannot%20be%20induced%20to%20fall%20back%20to%20the%20requested%20path%3B%20user%20policies%20mixing%20instruction_files%20with%20other%20rules%20evaluate%20in%20a%20safe%20order.::agentbox%2Fservice.py%23_resolved%2F_policy_args%2F_preview%2F_call_tool%2Fdecide%20%2B%20agentbox%2Fsandbox.py%23resolve%2Fwrite_file%2Fdelete_file%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fdefault_policy.yaml::DESKTOP-MOBILE-AND-LOCAL-IPC.md%23Local%20file%20ownership%20and%20TOCTOU` (owner h-if-policy)
- `Read-result%20boundary%20for%20instruction%20files%3A%20instruction_files.mark_read%2Fwith_notice%2Fnotice%20%28instruction_files.py%3A111-137%29%2C%20agent.py%20ToolClient.call_text%20%28%3A118-126%29%2C%20mcp_server.py%20read_file%20and%20instructions%20%28%3A46-52%2C%20119-125%29%2C%20exec%20notice%20in%20service._run_tool%20%28%3A133-141%29::When%20the%20agent%20reads%20an%20instruction%20file%2C%20the%20agent-visible%20text%20must%20carry%20the%20notice%20and%20an%20unforgeable%20boundary%20that%20encloses%20exactly%20the%20file%20content%2C%20identically%20for%20MCP%20and%20the%20built-in%20loop.%20Check%3A%20tag%20collision%20redraw%2C%20the%20truncation%20marker%20inside%20the%20boundary%2C%20content%20that%20imitates%20the%20notice%20or%20a%20boundary%20with%20a%20different%20tag%2C%20exec%20results%20%28notice%20only%2C%20no%20boundary%29%2C%20reads%20through%20a%20link%20or%20a%20non-instruction%20name%20pointing%20at%20an%20instruction%20file%20%28mark_read%20uses%20the%20requested%20path%29%2C%20list_dir%2C%20and%20whether%20a%20user%20read-blocking%20rule%20%28README%29%20can%20be%20bypassed%20through%20a%20link.::agentbox%2Finstruction_files.py%23mark_read%2Fwith_notice%20%2B%20agentbox%2Fagent.py%23call_text%20%2B%20agentbox%2Fmcp_server.py%23read_file%20%2B%20agentbox%2Fservice.py%23_run_tool::AI-AND-LLM.md%23Indirect%20injection%20through%20retrieved%20or%20ingested%20content` (owner h-if-notice-sinks)
- `Source-folder%20scan%20at%20sandbox%20creation%3A%20instruction_files.scan%20%28instruction_files.py%3A150-193%29%20called%20synchronously%20in%20AgentBox.create_sandbox%20%28service.py%3A577-597%29%2C%20_found_payload%2FFOUND_PATH_MAX%20%28service.py%3A778-786%29%20and%20bound_payload%2C%20web.describe%20and%20the%20create%20card::The%20scan%20must%20bound%20the%20time%20and%20memory%20a%20create%20request%20spends%20%28including%20a%20single%20blocking%20scandir%20or%20stat%20on%20a%20slow%2C%20FUSE%20or%20network%20directory%2C%20and%20per-directory%20entry%20buffering%29%2C%20report%20complete%3DFalse%20whenever%20the%20list%20may%20be%20partial%2C%20not%20hold%20locks%20or%20request%20threads%20that%20block%20other%20humans%20or%20agents%2C%20and%20its%20audit%20record%20must%20keep%20the%20count%20and%20truthfully%20mark%20a%20truncated%20list%20after%20bound_payload.::agentbox%2Finstruction_files.py%23scan%20%2B%20agentbox%2Fservice.py%23create_sandbox%2F_found_payload%20%2B%20agentbox%2Faudit.py%23bound_payload%20%2B%20agentbox%2Fweb.py%23describe::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-if-scan)

# Your paths, sandbox and result contract

- Agent ID: `h-refactor`. Audited source (read-only): `/projects/sandbox/.scratch/src-audited/` (git worktree of main at 3580df0, after PR #26). Read it with read_file or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/h-refactor/scratch/`. Retained artifacts: `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/h-refactor/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" h-refactor <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target). Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest are importable). Write `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/h-refactor/scratch/h.py`, then run `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" h-refactor /usr/bin/sh -c "/usr/bin/python3 /scratch/h.py > /scratch/h.out 2>&1"`. Unit tests (cwd must be /target; pass --capture=sys): `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" h-refactor /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/h-refactor/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
- Contract check: for EVERY unit in `"units"`, `unit["reviewed_paths"]` MUST equal the exact sorted set union of `c["reviewed_paths"]` across all `c` in `unit["checks"]`.
- Time box: aim to finish within roughly 50 tool calls. Stop each line of investigation as soon as the invariant is settled.
- Your final message must be ONLY the JSON object (no prose, no code fence).

## Structured hunter result

Return exactly one JSON object, with no surrounding prose:

```json
{
  "units": [
    {
      "coverage_id": "one assigned ID",
      "disposition": "covered|candidate|blocked",
      "reviewed_paths": ["repo/relative/path"],
      "checks": [
        {
          "agent_id": "canonical owner of this check",
          "reviewed_paths": ["repo/relative/path owned by this check"],
          "invariant": "specific control checked for this unit",
          "method": "source|local",
          "result": "what source or the bounded check established",
          "artifact": "agents/<agent-id>/artifacts/file for local, null for source"
        }
      ],
      "candidate_fingerprints": [],
      "unresolved": []
    }
  ],
  "candidates": [],
  "hardening": ["concrete non-finding note"],
  "uncovered": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "reason": "why this needs its own deterministic coverage unit"
    }
  ]
}
```

Each `candidates` entry is schema-shaped except that it uses `proposed_verdict` in place of `verdict`:

- `proposed_verdict: "confirmed"`: include every field required by the `confirmed` branch of `report-schema.json` other than `verdict`: `fingerprint`, title, description, `root_cause`, `intended_behavior`, ordered `trace`, `evidence`, `conditions`, target-neutral `execution`, `remediation`, `severity`, and `confidence`. The execution instructions describe only the bounded local check already performed. `payloads` holds the minimum test input, fixture, or native invocation. `observed_result` records actual local output. Overall severity must not exceed observed impact.
- `proposed_verdict: "needs_validation"`: include every field required by that schema branch other than `verdict`: `fingerprint`, title, description, `claimed_root_cause`, ordered `trace`, `evidence`, nonempty `blockers`, and `validation_plan` with at least one applicable `local` or `deployment` step. Do not invent an inapplicable context. Do not include severity, execution, remediation, reason, or a confirmed `root_cause`. `deployment` is an owner-observed check, not a request to probe a live target.

Every assigned coverage ID appears exactly once in `units`. A `covered` unit needs an owner, nonempty `reviewed_paths` and `checks`, no unresolved fact, and no candidate. A `candidate` unit has the same owned evidence and is the only state that carries linked fingerprints. A `blocked` unit is an owned partial review with nonempty paths, checks, and unresolved facts but no fingerprint. All source paths are repository-relative, never absolute or traversal paths. A trace with several entries begins at `entrypoint`, ends at `sink`, and labels intermediate steps `propagation`. Every check has its own canonical lowercase `agent_id` and nonempty `reviewed_paths`; the unit-level list is exactly the union of those owned paths. A `source` check uses `artifact: null`. A `local` check uses one successfully parent-promoted regular file beneath `agents/<check.agent_id>/artifacts/`; this permits a verifier to add independently owned evidence without taking ownership from the hunter. Never link scratch, an output-root file, or another check owner's artifact.

## report-schema.json `confirmed` branch (verbatim)

```json
{
 "type": "object",
 "description": "A source-grounded vulnerability that was independently demonstrated.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "confirmed"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
   "description": "A stable source-derived identifier that does not change between validation states."
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "intended_behavior": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "conditions": {
   "type": "array",
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "authentication_level",
       "authorization_role",
       "user_interaction",
       "system_configuration",
       "network_routing",
       "environmental_dependency",
       "data_state",
       "timing_dependency",
       "third_party_dependency"
      ]
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "execution": {
   "type": "object",
   "description": "Target-neutral reproduction in the target's native interface.",
   "properties": {
    "attacker_perspective": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "payloads": {
     "type": "array",
     "minItems": 1,
     "uniqueItems": true,
     "items": {
      "type": "string"
     }
    },
    "instructions": {
     "type": "array",
     "minItems": 1,
     "items": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "observed_result": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "attacker_perspective",
    "payloads",
    "instructions",
    "observed_result"
   ],
   "additionalProperties": false
  },
  "remediation": {
   "type": "object",
   "properties": {
    "strategy": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "code_changes": {
     "type": "array",
     "items": {
      "type": "object",
      "properties": {
       "file_name": {
        "type": "string",
        "minLength": 1
       },
       "fixed_code": {
        "type": "string"
       }
      },
      "required": [
       "file_name",
       "fixed_code"
      ],
      "additionalProperties": false
     }
    }
   },
   "required": [
    "strategy"
   ],
   "additionalProperties": false
  },
  "severity": {
   "type": "object",
   "properties": {
    "likelihood": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "impact": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "overall_severity": {
     "type": "string",
     "enum": [
      "informational",
      "low",
      "medium",
      "high",
      "critical"
     ]
    }
   },
   "required": [
    "likelihood",
    "impact",
    "overall_severity"
   ],
   "additionalProperties": false
  },
  "confidence": {
   "type": "object",
   "properties": {
    "score": {
     "type": "string",
     "enum": [
      "low",
      "medium",
      "high"
     ]
    },
    "reason": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "score",
    "reason"
   ],
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "root_cause",
  "intended_behavior",
  "trace",
  "evidence",
  "conditions",
  "execution",
  "remediation",
  "severity",
  "confidence"
 ],
 "additionalProperties": false
}
```

## report-schema.json `needs_validation` branch (verbatim)

```json
{
 "type": "object",
 "description": "A source-grounded candidate whose decisive validation is blocked.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "needs_validation"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$"
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "claimed_root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "blockers": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "string",
    "minLength": 1,
    "visibleContent": true
   }
  },
  "validation_plan": {
   "type": "object",
   "properties": {
    "local": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "deployment": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "claimed_root_cause",
  "trace",
  "evidence",
  "blockers",
  "validation_plan"
 ],
 "additionalProperties": false
}
```
