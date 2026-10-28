You are `critic-2`, the distinct final-clean coverage critic; the post-wave critic has already run and its accepted work is recorded in the ledger, in run-7 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `/projects/sandbox/.scratch/src-audited/` — a git worktree of `main` at `3580df0`. Your only writable directory is `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/critic-2/scratch/`, and you need not write anything.

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

# Full coverage ledger

Read it at `/projects/sandbox/agentbox/docs/security-audit/run-7/coverage-ledger.json` (7 units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

# Current candidate fingerprints and states

```json
[
 {
  "fingerprint": "agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed",
  "state": "final record: needs_validation",
  "title": "kind() casefold expands U+0130 and may miss an instruction name that a case-insensitive filesystem treats as canonical"
 },
 {
  "fingerprint": "agentbox/instruction_files.py:kind:instruction-dir-as-final-component-unmatched-so-write-into-linked-dir-skips-approval",
  "state": "final record: confirmed",
  "title": "write_file into an instruction directory via a directory symlink bypasses the approval gate (kind() never matches an instruction dir as the last path component)"
 },
 {
  "fingerprint": "agentbox/service.py:_resolved:resolve-failure-fails-open-to-requested-path-skips-instruction-file-approval",
  "state": "final record: confirmed",
  "title": "Induced resolve() failure makes the instruction-file write gate fail open to the benign requested path"
 },
 {
  "fingerprint": "agentbox/service.py:disk_low-unmonitored-docker-data-root",
  "state": "final record: needs_validation",
  "title": "disk_low fails open when the Docker data root is not reachable in the control-plane container"
 },
 {
  "fingerprint": "agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll",
  "state": "final record: confirmed",
  "title": "Instruction-file approval cards render attacker-sized full content with no per-card or aggregate cap, re-rendered on every 2 s poll"
 },
 {
  "fingerprint": "agentbox/service.py:disk_low-unmonitored-docker-data-root",
  "state": "ledger unit Completeness%20of%20the%207dbda9e%20fixes%20for%20run-6%20F1-F3%20and%20N1-N3%3A%20GuiBursts.covers%20container_id%20check%20and%20restore_sandbox%20bursts.end%20%28gui_bursts.py%3A72-83%2C%20service.py%3A625-635%29%3B%20idx_audit_sandbox_id%20and%20batched%20_verify_live%20outside%20_lock%20%28audit.py%3A38%2C%20337-400%29%3B%20_expand%20~%2F%7B%20handling%20and%20head%20-z%20-n%20cap%20plus%20preview%20notes%20%28sandbox.py%3A600-626%2C%20preview.py%3A88-114%29%3B%20same_origin%20scheme%20check%20and%20HSTS%20%28api.py%3A221-235%2C%20web.py%3A177%2C187%2C%20cli.py%3A102%2C%20deploy%2FCaddyfile%3A8%29%3B%20_exec_head%2C%20outbox%20head%20-c%2C%20screenshot%20link%2Fsize%20checks%20%28sandbox.py%3A41%2C%20422-461%2C%20564-574%2C%20sandbox_desktop.py%3A37%2C%20113-123%29%3B%20DockerRootDir%20and%20disk_low%20%28sandbox.py%3A179-183%2C%20service.py%3A461-485%29::Each%20run-6%20fix%20must%20close%20its%20root%20cause%20for%20all%20variants%20without%20introducing%20a%20new%20defect%3A%20no%20GUI%20input%20runs%20under%20a%20burst%20whose%20baseline%20belongs%20to%20another%20container%3B%20verify%28%29%20cannot%20hold%20AuditLog._lock%20for%20long%2C%20load%20the%20table%2C%20loop%20forever%2C%20or%20report%20a%20broken%20chain%20as%20intact%3B%20the%20rm%20preview%20does%20not%20show%20a%20real%20target%20as%20absent%20without%20a%20warning%3B%20a%20cross-scheme%20Origin%20is%20refused%20whenever%20cookies%20are%20secure%20%28including%20behind%20the%20TLS%20proxy%20and%20when%20secure_cookie%20is%20off%20by%20configuration%29%3B%20no%20container%20reader%20buffers%20unbounded%20output%20or%20follows%20an%20attacker%20link%3B%20disk_low%20sees%20the%20filesystem%20that%20holds%20container%20layers%20and%20snapshot%20images%20or%20fails%20closed%20when%20it%20cannot.::agentbox%2Fgui_bursts.py%23covers%2Fend%20%2B%20agentbox%2Fservice.py%23restore_sandbox%2Fdisk_low%20%2B%20agentbox%2Faudit.py%23_verify_live%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_exec_head%2Flist_dir%2Foutbox_list%2F_detect_runtime%20%2B%20agentbox%2Fpreview.py%23preview_command%20%2B%20agentbox%2Fsandbox_desktop.py%23screenshot%20%2B%20agentbox%2Fapi.py%23same_origin%2Fsecure_cookie%20%2B%20deploy%2FCaddyfile::ATTACK-CLASSES.md%23Business%20logic: candidate",
  "unit": "Completeness%20of%20the%207dbda9e%20fixes%20for%20run-6%20F1-F3%20and%20N1-N3%3A%20GuiBursts.covers%20container_id%20check%20and%20restore_sandbox%20bursts.end%20%28gui_bursts.py%3A72-83%2C%20service.py%3A625-635%29%3B%20idx_audit_sandbox_id%20and%20batched%20_verify_live%20outside%20_lock%20%28audit.py%3A38%2C%20337-400%29%3B%20_expand%20~%2F%7B%20handling%20and%20head%20-z%20-n%20cap%20plus%20preview%20notes%20%28sandbox.py%3A600-626%2C%20preview.py%3A88-114%29%3B%20same_origin%20scheme%20check%20and%20HSTS%20%28api.py%3A221-235%2C%20web.py%3A177%2C187%2C%20cli.py%3A102%2C%20deploy%2FCaddyfile%3A8%29%3B%20_exec_head%2C%20outbox%20head%20-c%2C%20screenshot%20link%2Fsize%20checks%20%28sandbox.py%3A41%2C%20422-461%2C%20564-574%2C%20sandbox_desktop.py%3A37%2C%20113-123%29%3B%20DockerRootDir%20and%20disk_low%20%28sandbox.py%3A179-183%2C%20service.py%3A461-485%29::Each%20run-6%20fix%20must%20close%20its%20root%20cause%20for%20all%20variants%20without%20introducing%20a%20new%20defect%3A%20no%20GUI%20input%20runs%20under%20a%20burst%20whose%20baseline%20belongs%20to%20another%20container%3B%20verify%28%29%20cannot%20hold%20AuditLog._lock%20for%20long%2C%20load%20the%20table%2C%20loop%20forever%2C%20or%20report%20a%20broken%20chain%20as%20intact%3B%20the%20rm%20preview%20does%20not%20show%20a%20real%20target%20as%20absent%20without%20a%20warning%3B%20a%20cross-scheme%20Origin%20is%20refused%20whenever%20cookies%20are%20secure%20%28including%20behind%20the%20TLS%20proxy%20and%20when%20secure_cookie%20is%20off%20by%20configuration%29%3B%20no%20container%20reader%20buffers%20unbounded%20output%20or%20follows%20an%20attacker%20link%3B%20disk_low%20sees%20the%20filesystem%20that%20holds%20container%20layers%20and%20snapshot%20images%20or%20fails%20closed%20when%20it%20cannot.::agentbox%2Fgui_bursts.py%23covers%2Fend%20%2B%20agentbox%2Fservice.py%23restore_sandbox%2Fdisk_low%20%2B%20agentbox%2Faudit.py%23_verify_live%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_exec_head%2Flist_dir%2Foutbox_list%2F_detect_runtime%20%2B%20agentbox%2Fpreview.py%23preview_command%20%2B%20agentbox%2Fsandbox_desktop.py%23screenshot%20%2B%20agentbox%2Fapi.py%23same_origin%2Fsecure_cookie%20%2B%20deploy%2FCaddyfile::ATTACK-CLASSES.md%23Business%20logic"
 },
 {
  "fingerprint": "agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll",
  "state": "ledger unit Human-facing%20sinks%20for%20attacker-chosen%20instruction-file%20names%2C%20paths%20and%20content%3A%20_created.html%20%28oneline%29%2C%20_outbox.html%20%28badge%2C%20data-notify%2Fdata-text%2C%20href%20urlencode%2C%20download%20attribute%29%2C%20_approvals.html%20full-content%20%3Cpre%3E%20polled%20every%202%20s%20%28index.html%3A25%2C%20sandbox.html%3A25%29%2C%20sandbox.html%20upload%20JS%2C%20web._shown%2F_oneline%2Fdescribe%28instruction_files_found%29%20%28web.py%3A35-100%29%2C%20cli._safe%2Fcmd_create%2F_show_approval%20%28cli.py%3A33-35%2C%20142-150%2C%20208-217%29%2C%20api.outbox_file%20Content-Disposition%20%28api.py%3A398-404%29::Every%20new%20sink%20must%20pass%20attacker%20strings%20through%20autoescape%20plus%20_shown%2Foneline%20%28web%29%20or%20_safe%20%28CLI%29%3A%20no%20markup%20or%20attribute%20injection%2C%20no%20bidi%2Finvisible%20reordering%2C%20no%20fake%20rows%20or%20lines%2C%20no%20header%20injection%3B%20and%20rendering%20up%20to%2020%20pending%20full-content%20approval%20cards%20per%20sandbox%20%281%20MiB%20each%29%20every%202%20s%20must%20not%20freeze%20the%20human%20UI%20or%20the%20control%20plane.::agentbox%2Ftemplates%2F_created.html%20%2B%20agentbox%2Ftemplates%2F_outbox.html%20%2B%20agentbox%2Ftemplates%2F_approvals.html%20%2B%20agentbox%2Fweb.py%23_shown%2F_oneline%2Fdescribe%20%2B%20agentbox%2Fcli.py%23_safe%2Fcmd_create%2F_show_approval%20%2B%20agentbox%2Fapi.py%23outbox_file::AI-AND-LLM.md%23Insecure%20output%20rendering: candidate",
  "unit": "Human-facing%20sinks%20for%20attacker-chosen%20instruction-file%20names%2C%20paths%20and%20content%3A%20_created.html%20%28oneline%29%2C%20_outbox.html%20%28badge%2C%20data-notify%2Fdata-text%2C%20href%20urlencode%2C%20download%20attribute%29%2C%20_approvals.html%20full-content%20%3Cpre%3E%20polled%20every%202%20s%20%28index.html%3A25%2C%20sandbox.html%3A25%29%2C%20sandbox.html%20upload%20JS%2C%20web._shown%2F_oneline%2Fdescribe%28instruction_files_found%29%20%28web.py%3A35-100%29%2C%20cli._safe%2Fcmd_create%2F_show_approval%20%28cli.py%3A33-35%2C%20142-150%2C%20208-217%29%2C%20api.outbox_file%20Content-Disposition%20%28api.py%3A398-404%29::Every%20new%20sink%20must%20pass%20attacker%20strings%20through%20autoescape%20plus%20_shown%2Foneline%20%28web%29%20or%20_safe%20%28CLI%29%3A%20no%20markup%20or%20attribute%20injection%2C%20no%20bidi%2Finvisible%20reordering%2C%20no%20fake%20rows%20or%20lines%2C%20no%20header%20injection%3B%20and%20rendering%20up%20to%2020%20pending%20full-content%20approval%20cards%20per%20sandbox%20%281%20MiB%20each%29%20every%202%20s%20must%20not%20freeze%20the%20human%20UI%20or%20the%20control%20plane.::agentbox%2Ftemplates%2F_created.html%20%2B%20agentbox%2Ftemplates%2F_outbox.html%20%2B%20agentbox%2Ftemplates%2F_approvals.html%20%2B%20agentbox%2Fweb.py%23_shown%2F_oneline%2Fdescribe%20%2B%20agentbox%2Fcli.py%23_safe%2Fcmd_create%2F_show_approval%20%2B%20agentbox%2Fapi.py%23outbox_file::AI-AND-LLM.md%23Insecure%20output%20rendering"
 },
 {
  "fingerprint": "agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed",
  "state": "ledger unit Instruction-file%20name%20classification%3A%20instruction_files._norm%2F_parts%2Fkind%20%28instruction_files.py%3A26-108%29%20and%20every%20caller%20%28policy.Policy.decide%20%3A214-232%2C%20service._preview%2F_run_tool%2Fimport_file%2Fexport_file%2Foutbox%2C%20IF.scan%2C%20paths_in_words%29::kind%28%29%20must%20classify%20a%20name%20as%20an%20instruction%20file%20whenever%20a%20downstream%20file%20system%2C%20archive%20tool%2C%20browser%20download%2C%20or%20coding%20agent%20would%20treat%20it%20as%20one%20of%20_NAMES%2F_DIRS%2F.github%20dirs%2C%20and%20must%20not%20flag%20ordinary%20names%20so%20often%20that%20normal%20writes%20go%20to%20approval.%20Check%20residual%20bypasses%20after%20a0a186c%3A%20combining%20marks%2C%20NFD%2FNFC%2FNFKD%20forms%2C%20default-ignorable%20characters%2C%20other%20case%20foldings%2C%208.3%20short%20names%2C%20names%20a%20browser%20rewrites%20on%20download%20%28download%20attribute%2C%20Content-Disposition%20filename%2A%29%2C%20trailing%20characters%20other%20than%20dot%2Fspace%2C%20and%20path%20splitting%20of%20backslash%20and%20%27..%27.::agentbox%2Finstruction_files.py%23_norm%2F_parts%2Fkind%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fapi.py%23outbox_file::ATTACK-CLASSES.md%23Resource%20and%20file%20handling: candidate",
  "unit": "Instruction-file%20name%20classification%3A%20instruction_files._norm%2F_parts%2Fkind%20%28instruction_files.py%3A26-108%29%20and%20every%20caller%20%28policy.Policy.decide%20%3A214-232%2C%20service._preview%2F_run_tool%2Fimport_file%2Fexport_file%2Foutbox%2C%20IF.scan%2C%20paths_in_words%29::kind%28%29%20must%20classify%20a%20name%20as%20an%20instruction%20file%20whenever%20a%20downstream%20file%20system%2C%20archive%20tool%2C%20browser%20download%2C%20or%20coding%20agent%20would%20treat%20it%20as%20one%20of%20_NAMES%2F_DIRS%2F.github%20dirs%2C%20and%20must%20not%20flag%20ordinary%20names%20so%20often%20that%20normal%20writes%20go%20to%20approval.%20Check%20residual%20bypasses%20after%20a0a186c%3A%20combining%20marks%2C%20NFD%2FNFC%2FNFKD%20forms%2C%20default-ignorable%20characters%2C%20other%20case%20foldings%2C%208.3%20short%20names%2C%20names%20a%20browser%20rewrites%20on%20download%20%28download%20attribute%2C%20Content-Disposition%20filename%2A%29%2C%20trailing%20characters%20other%20than%20dot%2Fspace%2C%20and%20path%20splitting%20of%20backslash%20and%20%27..%27.::agentbox%2Finstruction_files.py%23_norm%2F_parts%2Fkind%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fapi.py%23outbox_file::ATTACK-CLASSES.md%23Resource%20and%20file%20handling"
 },
 {
  "fingerprint": "agentbox/service.py:_resolved:resolve-failure-fails-open-to-requested-path-skips-instruction-file-approval",
  "state": "ledger unit Policy%20target%20versus%20write%20target%20for%20instruction%20files%3A%20service._resolved%2F_policy_args%2F_preview%20%28service.py%3A235-289%29%2C%20SandboxManager.resolve%20%28sandbox.py%3A487-496%29%2C%20write_file%20tmp%2Bmv%20and%20delete_file%20%28sandbox.py%3A502-525%29%2C%20Policy.decide%20match.instruction_files%20with%20resolved_path%20%28policy.py%3A214-232%29%2C%20default_policy.yaml%20version%204%20rule%20order%2C%20decide%28%29%20executing%20stored%20args%20%28service.py%3A520-575%29::An%20agent-caused%20write%20or%20delete%20must%20not%20land%20in%20an%20instruction%20file%20or%20instruction%20directory%20without%20approval.%20Invariant%3A%20the%20object%20policy%20judged%20%28requested%20path%20or%20the%20single%20realpath%20-m%20at%20decide%20time%29%20is%20the%20object%20mv%2Frm%20finally%20touches%2C%20including%20directory%20links%20as%20the%20last%20component%2C%20links%20changed%20between%20decide%20and%20execution%20or%20during%20the%20approval%20wait%20%28by%20allowlisted%20exec%2C%20write_file%2C%20GUI%20tools%20or%20concurrent%20calls%29%2C%20and%20resolve%28%29%20failures%20%28timeouts%2C%20errors%2C%20concurrency%29%20cannot%20be%20induced%20to%20fall%20back%20to%20the%20requested%20path%3B%20user%20policies%20mixing%20instruction_files%20with%20other%20rules%20evaluate%20in%20a%20safe%20order.::agentbox%2Fservice.py%23_resolved%2F_policy_args%2F_preview%2F_call_tool%2Fdecide%20%2B%20agentbox%2Fsandbox.py%23resolve%2Fwrite_file%2Fdelete_file%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fdefault_policy.yaml::DESKTOP-MOBILE-AND-LOCAL-IPC.md%23Local%20file%20ownership%20and%20TOCTOU: candidate",
  "unit": "Policy%20target%20versus%20write%20target%20for%20instruction%20files%3A%20service._resolved%2F_policy_args%2F_preview%20%28service.py%3A235-289%29%2C%20SandboxManager.resolve%20%28sandbox.py%3A487-496%29%2C%20write_file%20tmp%2Bmv%20and%20delete_file%20%28sandbox.py%3A502-525%29%2C%20Policy.decide%20match.instruction_files%20with%20resolved_path%20%28policy.py%3A214-232%29%2C%20default_policy.yaml%20version%204%20rule%20order%2C%20decide%28%29%20executing%20stored%20args%20%28service.py%3A520-575%29::An%20agent-caused%20write%20or%20delete%20must%20not%20land%20in%20an%20instruction%20file%20or%20instruction%20directory%20without%20approval.%20Invariant%3A%20the%20object%20policy%20judged%20%28requested%20path%20or%20the%20single%20realpath%20-m%20at%20decide%20time%29%20is%20the%20object%20mv%2Frm%20finally%20touches%2C%20including%20directory%20links%20as%20the%20last%20component%2C%20links%20changed%20between%20decide%20and%20execution%20or%20during%20the%20approval%20wait%20%28by%20allowlisted%20exec%2C%20write_file%2C%20GUI%20tools%20or%20concurrent%20calls%29%2C%20and%20resolve%28%29%20failures%20%28timeouts%2C%20errors%2C%20concurrency%29%20cannot%20be%20induced%20to%20fall%20back%20to%20the%20requested%20path%3B%20user%20policies%20mixing%20instruction_files%20with%20other%20rules%20evaluate%20in%20a%20safe%20order.::agentbox%2Fservice.py%23_resolved%2F_policy_args%2F_preview%2F_call_tool%2Fdecide%20%2B%20agentbox%2Fsandbox.py%23resolve%2Fwrite_file%2Fdelete_file%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fdefault_policy.yaml::DESKTOP-MOBILE-AND-LOCAL-IPC.md%23Local%20file%20ownership%20and%20TOCTOU"
 }
]
```

# Hunter-reported `uncovered` boundaries

```json
[]
```

# Prior-ledger gap summary

- run-7 is a focused follow-up audit at 3580df0 of the delta 530b29e..3580df0. run-6 closed all 11
  units with nothing deferred. The run-7 ledger holds seven new units: completeness of the 7dbda9e fixes
  for run-6 F1-F3/N1-N3, behaviour preservation of the 5bb3c17 refactor, and five IF-1 units (name
  classification, policy target vs write target, read-result boundary, human-facing sinks, source scan).
- Every other unit from run-4..run-6 was covered at 9805d91, 346df29 or 530b29e and its code is unchanged
  by the delta; proposing them again needs a concrete changed-code or cross-unit interaction reason.
- An owner-run single-pass IF-1 review at ccaf367 found 7 confirmed, 3 info, 5 needs_validation; a0a186c
  fixed the 7 confirmed and 2 needs_validation. Fixed root causes are not to be re-proposed.
- README known limitations (name-only detection, exec glob reads, GUI approval bypass N-1, LLM-provider
  data path, audit external anchor) are out of scope without a new angle.

# Your task (verbatim from the skill)

```text
Immediately after each hunter wave, spend the reserved invocation on one fresh `research` post-wave coverage critic. It receives `architecture.md`, the full coverage ledger including each assignment block map, current candidate fingerprints and states, and the prior-ledger gap summary. It reads source but does not write or run targets. Require exactly this JSON:

```json
{
  "missing_units": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{"block": "FILE.md#section", "reason": "..."}],
      "reason": "source-backed coverage gap"
    }
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}
```

The critic checks for unmapped entry points, unchecked parallel paths, missing lifecycle modes, selected companion classes without a unit, unjustified exclusions, units closed without paths/checks, and prior `needs_validation` or changed-source gaps that no unit addresses. It proposes coverage, not findings. `stop` is the critic's own assessment: `true` only when it accepts no `missing_units` and no `reassign_ids`; the parent's loop condition below, not `stop` alone, decides whether another wave runs. For each fingerprint in `resolved_prior_leads`, the parent marks the linked unit or prior-lead entry resolved and records the critic's source-backed reason.

The parent rejects proposed units outside the review scope or source/local boundary, derives canonical IDs for accepted units, and deduplicates them against current units. A prior same-source completed unit may supply evidence; prior `deferred`, `blocked`, `out_of_scope`, or changed-source units become current work and never suppress an accepted unit. Fail rather than merge a canonical ID collision. For each legitimate `reassign_id` with live `blocked`, `covered`, or `candidate` evidence, append that exact terminal record to the unit's `attempts` with the critic's source-backed `reassignment_reason`. Preserve its owner, checks, artifacts, fingerprints, and unresolved facts in that archive. Increment the live `wave`; the next hunter must be a fresh owner and receives an `in_progress` unit with empty live evidence. The hunter's terminal result writes only its new evidence into the live fields. Never copy an archived owner's checks or artifacts into the new live attempt. Sort IDs and validate the ledger before another assignment. In `standard` and `deep`, when the post-wave critic reports no accepted `missing_units` or legitimate `reassign_ids` and no `planned` units remain, spend the separately reserved invocation on a distinct final-clean critic. Complete coverage only when that critic also returns no accepted work. If it finds work, queue it and repeat the wave, post-wave critic, and final-clean process. If time or resources force an early stop, mark every untouched unit `deferred`, preserve the critic's reason, and disclose the gap in the report. Never use a silent wave or agent cap as evidence of complete coverage.
```

Budget note: Owner cap 20; 17 spent. This is the final-clean critic (18). 2 invocations remain; an accepted missing unit or reassignment will be recorded as deferred unless it fits in 2 calls.

Return exactly one JSON object and nothing else (no prose, no code fence):
```json
{
  "missing_units": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{"block": "FILE.md#section", "reason": "..."}],
      "reason": "source-backed coverage gap"
    }
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}
```
