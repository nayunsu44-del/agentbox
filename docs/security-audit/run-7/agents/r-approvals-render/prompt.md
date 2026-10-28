You are final record verifier `r-approvals-render` in run-7 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `/projects/sandbox/.scratch/src-audited/` — a git worktree of `main` at commit `3580df0`. Every path and line must exist in THAT tree (except `agents/...` artifacts which live under `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/...`).

# Record under verification

```json
{
 "fingerprint": "agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll",
 "title": "Instruction-file approval cards render attacker-sized full content with no per-card or aggregate cap, re-rendered on every 2 s poll",
 "description": "A prompt-injected sandbox agent holding its own agent token can queue PENDING_APPROVALS_MAX=20 pending write_file approvals per sandbox to instruction-file paths (default rule instruction-file-write-needs-approval). Each pending row stores the agent's full 'content', which is exempt from TOOL_ARG_MAX. _approvals.html renders every pending instruction-file card's content in full through autoescape plus _shown (escape_controls turns each non-printable-ASCII character such as U+0001 into a 4-character escape) with no truncation and no aggregate cap. web.render materialises and SHA-256-hashes the whole body on every request, including ones that end in 204, and index.html and sandbox.html both poll the fragment every 2 s; the index fragment aggregates the pending set of all sandboxes. Parent-live evidence against the real API: 20 write_file calls returned 202 (the 21st 429), and each GET /ui/approvals returned 83,920,462 bytes in about 13.7 s. Independent sandboxed reproduction with the real template and filters: 20 x 1 MiB U+0001 cards took 10.85 s to render and hash and produced an 80.0 MiB body, against 0.13 s / 20.0 MiB for printable ASCII. The human approval view becomes unusable while the attacker's writes are pending, and each poll ties up a control-plane worker for seconds of CPU.",
 "root_cause": "_approvals.html:13 outputs a.args.content in full with no length bound. _shown/escape_controls expands each non-printable-ASCII character about 4x. Neither the card nor the fragment has a rendered-size cap. web.render (web.py:147-148) always builds and hashes the full body before deciding on a 204. Content size is not checked when the approval is created: service.py:359-360 exempts 'content' from TOOL_ARG_MAX, and the max_write_bytes=1 MiB check only runs when the approved write executes (sandbox.py:507). A pending card's content is therefore bounded only by the 8 MiB JSON body limit (config.py:65); the 1 MiB-per-card figure used in the measurements is a conservative lower bound.",
 "intended_behavior": "The approvals fragment, polled every 2 s from the index and sandbox pages, should cap the CPU and bytes each poll costs, so that pending content chosen by an agent cannot make a poll cost seconds of control-plane CPU or tens of MiB of response, and the human can still review and deny the request.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 359,
   "scope": "AgentBox._call_tool argument-length gate",
   "description": "The agent's write_file call enters here. The TOOL_ARG_MAX comprehension skips the 'content' key, so content of any size passes. Nothing checks max_write_bytes before the approval is created."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 433,
   "scope": "AgentBox._request_approval",
   "description": "approvals.create stores the full args (including 1 MiB content); up to PENDING_APPROVALS_MAX=20 rows can be pending per sandbox."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 251,
   "scope": "approvals_view",
   "description": "Lists every pending approval; with sandbox_id=None (the index poll) it aggregates all sandboxes into one fragment."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 148,
   "scope": "render()",
   "description": "Builds the entire response body and hashes it on every request, even when it returns 204."
  },
  {
   "kind": "sink",
   "file": "agentbox/templates/_approvals.html",
   "line": 13,
   "scope": "pending instruction-file card",
   "description": "<pre>{{ a.args.content }}</pre> renders the full content through _shown; no truncation or aggregate cap."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 47,
   "description": "PENDING_APPROVALS_MAX = 20 pending approvals per sandbox."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 507,
   "description": "max_write_bytes is enforced only when the approved write executes, not when the pending approval is created."
  },
  {
   "file": "agentbox/config.py",
   "line": 65,
   "description": "max_body_bytes defaults to 8 MiB; this is the effective bound on pending content per card."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 24,
   "description": "instruction-file-write-needs-approval routes write_file to instruction files to approval, which selects the full-content card branch."
  },
  {
   "file": "agentbox/templates/index.html",
   "line": 25,
   "description": "hx-get=\"/ui/approvals\" (all sandboxes) with hx-trigger=\"load, every 2s\"."
  },
  {
   "file": "agentbox/templates/sandbox.html",
   "line": 25,
   "description": "Per-sandbox approvals fragment, also polled every 2s."
  },
  {
   "file": "agents/parent-live/artifacts/approvals_render_live.out",
   "line": 1,
   "description": "Live API: 20 write_file calls returned 202 and the 21st 429; GET /ui/approvals returned 200 with 83,920,462 bytes in 13.69-13.91 s per request, for both the index and the per-sandbox fragment."
  },
  {
   "file": "agents/v-approvals-render/artifacts/v_render.out",
   "line": 1,
   "description": "Sandboxed reproduction with the real template and filters: 20 x 1 MiB U+0001 took 10.846 s to render and hash and produced 83,909,472 bytes; 20 x 1 MiB 'a' took 0.131 s and produced 20,994,912 bytes."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds a per-sandbox agent token (the assumed prompt-injected agent)."
  },
  {
   "kind": "user_interaction",
   "description": "A human has an approvals view open; the index and sandbox pages poll /ui/approvals every 2 s automatically."
  },
  {
   "kind": "data_state",
   "description": "Up to 20 pending instruction-file write approvals per sandbox, each carrying large content of non-printable-ASCII characters; approvals expire after approval_timeout (default 300 s) and the agent can queue them again."
  },
  {
   "kind": "system_configuration",
   "description": "Default configuration: default_policy.yaml v4, PENDING_APPROVALS_MAX 20, max_body_bytes 8 MiB."
  }
 ],
 "execution": {
  "attacker_perspective": "As the sandbox agent, fill the per-sandbox pending queue with maximum-size instruction-file writes; every human poll of the approvals view then re-renders them.",
  "payloads": [
   "POST /sandboxes/{sid}/tools/write_file {\"args\":{\"path\":\"CLAUDE.md\",\"content\":\"\\u0001\" * 1048576}}",
   "repeat 20 times with different instruction-file paths to reach PENDING_APPROVALS_MAX"
  ],
  "instructions": [
   "In the sandbox, build a Jinja2 environment for agentbox/templates with autoescape on, finalize=agentbox.web._shown, and filters oneline/short as in web.register.",
   "Construct 20 pending-approval dicts with tool='write_file', preview.instruction_file set, and args.content = '\\x01' * (1024*1024).",
   "Render _approvals.html once and record render time and body size."
  ],
  "observed_result": "Rendering and hashing 20 x 1 MiB U+0001 cards took 10.846 s and produced an 80.0 MiB body; printable ASCII took 0.131 s for 20.0 MiB. The parent-live run against the real API measured 83,920,462 bytes in about 13.7 s per GET /ui/approvals."
 },
 "remediation": {
  "strategy": "In the polled fragment, show only a capped prefix of instruction-file content, with total length, a digest, and a link to a separate non-polled page that shows the full content for the approval under review. Cap the total rendered bytes per fragment. Reject or bound write_file content at max_write_bytes before creating an approval. Base the 204 version on approval ids and statuses, not on a hash of the rendered body.",
  "code_changes": [
   {
    "file_name": "agentbox/templates/_approvals.html",
    "fixed_code": "<pre class=\"instruction-content\" style=\"max-height:480px\">{{ a.args.content[:4096] }}{% if a.args.content | length > 4096 %}\n…({{ a.args.content | length - 4096 }}자 더)\n{% endif %}</pre><a href=\"/ui/approvals/{{ a.id }}/content\">전체 내용 보기</a>"
   },
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "        if tool == \"write_file\" and len(str(args.get(\"content\", \"\")).encode()) > self.sandboxes.settings.max_write_bytes:\n            raise ServiceError(413, \"쓸 내용이 너무 큼\")"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "Triggered by a prompt-injected agent under default configuration; the UI polls automatically."
  },
  "impact": {
   "score": "medium",
   "reason": "Degrades or denies the human approval UI and ties up control-plane threadpool workers while the human triages the attacker's writes; no data loss or privilege change."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Measured with the real template and filters in the sandbox and against the real API in a parent-live run; bounds and per-poll rebuild are source-confirmed."
 },
 "verdict": "confirmed"
}
```

# Phase 5 procedure (verbatim)

```text
### Phase 5: Verify the final records with fresh eyes

Launch one fresh `research` verifier per final `confirmed` and `needs_validation` record, in parallel. This verifier checks the structured record, not the hunter write-up, and remains inside source/local boundaries.

In a `quick` run, Phase 3 and Phase 5 merge: the Phase 3 verifier also performs these record checks and returns the final schema-shaped record, so each candidate gets one fresh independent reviewer instead of two. Every other profile keeps the two passes separate. Never skip independent review of a `confirmed` record in any profile.

For `confirmed`, require it to check:

1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.

For `needs_validation`, require it to check:

1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.

Each verifier returns exactly one JSON object: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","reason":"...","record":{...}}`, with no surrounding prose. A replacement record must match its `confirmed`, `needs_validation`, or `rejected` schema branch. Treat a malformed or prose-wrapped Phase 5 result the same way as in Phase 3: discard it without repairing it and re-run with a fresh verifier when the budget permits.

Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict, including any promotion to `confirmed`, or materially changes the root cause, trace, execution input or observed result, demonstrated impact, or severity. Give that complete replacement to a new independent verifier that did not hunt, perform Phase 3 validation, or propose the Phase 5 replacement. The new verifier rechecks the current source and independently reproduces any decisive local result under the execution boundary, then returns `verified` or another replacement. Apply a material replacement only after this fresh verification. If another material replacement results, repeat with a fresh verifier. If budget or independence is unavailable, remove the disputed record from `findings.json`, keep its ledger unit as an unresolved candidate, and set `run_status: "incomplete"` with an exact `incomplete_reason`. Non-material wording or repository-line corrections may be applied directly when they do not change meaning or evidence.

After every applied replacement, rerun both validators and update linked ledger decisions. If a final verifier identifies a separate root cause, assign a new fingerprint and send it through independent candidate validation before inclusion. Set `run_status: "complete"` only when every ledger candidate has an independent final disposition and every retained record passes Phase 5.

Do not verify only `confirmed` records. A misleading `needs_validation` handoff wastes owner time and can preserve a false premise.
```

# Architecture facts (summary; re-check every line you rely on)

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
  - `_created.html:4-13` (list via `| oneline`, first 20, incomplete notice), `_outbox.html:5-10` (badge, `data-notify`/`data-text` attributes with `f.name`, `href=…{{ f.name | urlencode }}`, `download="{{ f.name }}"`), `_approvals.ht

# Relevant companion blocks (verbatim)

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

<!-- AI-AND-LLM.md#Insecure output rendering -->
**Insecure output rendering**
Model output reaches an executing HTML, Markdown, template, URL, or command sink without the sink's required encoding and policy. For browser rendering, verify auto-loaded resources and CSP or sanitization in `CLIENT-SIDE.md`; renderer behavior outside the repository makes the candidate `needs_validation`.

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

<!-- CLIENT-SIDE.md#DOM-based XSS -->
**DOM-based XSS**
Trace `location` fields, `document.referrer`, `window.name`, message data, storage, and browser-controlled document state into `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs, executable URLs, jQuery HTML APIs, or framework escape hatches. Interpolation escaped by the framework is not a finding.

<!-- WEB-PROTOCOL-AND-AUTH.md#Response-header injection -->
**Response-header injection**
Untrusted data reaches `Location`, `Set-Cookie`, CSP, or another response header with unsafe control characters or normalization. Verify framework rejection before reporting and require a security-relevant response change.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

# Execution boundary and paths

- Agent ID `r-approvals-render`. Write ONLY in `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/r-approvals-render/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" r-approvals-render <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" r-approvals-render /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

# report-schema.json branches (verbatim)

## `confirmed`

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

## `needs_validation`

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

## `rejected`

```json
{
 "type": "object",
 "description": "A source-grounded candidate refuted during validation.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "rejected"
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
  "reason": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
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
  "reason"
 ],
 "additionalProperties": false
}
```
