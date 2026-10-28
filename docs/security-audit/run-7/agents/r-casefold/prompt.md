You are final record verifier `r-casefold` in run-7 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `/projects/sandbox/.scratch/src-audited/` — a git worktree of `main` at commit `3580df0`. Every path and line must exist in THAT tree (except `agents/...` artifacts which live under `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/...`).

# Record under verification

```json
{
 "fingerprint": "agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed",
 "title": "kind() casefold expands U+0130 and may miss an instruction name that a case-insensitive filesystem treats as canonical",
 "description": "_norm normalizes a name with unicodedata.normalize('NFKC', name).casefold(). Python's full casefold expands LATIN CAPITAL LETTER I WITH DOT ABOVE (U+0130) to 'i' followed by U+0307 COMBINING DOT ABOVE, so kind('gemİni.md') returns None. clean_name accepts the name on the outbox download path, outbox()/_outbox.html show no instruction-file badge, and the write never hit the instruction-file approval rule. If a recipient on a case-insensitive volume equates 'gemİni.md' to 'gemini.md', the human's other coding agent auto-reads attacker content as an instruction file, the same boundary the a0a186c fullwidth/U+017F fix was meant to close. NTFS $UpCase does not equate U+0130 with ASCII 'i', so Windows recipients are not affected; the open question is macOS and other case-insensitive volumes.",
 "claimed_root_cause": "_norm relies on Python's full casefold, which maps U+0130 to an ASCII letter plus a combining mark, diverging from an OS case-insensitive fold that may map U+0130 to plain 'i'; kind() therefore misclassifies a name a case-insensitive filesystem might resolve to a canonical instruction name. A fold that does not introduce combining marks (NFKD, drop Mn, then casefold, verified locally to yield 'gemini.md') would classify it.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/policy.py",
   "line": 225,
   "scope": "Policy.decide, match.instruction_files branch",
   "description": "A prompt-injected agent calls write_file with path 'outbox/gemİni.md'; kind() of path and resolved_path is None, so the instruction-file-write-needs-approval rule does not fire."
  },
  {
   "kind": "propagation",
   "file": "agentbox/instruction_files.py",
   "line": 74,
   "scope": "_norm",
   "description": "casefold() expands U+0130 to 'i'+U+0307, so _norm('gemİni.md')='gemi̇ni.md' and kind() returns None."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 674,
   "scope": "AgentBox.outbox",
   "description": "outbox() calls IF.kind(f['name']) which returns None, so no instruction_file flag or badge is shown."
  },
  {
   "kind": "sink",
   "file": "agentbox/api.py",
   "line": 403,
   "scope": "outbox_file Content-Disposition filename*",
   "description": "The human downloads the file (clean_name accepts the name); on a volume that folds U+0130 to 'i' the saved name could resolve to 'gemini.md'."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/instruction_files.py",
   "line": 74,
   "description": "n = unicodedata.normalize('NFKC', name).casefold(); observed locally (h2.out): kind('gemİni.md')=None while kind('gemini.md')='Gemini CLI'."
  },
  {
   "file": "agents/v-casefold/artifacts/v.out",
   "line": 1,
   "description": "Sandbox: kind('gemİni.md') is None, kind('gemini.md') is 'Gemini CLI', casefold gives 'gemi̇ni.md'; NFKD + drop Mn + casefold gives 'gemini.md'; clean_name accepts the name."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 49,
   "description": "clean_name accepts 'gemİni.md' (observed h2.out), so the name is downloadable from the outbox."
  },
  {
   "file": "agentbox/policy.py",
   "line": 225,
   "description": "decide() keys the instruction-file approval solely on kind(path)/kind(resolved_path)."
  }
 ],
 "blockers": [
  "Whether a real case-insensitive filesystem (APFS or HFS+) equates a filename containing U+0130 with the ASCII-'i' canonical name is not observable on the Linux-only offline host. Full casefold expands U+0130 to 'i'+U+0307, but simple (1:1) case folding, which file-system comparison typically uses, maps U+0130 to itself, so the alias is not established and may well be false.",
  "Whether a recipient coding agent on such a volume loads the aliased name requires that agent and OS at runtime.",
  "NTFS $UpCase is documented not to equate U+0130 with ASCII 'i', so the Windows recipient path is excluded."
 ],
 "validation_plan": {
  "local": "Already run in the approved sandbox (h2.out). Extend by enumerating every character whose casefold expands to an ASCII letter used in _NAMES/_DIRS plus a combining or invisible code point.",
  "deployment": "On an owner-controlled macOS machine with an APFS case-insensitive volume, create a file literally named 'gemİni.md' and check whether `stat gemini.md` resolves to it and whether `ls` shows one or two files. If it aliases, fold names for classification with a mapping that does not introduce combining marks (for example NFKD, drop Mn, then casefold, or special-case U+0130)."
 },
 "verdict": "needs_validation"
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

<!-- ATTACK-CLASSES.md#Resource and file handling -->
**Resource and file handling** (subagent_type: `general`)
- Path traversal (reading/writing outside intended directories) — including through symlinks, encoded sequences, and null bytes
- SSRF (making the application fetch attacker-controlled URLs) — including through redirects, DNS rebinding, and URL parser differentials
- Unsafe deserialization, archive extraction (zip slip), temp file handling
- Memory safety (if applicable): buffer overflows, use-after-free, integer overflow
- Race conditions on file operations (TOCTOU between check and use)

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

<!-- AI-AND-LLM.md#Indirect injection through retrieved or ingested content -->
**Indirect injection through retrieved or ingested content**
An attacker can write a RAG document, indexed page, file, email, issue body, tool response, or metadata that enters a different principal's model context. Trace who can write each source, how retrieval scopes it, whose session consumes it, and what capability is enabled there. Check isolation, resource authorization, and binding to the consuming principal's intent separately. The defect is a missing deterministic control, not persuasive text by itself.

<!-- AI-AND-LLM.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the crossed boundary and observable result: attacker, affected principal or shared resource, execution identity, target, and unauthorized or unrequested action or disclosure.
2. For confused-deputy authority claims, prove the tool lacks requester-and-resource authorization and that the attacker cannot perform the same action normally. For action-binding claims, instead prove attacker-controlled content caused an action under the affected principal's authority that the principal did not intentionally request or approve. Valid generic authorization does not establish that intent.
3. For memory or retrieval claims, cite both the attacker-controlled write and the later cross-principal read or privileged decision. A shared record without a reachable consumer is not enough.
4. For action binding, establish the intentional request or normalized approved object, if any, and compare it with the object the handler uses. Confirm a locally observable unrequested action, mutation, duplicate, or authority change without extending the test into harmful execution. For schema disagreement, compare the normalized validated object with the handler's object.
5. For MCP identity claims, verify the authenticated connection, request correlation, tool namespace, and effective credential. Mark `needs_validation` if external server identity or deployment routing is required.
6. Return `confirmed` findings only with a complete source trace and meaningful result. Return `needs_validation` for a specific unresolved boundary fact and state the bounded local or owner-observed check needed to resolve it.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion -->
**Export and backup scope expansion**
An export, snapshot, portability package, report, or backup includes other tenants, inaccessible object fields, soft-deleted data, secret values, or history above the requester's access. Check per-item authorization after selection and authorization to download the final artifact.

# Execution boundary and paths

- Agent ID `r-casefold`. Write ONLY in `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/r-casefold/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" r-casefold <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" r-casefold /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
