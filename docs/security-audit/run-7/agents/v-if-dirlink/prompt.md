You are candidate verifier `v-if-dirlink` in run-7 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/projects/sandbox/.scratch/src-audited/` — a git worktree of `main` at commit `3580df0` (after PR #26: 7dbda9e run-6 fixes, 5bb3c17 refactor, IF-1). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/instruction_files.py:kind:instruction-dir-as-final-component-unmatched-so-write-into-linked-dir-skips-approval",
 "title": "write_file into an instruction directory via a directory symlink bypasses the approval gate (kind() never matches an instruction dir as the last path component)",
 "description": "The instruction-file write-approval gate judges the requested path and the single `realpath -m` resolved path with `instruction_files.kind()`. `kind()` only matches a `_DIRS` / `.github` instruction directory when it appears as a non-final path part (`parts[:-1]`); a path whose final component is itself the instruction directory returns None. A source folder (attacker data) can contain a symlink such as `cfg -> .claude`. A prompt-injected agent calling `write_file('/workspace/cfg', <content>)` has `resolve()` return `/workspace/.claude`; both `kind('/workspace/cfg')` and `kind('/workspace/.claude')` are None, so `Policy.decide` matches no instruction rule and falls through `default: allow`. `_call_tool` then executes `write_file`, whose `mv -f -- /workspace/cfg.agentbox-tmp-<hex> /workspace/cfg` resolves the symlink target directory and deposits the attacker content inside `/workspace/.claude/` (as `cfg.agentbox-tmp-<hex>`) with no human approval card ever shown. `.github/instructions` as a final-component symlink target is the same bypass. delete_file is unaffected because a catch-all `delete-file-needs-approval` rule gates every delete.",
 "root_cause": "instruction_files.kind() classifies a directory only by inspecting parts[:-1] against _DIRS/_GITHUB_DIRS and never tests the final component as a directory (scan() works around this by probing kind(rel + '/_'), but _resolved/_policy_args/_preview and Policy.decide pass the bare resolved path). A write whose resolved target is exactly an instruction directory is therefore judged as a non-instruction path and allowed, while write_file's `mv -f` follows the directory symlink at execution time and lands inside that instruction directory.",
 "intended_behavior": "An agent-caused write whose final on-disk target is inside (or is) an instruction directory must be routed to human approval, the same as a write that resolves one level deeper into the directory.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 369,
   "scope": "AgentBox._call_tool",
   "description": "policy.decide(tool, self._policy_args(sid, tool, args)) is the sole write-approval gate; its ALLOW result leads straight to _run_tool."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 235,
   "scope": "AgentBox._resolved / _policy_args",
   "description": "For write_file, resolve(sid, '/workspace/cfg') returns the symlink target '/workspace/.claude', added as resolved_path."
  },
  {
   "kind": "propagation",
   "file": "agentbox/policy.py",
   "line": 226,
   "scope": "Policy.decide match.instruction_files",
   "description": "Hit is computed as kind(args['path']) or kind(args['resolved_path']); both are None for a bare instruction dir, so the instruction-file rule is skipped and evaluation falls through to default: allow."
  },
  {
   "kind": "propagation",
   "file": "agentbox/instruction_files.py",
   "line": 103,
   "scope": "instruction_files.kind",
   "description": "Loop runs over parts[:-1] only, so '.claude'/'.github/instructions' as the final path part is never matched against _DIRS/_GITHUB_DIRS; returns None."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 511,
   "scope": "SandboxManager.write_file",
   "description": "c.exec_run(['mv','-f','--', tmp, p]) with p='/workspace/cfg' a symlink to a directory moves the temp file into /workspace/.claude/, an unapproved write inside an instruction directory."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/instruction_files.py",
   "line": 103,
   "description": "`for i, p in enumerate(parts[:-1]):` the last path component is never tested against _DIRS/_GITHUB_DIRS, so kind() of a bare instruction directory is None."
  },
  {
   "file": "agentbox/policy.py",
   "line": 225,
   "description": "`hit = next((x for x in (args.get('path'), args.get('resolved_path')) if isinstance(x, str) and instruction_files.kind(x)), None)` only kind() of the bare requested/resolved path is checked, with no directory '/_' probe."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 24,
   "description": "Only `instruction-file-write-needs-approval` (tool: write_file, match.instruction_files) gates instruction writes; with no kind() hit a write_file falls through to `default: allow`."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 511,
   "description": "write_file executes `mv -f -- tmp p` as the agent uid using the stored requested path, following the directory symlink at execution time."
  },
  {
   "file": "agents/h-if-policy/artifacts/h.out",
   "line": 1,
   "description": "Sandbox reproduction of the decide() results and the mv-into-linked-directory landing."
  }
 ],
 "conditions": [
  {
   "kind": "data_state",
   "description": "The untrusted source folder (attacker data) contains a symlink whose name is an ordinary word and whose target is an instruction directory, e.g. `cfg -> .claude` or `gh -> .github/instructions`, present in /workspace after create_sandbox."
  },
  {
   "kind": "authorization_role",
   "description": "Lowest-trust agent token (agt_...) for the sandbox; the threat model assumes the agent is prompt-injected."
  },
  {
   "kind": "user_interaction",
   "description": "No human approval occurs; the bypass removes the approval card that the instruction-file write rule is meant to show."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected sandbox agent that wants to drop content into an instruction directory the recipient's other agents treat as config, without the human seeing an approval card.",
  "payloads": [
   "write_file path=/workspace/cfg content=<attacker text>  (with source symlink cfg -> .claude)",
   "write_file path=/workspace/gh content=<attacker text>   (with source symlink gh -> .github/instructions)"
  ],
  "instructions": [
   "Build Policy from agentbox/default_policy.yaml and call decide('write_file', {'path':'/workspace/cfg','resolved_path':'/workspace/.claude'}); observe action 'allow' with rule_id None, versus 'require_approval'/'instruction-file-write-needs-approval' when resolved_path is '/workspace/.claude/commands/x' or path is '/workspace/CLAUDE.md'.",
   "Confirm instruction_files.kind('/workspace/.claude') and kind('/workspace/.github/instructions') are None while kind('/workspace/.claude/settings.json') is 'Claude Code'.",
   "Create a directory .claude, a symlink cfg -> .claude, a file cfg.agentbox-tmp-74833b, and run `mv -f -- cfg.agentbox-tmp-74833b cfg`; observe the file now at .claude/cfg.agentbox-tmp-74833b.",
   "Confirm decide('delete_file', {...}) returns require_approval in all cases (catch-all rule)."
  ],
  "observed_result": "In the approved sandbox: write cfg (resolved=/workspace/.claude) -> ('allow', None); write gh (resolved=/workspace/.github/instructions) -> ('allow', None); write cmds (resolved=.claude/commands/x) -> require_approval; write CLAUDE.md -> require_approval; delete cfg and delete foo -> require_approval; real `mv -f -- cfg.agentbox-tmp-74833b cfg` produced .claude/cfg.agentbox-tmp-74833b."
 },
 "remediation": {
  "strategy": "Classify a path as an instruction target when its final component is itself an instruction directory. Where the write/delete target is resolved for policy and preview, also test the directory form, mirroring scan()'s `kind(rel + '/_')` probe, for both the requested path and resolved_path.",
  "code_changes": [
   {
    "file_name": "agentbox/policy.py",
    "fixed_code": "                hit = next((x for x in (args.get(\"path\"), args.get(\"resolved_path\"))\n                            if isinstance(x, str) and (instruction_files.kind(x) or instruction_files.kind(x.rstrip('/') + \"/_\"))), None)"
   },
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "            real = self._resolved(sid, tool, args)\n            def _k(x):\n                return x and (IF.kind(x) or IF.kind(x.rstrip('/') + \"/_\"))\n            k = _k(p) or _k(real)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Deterministic given the two threat-model-granted capabilities (attacker-controlled source folder provides the directory symlink; prompt-injected agent issues one write_file)."
  },
  "impact": {
   "score": "low",
   "reason": "An unapproved write is deposited inside an instruction directory, but write_file forces a random `.agentbox-tmp-<hex>` basename on the mv-into-directory, so the landed file does not carry a name recipient agents auto-load by name; delete_file is fully gated."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Root cause, policy decision, and the mv-into-symlinked-directory landing were demonstrated in the approved sandbox and match the parent-live real-container observation."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Policy%20target%20versus%20write%20target%20for%20instruction%20files%3A%20service._resolved%2F_policy_args%2F_preview%20%28service.py%3A235-289%29%2C%20SandboxManager.resolve%20%28sandbox.py%3A487-496%29%2C%20write_file%20tmp%2Bmv%20and%20delete_file%20%28sandbox.py%3A502-525%29%2C%20Policy.decide%20match.instruction_files%20with%20resolved_path%20%28policy.py%3A214-232%29%2C%20default_policy.yaml%20version%204%20rule%20order%2C%20decide%28%29%20executing%20stored%20args%20%28service.py%3A520-575%29::An%20agent-caused%20write%20or%20delete%20must%20not%20land%20in%20an%20instruction%20file%20or%20instruction%20directory%20without%20approval.%20Invariant%3A%20the%20object%20policy%20judged%20%28requested%20path%20or%20the%20single%20realpath%20-m%20at%20decide%20time%29%20is%20the%20object%20mv%2Frm%20finally%20touches%2C%20including%20directory%20links%20as%20the%20last%20component%2C%20links%20changed%20between%20decide%20and%20execution%20or%20during%20the%20approval%20wait%20%28by%20allowlisted%20exec%2C%20write_file%2C%20GUI%20tools%20or%20concurrent%20calls%29%2C%20and%20resolve%28%29%20failures%20%28timeouts%2C%20errors%2C%20concurrency%29%20cannot%20be%20induced%20to%20fall%20back%20to%20the%20requested%20path%3B%20user%20policies%20mixing%20instruction_files%20with%20other%20rules%20evaluate%20in%20a%20safe%20order.::agentbox%2Fservice.py%23_resolved%2F_policy_args%2F_preview%2F_call_tool%2Fdecide%20%2B%20agentbox%2Fsandbox.py%23resolve%2Fwrite_file%2Fdelete_file%20%2B%20agentbox%2Fpolicy.py%23decide%20%2B%20agentbox%2Fdefault_policy.yaml::DESKTOP-MOBILE-AND-LOCAL-IPC.md%23Local%20file%20ownership%20and%20TOCTOU",
  "surface": "Policy target versus write target for instruction files: service._resolved/_policy_args/_preview (service.py:235-289), SandboxManager.resolve (sandbox.py:487-496), write_file tmp+mv and delete_file (sandbox.py:502-525), Policy.decide match.instruction_files with resolved_path (policy.py:214-232), default_policy.yaml version 4 rule order, decide() executing stored args (service.py:520-575)",
  "boundary": "An agent-caused write or delete must not land in an instruction file or instruction directory without approval. Invariant: the object policy judged (requested path or the single realpath -m at decide time) is the object mv/rm finally touches, including directory links as the last component, links changed between decide and execution or during the approval wait (by allowlisted exec, write_file, GUI tools or concurrent calls), and resolve() failures (timeouts, errors, concurrency) cannot be induced to fall back to the requested path; user policies mixing instruction_files with other rules evaluate in a safe order.",
  "local_checks": [
   {
    "agent_id": "h-if-policy",
    "reviewed_paths": [
     "agentbox/default_policy.yaml",
     "agentbox/instruction_files.py",
     "agentbox/policy.py",
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "A write_file whose resolved target is an instruction directory, and a delete via a directory-symlink last component, must require approval; resolve() failure must not weaken the gate; delete_file must stay gated.",
    "method": "local",
    "result": "kind('/workspace/.claude') and kind('/workspace/.github/instructions') return None because kind() never compares the last path part to _DIRS/_GITHUB_DIRS (only parts[:-1]); so Policy.decide('write_file',{path:'/workspace/cfg',resolved_path:'/workspace/.claude'}) returns ('allow',None) and the write runs with no approval, while a resolved target one level deeper ('/workspace/.claude/commands/x') and a direct 'CLAUDE.md' both return ('require_approval','instruction-file-write-needs-approval'). The '.github/instructions' bare final component also returns ('allow',None). A real `mv -f -- cfg.agentbox-tmp-74833b cfg` with cfg a symlink to a dir lands the file at .claude/cfg.agentbox-tmp-74833b, matching the parent-live observation. delete_file returns ('require_approval','delete-file-needs-approval') for both the symlink case and an ordinary path (catch-all delete rule), so delete has no mirror bypass. resolve() failure fallback is not needed for this bypass: resolve() succeeds and returns the bare dir.",
    "artifact": "agents/h-if-policy/artifacts/h.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint

```json
- none
```

# Parent-live evidence

- `agents/parent-live/artifacts/recon_leads_live.out` (at `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/parent-live/artifacts/recon_leads_live.out`)

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
  - `_created.html:4-13` (list via `| oneline`, first 20, incomplete notice), `_outbox.html:5-10` (badge, `data-notify`/`data-text` attributes with `f.name`, `href=…{{ f.name | urlencode }}`, `download="{{ f.name }}"`), `_approvals.html:9-13`

# Relevant companion blocks (verbatim)

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Establish the realistic local or remote-content attacker: another app, another OS user, a sandboxed child, an untrusted document, or a remote origin. Self-harm within the same account and authority is not a boundary violation.
- Paths, process names, bundle/package IDs, and claimed sender fields are not peer authentication. Use OS peer credentials, code identity, capability handles, or protected channel state.
- The native bridge or helper must authorize each operation and final resource after parsing. A trusted UI or broker does not make attacker-influenceable arguments trusted.
- OS sandbox, signing, entitlements, permissions, keychain ACLs, exported-component policy, and prompt behavior are real controls when pinned and visible.
- Use `confirmed` for source evidence plus bounded local/emulator tests. Use `needs_validation` when signing, manifest merge, OS version, device policy, installer ACL, or packaging is required but not observable.
```

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU -->
**Local file ownership and TOCTOU**
The app checks a file/path then follows replacement, symlink, mount, or case/normalization changes during a privileged read/write. Use descriptor-relative operations and verify final ownership. Focus `MEMORY-SAFETY-AND-BINARY.md` on parsing after the file is opened.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves -->
## Universal moves (apply across the above)

- Enumerate every process, app component, local endpoint, URI scheme, file association, webview origin, and helper. Record OS identity, runtime privilege, caller, and callable operation.
- Read final packaging inputs: merged manifest, entitlements, installer rules, native-messaging registration, protocol handlers, and ACL creation. Source declarations can be overwritten downstream.
- Validate with dummy profiles and non-sensitive local fixtures on an isolated machine/emulator. Do not interact with other users' apps, credentials, or production services.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the attacker starting capability, OS/app principal crossed, entry channel, accepted argument or state, and unauthorized operation or disclosure.
2. Confirm OS sandbox, peer credential, signing, entitlement, permission, user-consent, and installer controls that apply. Unknown packaging/runtime facts require `needs_validation`.
3. For webview bridges, cite both navigation/origin control and privileged native sink. For IPC, cite peer authentication and per-resource authorization. For helpers, verify final normalized destination.
4. Keep local tests bounded and use dummy content/accounts. Stop after proving the boundary result; do not extend proof into persistence or broader system modification.
5. Return `confirmed` only with a complete source and local evidence chain. Return `needs_validation` with the exact OS, manifest, signing, ACL, or device-lifecycle fact required.

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement -->
**Policy and query disagreement**
Row-level policy, ORM default scopes, authorization filters, and raw/bypass clients apply different predicates. Check joins, aggregates, aliases, views, transactions, `unscoped` or service clients, and error paths where context is missing.

<!-- ATTACK-CLASSES.md#Access control -->
**Access control** (subagent_type: `general`)
Verify that a caller cannot do something outside its authority. Go beyond checking whether permission checks exist — verify they check the *right* permission for the *right* resource via the *right* mechanism:
- Is there a path to the same state change that checks a different (weaker) permission?
- Can a field in the request body override what the permission system intended to restrict?
- Are there endpoints that gate on authentication but forget authorization?
- Does the same resource have multiple access paths with inconsistent checks?
- What about bulk/batch/export/import operations — do they enforce per-item permissions?

# Verifier instructions (verbatim)

```text
You did not write this candidate. Try to refute it from repository source and bounded
local evidence. Do not contact deployed endpoints or external/shared services. Run
target-controlled code only inside the approved OS-enforced sandbox: no external
network, empty allowlisted environment, read-only target and tools, scratch-only
writes, and explicit low resource and wall-clock limits. If any control is unavailable,
do not execute; retain the exact missing capability as a needs_validation blocker.
Treat every scratch entry as target-controlled after execution. After the sandbox and
all its processes terminate, only trusted parent-side code may promote a predeclared
scratch-relative file, following the promotion procedure block included verbatim in
this prompt. You and target code never write retained artifacts. If promotion is
unavailable or fails, do not use that file as evidence.

1. Verify every trace and evidence file, positive line number, scope, and description.
   Confirm the first entry is a real lower-trust entrypoint and the last is the
   claimed sink or boundary effect.
2. Reconstruct the strongest source-visible validation, identity, authorization,
   normalization, lifecycle, framework, and containment controls on the path.
   Where the architecture summary names a comparable baseline, note whether it
   shares the pattern — as calibration, never as grounds to dismiss.
3. For a proposed confirmed candidate, independently reproduce the minimum observed
   result when possible. Verify inputs, interface shape, conditions, and affected
   dummy principal/resource. Do not infer a stronger result or continue after it.
4. Verify that likelihood, impact, confidence, and the proposed source fix match only
   what the evidence establishes.
5. For a proposed needs_validation candidate, decide whether the blocker is genuinely
   outside source/local observation. If source refutes the trace, reject it. If the
   missing fact remains decisive, keep needs_validation and make the local and
   owner-observed plans exact and non-destructive.
6. Preserve the fingerprint for the same source-derived root cause across every state.

Return exactly one JSON object and no surrounding prose:
{"decision": "confirmed|needs_validation|rejected", "record": { ... }}
where record exactly matches the decision's verdict branch of the schema included
in this prompt. A corrected record replaces the hunter's wording.
```

# Artifact promotion procedure (verbatim)

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

# Execution boundary and paths

- Agent ID `v-if-dirlink`. Write ONLY in `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/v-if-dirlink/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" v-if-dirlink <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" v-if-dirlink /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-if-dirlink/artifacts/<file>`.
- Your final message must be ONLY the JSON object `{"decision": ..., "record": {...}}` plus that optional field. No prose, no code fence.

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
