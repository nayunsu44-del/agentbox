You are candidate verifier `v-policy-cpu` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap",
 "title": "Agent exec command of up to 8 MiB drives minutes of GIL-holding policy parsing per call, slowing the shared control plane",
 "description": "An agent token can POST /sandboxes/{sid}/tools/exec with a command of shell-punctuation tokens (e.g. 'x;x;x;...') up to the 8 MiB AGENTBOX_MAX_BODY. No per-command length cap exists anywhere before Policy.decide. With the default policy, command_names calls _words, which constructs a new shlex.shlex for every token that contains a punctuation character, including each bare ';'. That costs about 38 us per token: 4.85 s for 128 KiB, linear, so about 310 s for one 8 MiB call. The work runs on the shared tool_pool and holds the process GIL. One agent can keep 4 such calls running (tool_concurrency). The run happens before the pending-approval cap, so that cap does not stop it. A stand-in event-loop thread slowed from 2.2 ms median / 2.7 ms max to 8.6 ms median / 88.8 ms max while 4 calls ran, and each call's wall time stretched to about 25 s. The control plane degrades (it is not frozen) for every human request and every other sandbox for as long as the agent re-issues calls.",
 "root_cause": "Policy evaluation has no input-size bound. AgentBox.call_tool/_call_tool pass args['command'] of any length to Policy.decide (service.py:311). The only limit is the 8 MiB HTTP body cap. _words (policy.py:40-62) re-lexes every token that contains a shell punctuation or whitespace character with a fresh shlex.shlex instance (policy.py:45, 60-61). shlex.__init__ is expensive (str.translate of wordchars), so cost is about 38 us per punctuation token, and an 8 MiB command holds about 4M such tokens.",
 "intended_behavior": "An agent-supplied command or argument longer than a small fixed bound (e.g. 64 KiB) is rejected (400/413) or sent straight to REQUIRE_APPROVAL without full parsing, before policy.decide and preview run. _words does not re-lex tokens made only of punctuation, so evaluation costs at most milliseconds and human requests keep their normal latency.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "call_tool route",
   "description": "An agent token posts {\"args\":{\"command\":\"x;\"*N}}. ToolCall.args is an unbounded dict (api.py:54-55), limited only by _BodyLimit at 8 MiB (config.py:65)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 278,
   "scope": "call_tool route",
   "description": "Dispatched to the shared 32-thread tool_pool (api.py:160) via run_in_executor. A client disconnect does not cancel the job."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 287,
   "scope": "AgentBox.call_tool",
   "description": "Admits up to tool_concurrency (4) concurrent calls per sandbox, with no size check."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 311,
   "scope": "AgentBox._call_tool",
   "description": "policy.decide(tool, args) runs after the tool_request audit row and before the pending-approval cap (service.py:326)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/policy.py",
   "line": 211,
   "scope": "Policy.decide",
   "description": "The rm-curl-needs-approval rule (default_policy.yaml:12-17) calls command_names(cmd) on the whole command."
  },
  {
   "kind": "sink",
   "file": "agentbox/policy.py",
   "line": 61,
   "scope": "_words",
   "description": "Each token containing a punctuation char (every ';') is recursively re-lexed with a new shlex instance (policy.py:45). This is about 38 us per token, holding the GIL."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/policy.py",
   "line": 60,
   "description": "Recursion condition: any token with whitespace or a char in _SHELL_PUNCT, including a bare ';' token, triggers _words(t, depth+1), which builds a new shlex (line 45)."
  },
  {
   "file": "agentbox/service.py",
   "line": 311,
   "description": "decide is called with the raw command. No length check exists in call_tool/_call_tool (service.py:279-311). grep finds no command-length constant in agentbox/."
  },
  {
   "file": "agentbox/config.py",
   "line": 65,
   "description": "max_body_bytes defaults to 8 MiB, the only bound on the command length."
  },
  {
   "file": "agentbox/service.py",
   "line": 286,
   "description": "Per-sandbox tool_concurrency (default 4) allows 4 concurrent evaluations per agent. tool_pool has 32 workers across sandboxes (api.py:160)."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Requires the sandbox's agent token, which is the lowest-trust principal and is assumed prompt-injected by the threat model."
  },
  {
   "kind": "system_configuration",
   "description": "Default AGENTBOX_MAX_BODY (8 MiB), default policy with an exec 'commands' rule (rm-curl-needs-approval), default tool_concurrency 4."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding its own sandbox's agent token repeatedly sends exec tool calls whose command is a long run of 'x;' tokens. Each call is eventually queued as an approval (or 429 by the pending cap), but only after Policy.decide has consumed CPU in proportion to the command length.",
  "payloads": [
   "{\"args\":{\"command\":\"x;x;x;...\"}} with 'x;' repeated 65536 times (131072-byte command)",
   "Policy.load('agentbox/default_policy.yaml').decide('exec', {'command': 'x;' * 65536})"
  ],
  "instructions": [
   "In the parent-approved sbx (no network, uid 65534, 512 MiB, 1 CPU, 120 s, audited source read-only at /target), load the default policy with agentbox.policy.Policy.load and time Policy.decide('exec', {'command': s}) for s = 'x;'*n at 16/32/64/128 KiB, plus 'x|', 'a ' and 'rm a a ...' shapes. Profile the 16 KiB case with cProfile.",
   "In the same harness, run an asyncio probe on the main thread (40 iterations of a fixed 20000-step Python loop plus await asyncio.sleep(0.001)) alone, with 1 thread, and with 4 threads each running decide on the 128 KiB 'x;' command. Record median, max and total probe latency and each decide's wall time."
  ],
  "observed_result": "decide('x;' * n): 16 KiB 0.641 s, 32 KiB 1.318 s, 64 KiB 2.593 s, 128 KiB 4.845 s (linear, ~38 us per token). 'x|' was the same, 'a ' 0.199 s at 128 KiB, and 'rm a a...' 0.108 s at 128 KiB. cProfile: command_names to _words took 2.30 of 2.53 s, with 65538 shlex.__init__ calls (1.02 s) and str.translate (0.78 s). Probe baseline median 2.2 ms / max 2.7 ms / total 0.09 s. With 1 decide thread: 7.5 / 10.1 ms / 0.31 s. With 4 decide threads: 8.6 / 88.8 ms / 0.90 s, and each decide's wall time stretched to 24.3-25.0 s. Extrapolation: about 310 s CPU for one 8 MiB call (not run). (agents/h-policy-cpu/artifacts/h.out, agents/h-policy-cpu/artifacts/h2.out)"
 },
 "remediation": {
  "strategy": "Bound the input before any parsing, and remove the per-token re-lex. In AgentBox._call_tool (before the tool_request audit row and policy.decide), refuse an exec command or any string argument longer than a fixed TOOL_ARG_MAX (e.g. 64 KiB) with 413/400 and a tool_blocked audit row. Alternatively, route it directly to REQUIRE_APPROVAL with a fixed 'too long to analyse' preview, skipping command_names and preview_command. In _words, skip recursion for tokens made only of punctuation and recurse only on tokens that contain whitespace or '$(' or '`'. Add a regression test asserting that decide on a 64 KiB 'x;' command finishes in under ~100 ms and that a 1 MiB command is rejected or approval-routed without calling command_names.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "TOOL_ARG_MAX = 64 * 1024\n...\n    def _call_tool(self, sid, tool, args, actor):\n        if tool not in TOOLS:\n            raise ServiceError(404, ...)\n        self.sandboxes.get(sid)\n        if any(isinstance(v, str) and len(v) > TOOL_ARG_MAX for k, v in args.items() if k != \"content\"):\n            self.log_best_effort(sid, tool, \"tool_blocked\", {\"reason\": \"argument_too_long\", \"limit\": TOOL_ARG_MAX})\n            raise ServiceError(413, f\"도구 인자가 너무 김 (최대 {TOOL_ARG_MAX}자)\")\n        ..."
   },
   {
    "file_name": "agentbox/policy.py",
    "fixed_code": "    for t in tokens:\n        if not t:\n            continue\n        cleaned = ...\n        out.extend(cleaned.split())\n        if all(c in _SHELL_PUNCT for c in t):\n            continue  # 순수 구분자 토큰은 다시 렉싱하지 않는다\n        if any(c.isspace() for c in t) or any(c in _SHELL_PUNCT for c in t):\n            out.extend(_words(t, depth + 1))"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "A single agent-token request with a default configuration triggers it, and a prompt-injected agent can repeat it indefinitely. No approval or human action is needed first."
  },
  "impact": {
   "score": "low",
   "reason": "Measured effect is degradation, not denial. One agent's 4 concurrent calls slowed a same-process stand-in loop about 4x at the median and up to 33x at the max, for minutes per call at the body cap. The control plane keeps answering, and the effect ends when the calls finish. Several hostile sandboxes would worsen it, but that was not measured."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The CPU cost, linear growth and GIL contention were measured directly on the audited code with the default policy. The real server's latency under uvicorn on the host's CPU count, and the full 8 MiB figure, are extrapolated, not observed."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2Fexec%20%28and%20any%20tool%20whose%20argument%20text%20reaches%20Policy.decide%20and%20preview_command%29%20with%20a%20long%20or%20adversarially%20shaped%20command%2C%20run%20on%20the%20tool_pool%20thread%20before%20any%20approval%20exists%2C%20plus%20the%20approval-card%20render%20of%20the%20same%20text::Agent%20to%20control-plane%20availability%3A%20pure-Python%20policy%20and%20preview%20parsing%20%28Policy.decide%2C%20_split_segments%2C%20shlex%20passes%2C%20_raw_hits%2C%20preview%20glob%2Fwalk%29%20of%20an%20agent%20command%20up%20to%20the%208%20MiB%20body%20cap%2C%20with%20no%20per-command%20length%20cap%2C%20holds%20the%20GIL%20shared%20with%20the%20event%20loop%20and%20human%20threads%20%28hunter%20measurement%3A%204.96%20s%20for%20a%20128%20KiB%20command%2C%204%20concurrent%20per%20sandbox%29.%20Invariant%3A%20no%20agent-supplied%20argument%20makes%20evaluation%20cost%20more%20than%20a%20small%20bounded%20amount%20of%20CPU%2C%20memory%20or%20container%20exec%20time%20before%20rejection%20or%20queueing%2C%20and%20the%20human%20API%20stays%20responsive.::agentbox%2Fpolicy.py%23decide%2F_words%2Fcommand_names%2F_raw_hits%2Fsimple_programs%2Fhas_bash_comment%20%2B%20agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%20%28container-side%20glob%20and%20find%2C%20no%20timeout%29%20%2B%20agentbox%2Fservice.py%23call_tool%2F_call_tool%2F_logged_args%20%2B%20agentbox%2Fapi.py%23tool%20route::Resource%20exhaustion%3A%20algorithmic%20complexity%20and%20worker%20starvation",
  "surface": "POST /sandboxes/{sid}/tools/exec (and any tool whose argument text reaches Policy.decide and preview_command) with a long or adversarially shaped command, run on the tool_pool thread before any approval exists, plus the approval-card render of the same text",
  "boundary": "Agent to control-plane availability: pure-Python policy and preview parsing (Policy.decide, _split_segments, shlex passes, _raw_hits, preview glob/walk) of an agent command up to the 8 MiB body cap, with no per-command length cap, holds the GIL shared with the event loop and human threads (hunter measurement: 4.96 s for a 128 KiB command, 4 concurrent per sandbox). Invariant: no agent-supplied argument makes evaluation cost more than a small bounded amount of CPU, memory or container exec time before rejection or queueing, and the human API stays responsive.",
  "local_checks": [
   {
    "agent_id": "h-policy-cpu",
    "reviewed_paths": [
     "agentbox/policy.py",
     "agentbox/default_policy.yaml",
     "agentbox/service.py",
     "agentbox/api.py",
     "agentbox/config.py"
    ],
    "invariant": "Policy.decide on an agent exec command costs a small bounded amount of CPU before the call is rejected or queued. A length cap sits before decide.",
    "method": "local",
    "result": "No per-command or per-argument length cap exists. ToolCall.args is an unbounded dict (api.py:54-55), and the only limit is _BodyLimit max_body_bytes, 8 MiB (config.py:65). The route runs box.call_tool on the shared 32-thread tool_pool (api.py:160, 277-278). call_tool admits 4 per sandbox (service.py:286-290). _call_tool writes the tool_request audit row and then calls policy.decide (service.py:309-311), before the pending-approval cap (service.py:326). Measured in sbx (Python 3.13, 1 CPU), default policy, 'x;'*n: 16/32/64/128 KiB took 0.64/1.32/2.59/4.85 s. 'x|' gave the same. 'a '*n took 0.025-0.20 s, and 'rm a a ...' took 0.014-0.108 s. Growth is linear, not superlinear, but the constant is large: about 38 us per shell-punctuation token. cProfile shows command_names to _words taking 2.30 of 2.53 s. _words builds a new shlex for every token that contains punctuation, even a bare ';' (policy.py:45, 60-61), and shlex.__init__ plus str.translate account for 1.0 s and 0.78 s. has_bash_comment (0.008 s), simple_programs (0.096 s), _raw_hits (0.002 s) and _split_segments (0.099 s) at 64 KiB are minor. Linear extrapolation gives about 310 s of GIL-holding CPU for one 8 MiB call.",
    "artifact": "agents/h-policy-cpu/artifacts/h.out"
   },
   {
    "agent_id": "h-policy-cpu",
    "reviewed_paths": [
     "agentbox/policy.py"
    ],
    "invariant": "While agent policy evaluation runs, other Python threads in the same process (event loop, human request threads) stay responsive.",
    "method": "local",
    "result": "An asyncio stand-in loop in the main thread ran a fixed small CPU unit plus a 1 ms sleep, 40 times. Baseline: median 2.2 ms, max 2.7 ms, total 0.09 s. With 1 concurrent Policy.decide('x;'*65536, i.e. 128 KiB): median 7.5 ms, max 10.1 ms, total 0.31 s. With 4 concurrent (the per-sandbox tool_concurrency default): median 8.6 ms, max 88.8 ms, total 0.90 s, and each decide's wall time stretched from 5.6 s to about 24.9 s. The GIL switch interval is 5 ms, so other threads are slowed in proportion to the number of runnable decide threads (about 4x median, 33x max with one agent's 4 slots), not frozen. Several sandboxes' agents would add up to 32 tool_pool threads.",
    "artifact": "agents/h-policy-cpu/artifacts/h2.out"
   },
   {
    "agent_id": "h-policy-cpu",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "Preview of a REQUIRE_APPROVAL exec command costs a bounded number of container execs and a bounded amount of exec time before the approval is created.",
    "method": "local",
    "result": "_call_tool calls _preview (service.py:331-332) to SandboxManager.preview (sandbox.py:584-587) to preview_command. For every rm operand, preview calls expand(op) (preview.py:88-89), and for every match under -r it calls walk(m, limit) (preview.py:96). Each of these is one synchronous docker exec_run with no container-side timeout (_expand sandbox.py:568-574, _walk sandbox.py:576-582), unlike the _timed manifest/read execs. 'limit' only truncates 'affected' after all execs have run (preview.py:126-128). Counted with stub callbacks: 'rm -r d d ...' at 16 KiB gave 8189 expand + 8189 walk calls; at 64 KiB, 32765 + 32765. 'rm -r *' over 5000 workspace entries gave 1 expand + 5000 walk calls. Scaled to the 8 MiB cap, that is about 4.2M expand plus 4.2M walk execs, run serially on one tool_pool thread, with no deadline and no cancellation on client disconnect. The real per-exec latency and Docker-daemon impact need the live daemon (not available in sbx).",
    "artifact": "agents/h-policy-cpu/artifacts/h2.out"
   },
   {
    "agent_id": "h-policy-cpu",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/templates/_approvals.html",
     "agentbox/approvals.py",
     "agentbox/audit.py"
    ],
    "invariant": "Preview output and the approval-card render of an agent command stay bounded in memory and size.",
    "method": "local",
    "result": "preview_command appends one note per unrecognised segment with no cap (preview.py:122-125). Measured: 32/128/512 KiB 'x;' commands gave 16384/65536/262144 notes and preview JSON of 1.46/5.83/23.3 MB, a constant 44.5x. tracemalloc peak was 14.8/59.4 MiB at 128/512 KiB, which extrapolates to about 950 MiB for 8 MiB. ApprovalStore.create json.dumps the raw preview into the pending row (approvals.py:49-59). _approvals.html renders every note (line 16) and the full command (line 8) for pending rows. The audit copy is bounded by bound_payload (audit.py:141-152). This is the same root cause, and the same remediation (a NOTES_MAX cap in preview.py), as the already-filed h-approvals finding agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention, which measured the 5832767-byte preview and the 7.47 MB card. It is consolidated there, not re-filed.",
    "artifact": "agents/h-policy-cpu/artifacts/h2.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-4 wording)

```json
- none
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-5)
Source ref: `346df29` (`main`, after fix PRs #16-#23). Profile `standard`, focused follow-up, budget 30. This file is the run-4 architecture (built at `9805d91` from recon-1a..1d) plus a parent-written delta in section 0. No reconnaissance agent was spent in run-5: the parent re-read every file changed since `9805d91` (15 files, +712/-148 in `agentbox/`). **Line numbers in sections 1-8 are run-4 (`9805d91`) numbers and are approximate in this tree; section 0 numbers are current.**
## 0. Run-5 delta (current line numbers, `346df29`)
- **Body cap (F1 fix, PR #16).** `api.py:89-148` `_BodyLimit` pure-ASGI middleware, added at `api.py:170`, runs before routing and auth for every `http` scope (not `websocket`). Cap = `max_upload_body_bytes` (`AGENTBOX_MAX_UPLOAD_BODY`, 256 MiB) when `POST` and path fullmatches `/sandboxes/[^/]+/files` (`api.py:86`), else `max_body_bytes` (`AGENTBOX_MAX_BODY`, 8 MiB) (`config.py:65-66`). Content-Length over cap or non-digit → 413 without reading; streamed bodies are counted in `limited_receive` and cut with a fake `http.disconnect`. Upload route `api.py:335-352` authenticates (`screen_human`) then reads `request.form()` and each file with `read(limit+1)` (`max_upload_bytes` 50 MiB). `deploy/Caddyfile` adds `request_body` caps. `web.py` has its own upload form (`web.py:~229`).
- **Audit cap (F3 fix, PR #16).** `audit.py:126-152` `_bound`/`bound_payload` bound every payload before hashing (strings 64 KiB, lists 200, row 128 KiB); `AuditLog.append` (`audit.py:281`).
- **GUI gate (F2) and quota recheck (F7), PR #17.** `_run_tool` refuses GUI input without an open burst (`GuiBursts.covers`, `gui_bursts.py:68`); allow-path commit rechecks `_over_snapshot_quota` (`service.py:254`) and logs `tool_blocked`/`snapshot_quota_changed`.
- **Lifecycle lock (F6), F4, F5, F8, PR #18.** `AgentBox._lifecycle` (`service.py:500`) serialises pause/resume/snapshot/restore/delete per sandbox; `SandboxManager.restore` refuses `deleted`. Preview `_expand`/`_walk` use NUL-separated output. `extract_novnc` (`sandbox_desktop.py:174`) single-flight with 60 s negative cache. Login failures rate-logged (`web.py:102-114`, 5/min + `suppressed_before`); token compare on bytes.
- **Control-character filter (N5, PR #19).** `display.escape_controls` escapes Unicode categories Cc/Cf/Zl/Zp; shared by `web._shown` and `cli._safe`.
- **Disk guard and approval compaction (N2 stage 1, PR #20).** `AgentBox.disk_low` (`service.py:388-404`) uses `shutil.disk_usage(db_path.parent).free < min_free_bytes` (`AGENTBOX_MIN_FREE`, 256 MiB; 0 disables); `call_tool` (`service.py:279-285`) refuses **agent** calls with 507; `api.py:313` skips the agent `approval_forbidden` row while low; state changes log `disk_low`/`disk_ok` only on transitions. `_finish` (`service.py:406-411`) rewrites finished approval rows' `args` with `_logged_args` (size/sha256/16 KiB head) and `preview` with `bound_payload` via `ApprovalStore.finish(..., args, preview)` (`approvals.py:91-100`, `COALESCE`). Pending rows still hold raw args/preview (`approvals.py:49-59`). `decide` maps a `claim` `sqlite3.Error` to 503; `expire_stale` (`service.py:422-438`) returns on `sqlite3.Error`. `_approvals.html` shows `args.args_head` for compacted rows.
- **Prune and anchor (N2 stage 2, PR #21).** `retention.py` (new): `prune(db_path, before, archive, dry_run)` — host CLI only (`cli.py:319` `cmd_prune`, `agentbox prune --before --archive [--dry-run]`), never HTTP. Plan: audit rows with `id < MIN(id WHERE ts >= cutoff)`, approvals with status in denied/executed/failed/expired and `created_at < cutoff` (`retention.py:54-64`). Archive written outside the DB lock with `open(path, "xb")` + gzip + fsync, sha256 (`:67-84`). Then `BEGIN IMMEDIATE`: concurrent-prune check, `DROP TRIGGER audit_no_delete`, `DELETE`, recreate trigger from `NO_DELETE_SQL`, insert `audit_anchor` row (always, even approvals-only), delete approvals, `insert_record(... "audit_pruned" ...)`, `COMMIT`; on any exception rollback and unlink the archive (`:105-132`). `audit.py`: `audit_anchor` table with no-update/no-delete triggers (`:44-55`), `latest_anchor:178`, `check_chain:184`, `read_archive:208` (gzip JSON Lines, header format check), `insert_record:228` (chains from last row else latest anchor else GENESIS; `append` uses it), `verify:336` (starts at latest anchor; anchor + empty table fails), `verify_archives:351` (GENESIS → each archive must match its anchor's sha256/last row → live table). `cli.py:299` `cmd_verify --archive` runs `verify_archives` locally against `Settings().db_path`. Known limit (README): anchor lives in the same DB, so a DB writer can forge it.
- **Window owner via XRes (N4, PR #22).** `sandbox_desktop.py:42-75` `_WINDOW_OWNERS` ctypes script (libX11 + libXRes `XResQueryClientIds` mask 2 → `XResGetClientPid`); `desktop_processes` (`:77-~95`) runs `sh -c 'xdotool search --onlyvisible --name . 2>/dev/null | xargs -r /usr/bin/python3 -I -c "$0"' <script>` as the desktop user inside the container; nonzero exit → no window pids (fail-closed: more strays). `gui_state._new_processes:53` returns `(stray, kept)`; `gui_kept:95`. `gui_bursts._stop_strays:89` stores `_kept[sid] = (container_id, pids)` and logs `gui_processes_kept`; `open:73` removes kept pids from the next baseline when the container id matches.
- **Docs (PR #23).** LLM-provider data path documented as an accepted limitation; out of scope for hunting.
Unchanged since run-4 and not re-hunted: N1 (`same_origin` scheme) and N3 (container output readers) remain needs_validation.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full JSON API (`api.py:115` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py:157` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py:356`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates, `cli.py:68-111`; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default (`cli.py:124-126`), and the bare `create_app` factory (`api.py:376`) that skips the serve-time gates. Container flags (`sandbox.py:243-265`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Docker 29.9.1, runtimes `runc`/`io.containerd.runc.v2` only, cgroup v1, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1` (rebuilt from this tree). Agent-run code goes through `tools/sbx` (no network, read-only target, 256 MiB loop scratch, uid 65534, 512 MiB, 64 pids, 120 s; `agentbox.web`/`api` importable). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`; fakes for `GuiBursts`/`AgentBox` in `test_m2_unit.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (`service.py:268`, per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (`service.py:290`: audit with capped args `_logged_args:181` → `policy.decide` → quota → approval or `_snapshot:250` → `_run_tool`) on the 32-thread `tool_pool` (`api.py:103`). Pending approvals capped at 20 (`service.py:44`).
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide` (`service.py:389`): atomic claim, snapshot, run stored args. Runs on the Starlette threadpool, outside `tool_pool`, `_busy` and `_snap_locks`. Preview (`preview.py:67` `preview_command` with `_expand`/`_walk` callbacks, `sandbox.py:557-569`) and capture run before the approval exists.
- **Lifecycle** (refactor PR 1): `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` (`service.py:444-475`), called by `api.py` and `web.py` inside `guard`. Restore: log → `end_desktop` → `sandboxes.restore` → `bursts.reset_timers` → log. Delete: log → `end_desktop` → delete → `drop_captures`. Pause: log → `bursts.end` → pause. None takes `gui_lock` or `_snap_locks`.
- **GUI bursts** (`gui_bursts.py:23`, refactor PR 2): `needs_snapshot:52`, `open:65` (fail-closed baseline, bound to `container_id`), `close:100`/`_finish:113` (stray kill via `gui_state.gui_strays` from root `ps` + `_NET_WM_PID`, manifest diff → `gui_changes`), `close_idle:137` on a dedicated pool from `expire_stale` callers, `end:157`. Timestamps `_gui_input_at`/`_gui_snap_at` are written without a lock.
- **Desktop**: tickets (60 s, one-time, hashed), sessions (12 h, scoped), leases; takeover/handback (`service.py:503,523`, `bursts.close` under `gui_lock`); WS route `api.py:344` (cookie, `same_origin` with missing Origin allowed, mode, `may_connect`) → `desktop_ws.relay:18` (no auth of its own; session re-check every 30 s; x11vnc without `-noremote`/`-safer`).
- **Files**: `read_file`/`write_file`/`delete_file`/`list_dir` (`safe_path`), upload, outbox list/read; `list_dir`, `exists`, `is_dir`, `outbox_list`, `_expand` run `exec_run` with no container-side timeout and full buffering.
- **Rendering**: Jinja autoescape + `finalize=_shown` → `display.escape_controls:18` (shared with `cli._safe`); `_NoFraming` middleware (`api.py:63`) on HTTP responses.
- **Audit**: hash chain + append-only triggers, `mask_text`; `log_human` fails closed with 503 (`service.py:590`); tool results and burst records are best-effort.
## 5. Trust boundaries and strongest control
| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc on this host) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>`/`$` gate |
| Agent → approval 

# Relevant companion blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation -->
**Superlinear parsing, matching, or evaluation**
Small accepted input drives catastrophic regex backtracking, nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort/hash behavior. Derive accepted depth/cardinality and complexity, then demonstrate a bounded growth curve locally.

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

- Agent ID `v-policy-cpu`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-policy-cpu/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-policy-cpu <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-policy-cpu /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish.
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
