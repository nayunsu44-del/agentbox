You are final record verifier `rv-policy-cpu` in run-5 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Why you are seeing this record (material replacement)

This record is a replacement proposed by the Phase 5 verifier `r-policy-cpu` for a confirmed record (Phase 3 by `v-policy-cpu`). It keeps verdict, severity and trace locations, and changes wording of the root cause and description, the observed result (new measurements and token shapes), intended behaviour and remediation (it argues a 64 KiB cap plus skipping pure-punctuation tokens is not enough). Under the skill a replacement that touches root cause or execution is applied only after a fresh independent verifier checks it; you are that verifier. You did not hunt it, did not run its Phase 3 or Phase 5, and did not draft this replacement.

- Previous record: `/home/user/agentbox/docs/security-audit/run-5/agents/r-policy-cpu/record.json`. The replacement's reasoning: `agents/r-policy-cpu/final.txt` (`reason`). Its harnesses (if promoted): `agents/r-policy-cpu/artifacts/`.
- Re-check the cited lines and rerun bounded measurements (at most 128 KiB) in your sandbox. Pay particular attention to the remediation claims: whether recursing only on whitespace, backtick or '$(' would miss a command hidden in a quoted token without whitespace such as `bash -c 'x;rm y'`, and say so if the proposed _words change would weaken the policy. Return `verified` only if every factual claim holds; otherwise return `replace` with the corrected complete record.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap",
 "title": "Agent exec command of up to 8 MiB drives minutes of GIL-holding policy parsing per call, slowing the shared control plane",
 "description": "An agent token can POST /sandboxes/{sid}/tools/exec with a command made of shell-punctuation tokens (for example 'x;x;x;...') up to the 8 MiB AGENTBOX_MAX_BODY. No per-command or per-argument length cap exists before Policy.decide. With the default policy, the first rule (rm-curl-needs-approval, default_policy.yaml:12-18) calls command_names, which calls _words. _words builds a new shlex.shlex for every token that contains a shell punctuation character, including each bare ';', and a bare ';' is re-lexed again at every recursion level up to the depth cap of 4. That costs about 40 us per token and is linear: 0.71/1.23/2.39/5.73 s for 16/32/64/128 KiB in this verifier's rerun, so roughly 300 s of CPU for one 8 MiB call (extrapolated, not run). The work runs on the shared 32-thread tool_pool and holds the GIL. One agent can keep 4 such calls running (tool_concurrency). The evaluation happens before the pending-approval cap, so that cap does not stop it. A stand-in asyncio loop on the main thread slowed from 1.6 ms median / 1.9 ms max (idle) to 6.9/12.2 ms with 1 decide thread and 7.4/60 ms with 4 decide threads (earlier verifier measurement). This is degradation of the shared control plane (human API, other sandboxes) for as long as the agent re-issues calls, not a freeze. Other token shapes with the same cost profile exist (for example 'x$ ' repeated, or backtick-quoted words), so the cost is not specific to ';'.",
 "root_cause": "Policy evaluation has no input-size bound. AgentBox._call_tool passes args['command'] of any length to Policy.decide (service.py:311). The only limit is the 8 MiB HTTP body cap. _words (policy.py:40-62) re-lexes every token that contains whitespace or a shell punctuation character with a fresh shlex.shlex instance (policy.py:45, 60-61), even a token that is only ';', and the re-lex recurses to depth 4. shlex construction is expensive, so cost is about 40 us per punctuation token, and an 8 MiB command holds about 4M such tokens.",
 "intended_behavior": "An agent-supplied command or argument longer than a small fixed bound is rejected (400/413) or sent straight to REQUIRE_APPROVAL with a fixed 'too long to analyse' preview, before Policy.decide and preview run. The bound is small enough that the worst-case token shape finishes in well under a second (about 8 KiB on this hardware), and _words does not re-lex tokens that cannot contain a nested command, so human requests keep their normal latency.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "call_tool route",
   "description": "An agent token posts {\"args\":{\"command\":\"x;\"*N}}. ToolCall.args is an unbounded dict (api.py:54-55), limited only by the _BodyLimit middleware at 8 MiB (config.py:65)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 277,
   "scope": "call_tool route",
   "description": "Dispatched to the shared 32-thread tool_pool (api.py:160) via run_in_executor (api.py:277-278). A client disconnect does not cancel the running job."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 288,
   "scope": "AgentBox.call_tool",
   "description": "Admits up to tool_concurrency (default 4, config.py:53) concurrent calls per sandbox (service.py:286-290), with no size check on args."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 311,
   "scope": "AgentBox._call_tool",
   "description": "policy.decide(tool, args) runs with the raw args after the tool_request audit row and before the pending-approval cap (service.py:326)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/policy.py",
   "line": 211,
   "scope": "Policy.decide",
   "description": "The first default rule (rm-curl-needs-approval, default_policy.yaml:12-18) has match.commands, so decide calls command_names(cmd) on the whole command, then _raw_hits."
  },
  {
   "kind": "sink",
   "file": "agentbox/policy.py",
   "line": 61,
   "scope": "_words",
   "description": "Each token containing a punctuation char (every ';') is recursively re-lexed with a new shlex.shlex instance (policy.py:45) while holding the GIL, about 40 us per token."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/policy.py",
   "line": 60,
   "description": "Recursion condition: any token with whitespace or a char in _SHELL_PUNCT (policy.py:26), including a bare ';' token, calls _words(t, depth+1), which builds a new shlex at line 45. A bare ';' recurses until the depth > 4 return at policy.py:42."
  },
  {
   "file": "agentbox/service.py",
   "line": 311,
   "description": "decide is called with the raw command. No length check exists in call_tool/_call_tool (service.py:279-311). The only size constants are LOGGED_ARGS_MAX (audit logging only, service.py:39) and AUDIT_STR_MAX (audit.py:120)."
  },
  {
   "file": "agentbox/config.py",
   "line": 65,
   "description": "max_body_bytes defaults to 8 MiB and is the only bound on the command length."
  },
  {
   "file": "agentbox/service.py",
   "line": 286,
   "description": "Per-sandbox tool_concurrency allows 4 concurrent evaluations per agent; tool_pool has 32 workers across sandboxes (api.py:160)."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Requires a sandbox agent token, the lowest-trust principal, which the threat model assumes can be prompt-injected."
  },
  {
   "kind": "system_configuration",
   "description": "Default AGENTBOX_MAX_BODY (8 MiB), the default policy with an exec 'commands' rule (rm-curl-needs-approval), and the default tool_concurrency of 4. A policy with no exec commands rule would skip command_names."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding its own sandbox's agent token repeatedly sends exec tool calls whose command is a long run of 'x;' tokens. Each call ends as an approval request (or a 429 from the pending cap), but only after Policy.decide has consumed GIL-holding CPU in proportion to the command length. Up to 4 calls per sandbox run at once.",
  "payloads": [
   "{\"args\":{\"command\":\"x;x;x;...\"}} with 'x;' repeated 65536 times (131072-byte command)",
   "Policy.load('agentbox/default_policy.yaml').decide('exec', {'command': 'x;' * 65536})"
  ],
  "instructions": [
   "In the sandbox (no network, uid 65534, 1 CPU), load the default policy with agentbox.policy.Policy.load and time Policy.decide('exec', {'command': 'x;'*n}) for n = 8192, 16384, 32768, 65536 (16-128 KiB).",
   "In the same process run an asyncio probe on the main thread (30 iterations of a 20000-step Python loop plus await asyncio.sleep(0.001)) alone, with 1 thread, and with 4 threads each running decide on a 32 KiB 'x;' command. Record median and max iteration latency."
  ],
  "observed_result": "Verifier rerun, decide('x;'*n): 16 KiB 0.71 s, 32 KiB 1.23 s, 64 KiB 2.39 s, 128 KiB 5.73 s, all returning require_approval via rule exec-needs-approval; growth is linear. Other shapes at about 64 KiB: 'x$ ' repeated 1.65 s, '$ ' repeated 1.57 s. Probe (32 KiB command per thread, earlier verifier run): idle median 1.6 ms / max 1.9 ms; 1 decide thread 6.9 / 12.2 ms; 4 decide threads 7.4 / 60.0 ms. This matches the hunter's figures (4.85 s at 128 KiB, 8.6 / 88.8 ms with 4 threads) within run-to-run variance. The 8 MiB figure of about 300 s is a linear extrapolation and was not run, and no live uvicorn server was measured."
 },
 "remediation": {
  "strategy": "Bound the input before any parsing, and shrink the per-token work. (1) In AgentBox._call_tool, before the tool_request audit row and policy.decide, refuse an exec command or any string argument over a small fixed TOOL_ARG_MAX with 413 and a tool_blocked audit row, or route it straight to REQUIRE_APPROVAL with a fixed 'too long to analyse' preview that skips command_names and preview_command. Pick the bound from the worst-case token shape, not from file-size intuition: a re-lex-only change leaves 64 KiB of 'x;' at about 0.22 s and 52 KB of backtick-quoted words at about 1.0 s on this hardware, so 64 KiB would still permit seconds per call; about 8 KiB (worst case about 0.15 s) is the order needed, and write_file content keeps its own size handling. (2) In _words, recurse only on tokens that can hide a nested command (whitespace, a backtick or '$('), not on tokens that merely contain a punctuation character. Skipping only pure-punctuation tokens is not enough: 'x$ ' repeated still costs about 2.0 s at 64 KiB, because tokens containing '$' still recurse. (3) Add a regression test that decide on a command at the cap, for each of the shapes 'x;', 'x$ ' and backtick words, finishes in under about 250 ms, and that a command over the cap is rejected or approval-routed without calling command_names.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "TOOL_ARG_MAX = 8 * 1024\n...\n    def _call_tool(self, sid, tool, args, actor):\n        if tool not in TOOLS:\n            raise ServiceError(404, ...)\n        self.sandboxes.get(sid)\n        if any(isinstance(v, str) and len(v) > TOOL_ARG_MAX for k, v in args.items() if k != \"content\"):\n            self.log_best_effort(sid, tool, \"tool_blocked\", {\"reason\": \"argument_too_long\", \"limit\": TOOL_ARG_MAX})\n            raise ServiceError(413, f\"tool argument too long (max {TOOL_ARG_MAX})\")\n        ..."
   },
   {
    "file_name": "agentbox/policy.py",
    "fixed_code": "    for t in tokens:\n        if not t:\n            continue\n        cleaned = t.replace(\"$(\", \" \").replace(\"`\", \" \").replace(\"${\", \" \").replace(\"}\", \" \")\n        out.extend(cleaned.split())\n        # re-lex only tokens that can hide a nested command string\n        if any(c.isspace() for c in t) or \"`\" in t or \"$(\" in t:\n            out.extend(_words(t, depth + 1))"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "A single agent-token request under the default configuration triggers it, and a prompt-injected agent can repeat it indefinitely. No approval or human action is needed first."
  },
  "impact": {
   "score": "low",
   "reason": "Measured effect is slowdown, not denial: about 4x median and up to 30x max latency for a same-process stand-in loop with one agent's 4 concurrent calls, lasting minutes per call at the body cap. The control plane keeps answering and the effect ends when the calls finish. Several hostile sandboxes would worsen it but that was not measured. Other availability costs from the same input (unbounded preview notes, per-operand container execs) are tracked under other findings."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The source path, the linear CPU cost and the GIL contention were independently reproduced on the audited code with the default policy, and the remediation limits were measured on the same code. The latency under a real uvicorn server with a Docker-backed sandbox, and the full 8 MiB figure, are extrapolated rather than observed."
 }
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
| 

# Relevant companion blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation -->
**Superlinear parsing, matching, or evaluation**
Small accepted input drives catastrophic regex backtracking, nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort/hash behavior. Derive accepted depth/cardinality and complexity, then demonstrate a bounded growth curve locally.

# Execution boundary and paths

- Agent ID `rv-policy-cpu`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/rv-policy-cpu/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx rv-policy-cpu <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3.13`.
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx rv-policy-cpu /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
