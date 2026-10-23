You are Phase 5 final-record verifier `p5-v17` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.

# Execution boundary (verbatim from the skill)

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
```

# Phase 5 checks for a `confirmed` record (verbatim from the skill)

```text
1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.
```

A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# Final record (from findings.json)

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:preview:unrecognized-destructive-segment-omitted-and-catchall-note-suppressed-by-rm-curl-row",
 "title": "Approval impact table leaves out unrecognized destructive segments and drops its documented 'could not compute' warning whenever an rm/curl segment is present",
 "description": "SandboxManager.preview builds the 'system-computed impact' list (시스템이 계산한 영향) on the exec approval card. It models only two verbs, rm and curl. README.md:380 states the compensating control: for any other command it shows '자동 계산 못 함' (could not compute) and the raw command. The code adds that note only when the whole command produced no affected rows and no notes (sandbox.py:872). A compound command from the agent such as 'rm /workspace/harmless.txt; find /workspace/keep -delete' or 'rm /workspace/a.txt; mv /workspace/important.db /tmp/gone' therefore produces one row, 'delete harmless.txt', and notes=[]. The find -delete or mv segment gets no row and no warning. The default policy sends the whole command to require_approval under rule rm-curl-needs-approval, whose reason text mentions only rm/curl. Both renderers (templates/_approvals.html:12-16 and cli.py:204-212) show the partial list as '(1건)' with no warning, and decide() then runs the complete stored command (service.py:415). Run alone, the same mv or find -delete would have shown the could-not-compute warning. The agent cannot delete workspace files without approval (delete_file and non-allowlisted exec need approval). So a prompt-injected agent can get a deletion or rename it could not do on its own executed under the human's approval, while the system-computed impact summary marks the action as only the benign deletion. The raw command text is still shown verbatim above the table, so the approver can see the extra segment if they read it. The defect is that the documented 'could not compute' safety net silently fails for compound commands. Overwrite-only payloads (dd of=, '> file') add nothing beyond the agent's own authority, because write_file overwrites are allowed without approval in the default policy.",
 "root_cause": "SandboxManager.preview (agentbox/sandbox.py:814-874) adds affected rows only in the name == 'rm' (line 824) and name == 'curl' (line 846) branches. It has no else branch for other segments. Its only fallback note is gated on `if not affected and not notes` (line 872), so it covers the whole command, not each segment. One rm or curl row makes `affected` non-empty, and that suppresses the warning for every other unmodeled segment. The substitution heuristic at line 818 checks only '$', backtick, '<(' and 'eval '. This contradicts the documented behavior in README.md:380, which says commands other than rm/curl show '자동 계산 못 함' together with the raw command.",
 "intended_behavior": "When any segment of the stored exec command is not one the preview can model, the approval card must say that the computed impact is incomplete and that the raw command must be read, as README.md:380 promises. This must hold whether or not other segments produced rows. A partial impact list must never be shown as the complete system-computed impact with no warning.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 205,
   "scope": "create_app.call_tool (POST /sandboxes/{sid}/tools/{tool})",
   "description": "An agent token holder (lowest-trust network principal, own sandbox only, line 207) submits an exec tool call with a fully attacker-chosen command string."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 315,
   "scope": "AgentService._call_tool",
   "description": "Policy returns REQUIRE_APPROVAL (rule rm-curl-needs-approval for any command containing rm/curl), so _preview builds the impact stored with the approval and shown to the human."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 158,
   "scope": "AgentService._preview",
   "description": "For tool == 'exec', delegates to sandboxes.preview(sid, command) with the agent's raw command."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 820,
   "scope": "SandboxManager.preview",
   "description": "Iterates _split_segments(command). Only the rm (824) and curl (846) branches append rows. mv, find -delete, dd, redirection targets and every other segment are skipped with no row and no note."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 872,
   "scope": "SandboxManager.preview",
   "description": "The could-not-compute note is added only when `not affected and not notes`. The rm/curl row makes affected non-empty, so the warning for the unmodeled segment is suppressed."
  },
  {
   "kind": "propagation",
   "file": "agentbox/templates/_approvals.html",
   "line": 13,
   "scope": "_approvals.html pending card",
   "description": "Renders '시스템이 계산한 영향 (1건)' with only the rm row. The notes loop at line 16 shows no warning. cli.py:204-212 (_show_approval) prints the same partial list with no notes."
  },
  {
   "kind": "sink",
   "file": "agentbox/service.py",
   "line": 415,
   "scope": "AgentService.decide",
   "description": "After the human approves, the complete stored args, including the unlisted mv / find -delete segment, run via _run_tool under the human's approval (after the AP-2 snapshot at line 406)."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 824,
   "description": "`if name == \"rm\":` and `elif name == \"curl\":` (line 846) are the only branches that add impact rows. There is no else branch for other verbs."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 872,
   "description": "`if not affected and not notes:` gates the only '시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.' note on the whole command."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 818,
   "description": "The substitution warning checks only '$', '`', '<(' and 'eval '. Unrecognized verbs and redirection are not flagged."
  },
  {
   "file": "README.md",
   "line": 380,
   "description": "Documents the compensating control: preview only knows rm and curl, and other commands show '자동 계산 못 함' plus the raw command. That promise does not hold for compound commands that include rm/curl."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 12,
   "description": "rm-curl-needs-approval routes any command containing rm/curl to require_approval (verified locally for all compound payloads). write_file has no rule and is allowed under default: allow (line 10). delete_file (line 18) and non-allowlisted exec (line 30) require approval, so deletion and rename are not within the agent's direct authority."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 13,
   "description": "Labels preview.affected as '시스템이 계산한 영향 (N건)'. Line 16 iterates preview.notes as the only warning channel. Line 8 shows the raw command in a <pre>."
  },
  {
   "file": "agentbox/cli.py",
   "line": 205,
   "description": "The terminal approver prints the same '시스템이 계산한 영향' list (204-208) and notes (211-212), so it inherits the same omission."
  },
  {
   "file": "agentbox/service.py",
   "line": 415,
   "description": "decide() runs the full stored args after the pre-execution snapshot (line 406)."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds the agent token for its own sandbox (assumed prompt-injected per the threat model)."
  },
  {
   "kind": "user_interaction",
   "description": "A human approver approves based on the system-computed impact table and its warnings, without spotting the extra segment in the raw command shown above the table."
  },
  {
   "kind": "system_configuration",
   "description": "Default policy is in force, which routes the compound command to require_approval rather than deny."
  },
  {
   "kind": "data_state",
   "description": "The compound command contains at least one rm or curl segment, so affected is non-empty. An rm operand that does not exist still yields a 'does not exist' row."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent sends one exec whose first segment is a benign rm (or curl) and whose later segment deletes or renames a file the agent cannot delete without approval. The approval card's system-computed impact then lists only the benign deletion and shows no could-not-compute warning.",
  "payloads": [
   "rm /workspace/harmless.txt; find /workspace/keep -delete",
   "rm /workspace/a.txt; mv /workspace/secret.key /workspace/public.txt",
   "curl http://example.invalid/x; mv /workspace/important.db /tmp/gone",
   "rm /workspace/harmless.txt; dd if=/dev/zero of=/workspace/important.db bs=1M count=10"
  ],
  "instructions": [
   "Inside the sbx5 sandbox (audited source read-only at /target, no network, no Docker), import agentbox.sandbox and call SandboxManager.preview as an unbound function on a dummy object. The dummy provides _container, plus _expand/_walk resolving against a fixed in-memory set of /workspace paths. Only these Docker-backed helpers are stubbed. The segment loop and the line 872 gate run unmodified.",
   "Call preview for each compound payload and for the lone mv / find -delete / dd baselines, and record affected and notes.",
   "Run agentbox.policy.Policy.load(default_policy.yaml).decide on the same commands, and on write_file and delete_file, to confirm routing and the agent's direct authority."
  ],
  "observed_result": "Every compound payload returned only the rm/curl row (for example affected=[{path: /workspace/harmless.txt, effect: 삭제}] or the curl 외부 접속 row) and notes=[]. The find -delete, mv and dd segments got no row and no warning. The lone baselines 'mv /workspace/important.db /tmp/gone', 'find /workspace/keep -delete' and 'dd ... of=/workspace/important.db' each returned affected=[] and notes=['시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.']. Policy routed all compound commands to require_approval (rm-curl-needs-approval, matched [rm]), lone mv to exec-needs-approval and delete_file to delete-file-needs-approval. write_file overwrite was allow. Captured in agents/v17/artifacts/v17.out and agents/v17/artifacts/v17-policy.out. The approval UI was not rendered live and nothing was executed."
 },
 "remediation": {
  "strategy": "Make the preview fail closed per segment. For every _split_segments segment the preview does not model, including bare redirection-target segments, add a note naming that segment and telling the approver to read the raw command. Keep the global fallback for an empty result. Optionally flag '>'/'>>' redirection next to the substitution heuristic, and label the table as partial whenever any segment was unmodeled.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "        for seg in _split_segments(command):\n            if not seg:\n                continue\n            name = seg[0].rsplit(\"/\", 1)[-1]\n            if name == \"rm\":\n                ...  # existing rm handling\n            elif name == \"curl\":\n                ...  # existing curl handling\n            else:\n                notes.append(f\"'{' '.join(seg)[:80]}' 부분의 영향은 자동 계산하지 못함. 명령 원문을 확인할 것.\")\n        if len(affected) > limit:\n            notes.append(f\"영향 항목 {len(affected)}개 중 앞의 {limit}개만 표시.\")\n            affected = affected[:limit]\n        if not affected and not notes:\n            notes.append(\"시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.\")\n        return {\"command\": command, \"cwd\": WORKSPACE, \"affected\": affected, \"notes\": notes}"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Building the compound command is trivial and fully under agent control, and the default policy routes it to approval. Success still depends on the approver trusting the impact table and warnings rather than reading the raw command. The raw command is shown verbatim directly above the table (web <pre>, CLI per-line with line count)."
  },
  "impact": {
   "score": "low",
   "reason": "The gain beyond the agent's own authority is a deletion or rename of /workspace files (mv, find -delete, etc.) executed under the human's approval without being shown in the system-computed impact. Overwrites (dd, redirection) are already allowed to the agent via write_file, so they add nothing. Effects stay inside the network=none sandbox's /workspace, and decide() takes an unconditional AP-2 snapshot before execution (service.py:406), so files can be restored."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Source shows the per-command gate. A bounded sandboxed harness ran the real preview() and policy code, stubbing only the Docker glob/walk helpers, and reproduced the suppressed warning against lone-command baselines. Live rendering in the card was not exercised, but both templates display preview.affected/notes verbatim per source."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Architecture facts

# agentbox architecture summary (run-3)

Source ref: `0e4b958` on `ccr-e10bee8e-6wt669` (PR #5 head; `agentbox/` identical after merge to `main`). Profile `standard`, whole repo.

## 1. Product, principals, protected resources

agentbox is a self-hosted control plane (FastAPI + SQLite) that gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. A desktop mode adds Xvfb/Xfce/noVNC so a human can watch or take over the screen.

- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full API.
- **Web UI cookie session**, scope `*` (token login form or one-time `*` ticket): full UI (`web.py:208-242`, `desktop.py`).
- **Desktop-link session**, scope = one sandbox id (redeemed per-sandbox ticket): only that sandbox's desktop page/state/takeover/handback/WS (`api.py:134-140,298-336`, `desktop.py:147-152`).
- **Agent token** `agt_…` per sandbox (hash stored): tool calls on its own sandbox, read own sandbox/approval/desktop state (`api.py:160-230,315`). Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (tool execs), uid 1001 `desktop` (X session, GUI tools, x11vnc; member of the agent group, `/workspace` group-writable). Container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listings, file names) is attacker-controlled input to the control plane.
- **MCP stdio server / agent.py LLM loop**: hold an agent token; inherit trust from the local launcher.

Protected resources: the human token and approval authority; host filesystem and Docker daemon (control plane holds `docker.sock` = host root); other sandboxes; integrity of `/workspace` restore points (AP-2 snapshots before destructive actions); audit-log integrity and secret masking; control-plane availability (shared thread pool, memory, host disk via `docker commit`).

## 2. Comparable baseline

No source-grounded comparable product. Components: MCP (FastMCP stdio), VNC/RFB via x11vnc+noVNC, gVisor/Kata runtimes. A runc sandbox shares the host kernel; the code refuses runc only when the control plane is exposed (`cli.py:79-115`).

## 3. Stack, deployment, offline limits

Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: local `agentbox serve` (127.0.0.1), direct TLS, `--behind-tls-proxy` (compose + Caddy, `forwarded_allow_ips="*"` by default), `--insecure`, and the bare `uvicorn agentbox.api:create_app --factory` path that skips serve-time checks. Container flags: `network_mode=none`, `/source` read-only bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits; no userns, default seccomp (`sandbox.py:367-388`). Host: Docker 29.9.1, runtimes `runc` and `io.containerd.runc.v2` only (no gVisor/Kata), cgroup v1, images `agentbox-desktop:0.1`, `buildpack-deps:noble-curl`. Pure-function harnesses and the three unit test modules fit the parent's `sbx` sandbox; anything that builds the app needs the Docker daemon (parent-live checks).

## 4. Entry surfaces and important paths

- JSON API `POST /sandboxes/{sid}/tools/{tool}` → `service.call_tool` (per-sandbox concurrency 4, 429) → audit → `policy.decide` → allow / approval queue → `sandbox.exec|read_file|write_file|delete_file|list_dir|gui_*` (`docker exec` as uid 1000/1001), dedicated 32-thread `tool_pool` (`api.py:81`). Exec output streamed and capped (`_Head`, 64 KB).
- Approvals `POST /approvals/{aid}` (human only) → atomic claim → pre-snapshot → run with the agent's original args; terminal approver `cli.py` renders args through `_safe()`.
- Snapshots: `docker commit` before write/delete overwrite and per GUI burst; quota 50 → approval (`service.py:199-204`); per-sandbox `_snap_locks`.
- GUI bursts (`service.py:186-260`): snapshot + manifest + baseline pids at burst start; at close, kill new uid-1001 processes classified by `gui_strays` from root `ps` output and `xdotool` window pids (`sandbox.py:174-225,686-697`), diff `find -printf` manifest (8 MB cap) and log `gui_changes`. Closed on idle from `expire_stale`, `call_tool`, `GET /audit`, UI audit fragment, takeover, end_desktop.
- Files: `read_file` (`timeout` + `[ -f ]` FIFO guard), `outbox_list/read`, `POST /sandboxes/{sid}/files` upload, `source_dir` copy at create (refuses overlap with `settings.home`/DB dir).
- Desktop: tickets (60 s, one-time, hashed), sessions (12 h, hashed, `scope`), leases keyed by public session id `hs_`+32 bits, WS `/desktop/ws` (cookie + same_origin; control needs lease; re-check every 30 s, `session_ended` handback), logout `end_ui_session`.
- Audit: hash chain with append-only triggers, `mask_text` regex set (`audit.py`), UI/CLI timelines render container-controlled strings (`web.py describe`, Jinja autoescape; `cli._safe`).
- Serve: `bind_problem`, `runtime_problem` (literal `"runc"` only), `--allow-runc`/`AGENTBOX_ALLOW_RUNC`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc here) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot, `gui_changes`, stray kill (partial, N-1) |
| Agent → human authority | token kinds, `human_only`, scope checks, source_dir overlap check |
| Agent → control-plane availability | tool_pool, tool_concurrency, `_Head`, snapshot quota, read timeouts |
| Container output → control plane | parsers `_parse_ps`, `_parse_manifest`, `_parse_outbox`; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin` (missing Origin allowed) |
| Desktop-link session → rest of UI | `scope` column, `desktop_human` |
| Network → control plane | `bind_problem` TLS gate; proxy trust `*` |

## 6. Starting paths

`agentbox/service.py`, `sandbox.py`, `api.py`, `policy.py`, `desktop.py`, `audit.py`, `web.py`, `cli.py`, `config.py`, `approvals.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

run-1 (`7fc501f`, standard, source-only) ledger: 15 units; run-2 validated live. 9 confirmed records, all with changed source (fixed in PR #1–#5; N-1 GUI bypass only partially mitigated) → `prior_confirmed_changed_source` revalidation units, not excluded from hunting. One rejected claim (`desktop.py:redeem:sandbox-scoped-ticket-mints-unscoped-full-admin-session`): source changed (scope column), so the unit is current work. No same-source confirmed exclusions. Changed since `7fc501f`: 9 source files (+598/−67) — first priority.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent-driven work consumes the shared pool, memory, host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: browser UI with htmx and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 desktop helper killed/inspected by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release/signing path; CI only runs tests), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker/RPC beyond HTTP/WS/MCP stdio covered elsewhere).


# Execution paths

- Agent ID `p5-v17`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v17/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v17 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v17/artifacts/<file>`.

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


# report-schema.json branches (verbatim): confirmed, needs_validation, rejected

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


# Output

Return exactly one JSON object with no prose and no markdown fence, one of:
{"decision": "verified", "fingerprint": "<the record's fingerprint>"}
{"decision": "replace", "reason": "<what failed and why>", "record": {...}, "artifacts_to_promote": [...]}
A replacement record must match its `confirmed`, `needs_validation`, or `rejected` branch exactly (additionalProperties: false) and keep the same fingerprint unless you identified a genuinely different root cause. `artifacts_to_promote` is optional. Overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
