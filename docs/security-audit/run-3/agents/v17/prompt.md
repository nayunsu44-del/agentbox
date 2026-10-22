You are candidate verifier `v17` in a defensive security audit of agentbox (audited source, read-only: `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/`, a worktree at commit 8e4db9e; agentbox/ identical to 0e4b958).


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


# Candidate (proposed by wave-3 hunter h-preview; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:preview:unrecognized-destructive-segment-omitted-and-catchall-note-suppressed-by-rm-curl-row",
 "title": "Approval impact table omits destructive command segments and suppresses its 'could-not-compute' warning whenever any rm/curl segment is present",
 "description": "The approval card's 'system-computed impact' table (SandboxManager.preview) only understands two verbs, rm and curl. For a compound exec command that contains one rm (or curl) segment alongside any other destructive segment (dd, a '>' write-redirection, mv, tee, truncate, python -c, find -delete, etc.), the preview builds an 'affected' list containing only the rm/curl effects and leaves the other segments out entirely. The only safety net, a catch-all note '시스템이 영향 파일을 계산하지 못함 (could not compute, check the raw command)', is added only when BOTH the affected list and the notes list are empty (sandbox.py:872). Because the rm/curl segment populates 'affected', that catch-all is suppressed for the whole command, and the substitution warning at sandbox.py:818 only checks for $, backtick, <( and eval, not for redirection or unrecognized verbs. A prompt-injected agent (the lowest-trust network principal, whose compound exec is routed to human approval by default_policy.yaml) can therefore submit e.g. 'rm /workspace/harmless.txt; dd if=/dev/zero of=/workspace/important.db' and the human approver is shown an authoritative impact table listing only 'delete harmless.txt' with no warning, while approval executes the full stored command and overwrites important.db. This breaks the action-confirmation/approval-binding invariant: the human approves a described action (a benign deletion) but a materially different, more destructive action also runs under the human's approval authority, without their intentional consent. Both renderers (templates/_approvals.html and cli.py:_show_approval) present the same partial list.",
 "root_cause": "SandboxManager.preview (agentbox/sandbox.py:814-874) special-cases only the verbs 'rm' (line 824) and 'curl' (line 846) when building the human-facing 'affected' impact list, and gates its only catch-all safety note on `if not affected and not notes` (line 872). Any other destructive verb inside a multi-segment command produces no affected rows, and the presence of a single rm/curl row makes `affected` non-empty, which suppresses the catch-all warning for the entire command. The substitution-warning heuristic at line 818 does not cover redirection or unrecognized verbs. The result is an authoritative-looking but incomplete impact summary presented with zero warnings.",
 "intended_behavior": "The impact table the human relies on to approve a gated exec must either enumerate the real effects of the complete stored command, or, whenever any segment's effect cannot be computed, warn the approver that the displayed impact is incomplete and the raw command must be read. A warning must fire per unrecognized destructive segment, not only when the whole affected list is empty.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 315,
   "scope": "AgentService._call_tool",
   "description": "When policy returns REQUIRE_APPROVAL for an agent exec, _preview is called to build the impact shown to the human."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 158,
   "scope": "AgentService._preview",
   "description": "For tool=='exec', delegates to sandboxes.preview(sid, command) with the agent's raw command string."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 820,
   "scope": "SandboxManager.preview",
   "description": "Iterates _split_segments(command); only the name=='rm' (824) and name=='curl' (846) branches append rows to 'affected'. Any other segment (dd, mv, redirection target, etc.) is skipped with no row and no note."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 872,
   "scope": "SandboxManager.preview",
   "description": "The catch-all 'could not compute' note is added only when `not affected and not notes`; a single rm/curl row makes affected non-empty and suppresses the warning for the whole compound command."
  },
  {
   "kind": "sink",
   "file": "agentbox/templates/_approvals.html",
   "line": 13,
   "scope": "_approvals.html pending card",
   "description": "Renders preview.affected under the authoritative label '시스템이 계산한 영향' and preview.notes as warnings; the partial list and empty notes display as a complete, benign impact with no warning (cli.py:204-212 is the identical CLI sink). On approval, decide() executes the full stored args (service.py ~424)."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 824,
   "description": "Only `if name == 'rm'` and `elif name == 'curl'` (line 846) branches contribute to the 'affected' impact list; every other verb in the command is ignored."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 872,
   "description": "`if not affected and not notes:` — the sole catch-all 'could not compute' warning fires only when affected is empty, so any rm/curl row suppresses it."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 818,
   "description": "Substitution warning checks only for '$', backtick, '<(' and 'eval '; it does not warn on redirection or unrecognized destructive verbs."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 12,
   "description": "rm/curl commands and all other non-read-only exec route to require_approval (no DENY rule), so a compound 'rm x; dd ...' reaches the preview/approval card."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 13,
   "description": "The web card presents preview.affected as '시스템이 계산한 영향' (system-computed impact), the authoritative decision aid, with notes (line 16) as the only warning channel."
  },
  {
   "file": "agentbox/cli.py",
   "line": 205,
   "description": "The terminal approver prints the same 'system-computed impact' affected list (line 204-208) and notes (211-212), inheriting the identical omission."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds an agent token (agt_...) for its own sandbox, the lowest-trust network principal; the threat model assumes it is prompt-injected."
  },
  {
   "kind": "user_interaction",
   "description": "A human approver reads the approval card and clicks approve, relying on the system-computed impact table as intended."
  },
  {
   "kind": "system_configuration",
   "description": "Default policy (default_policy.yaml) in force, which routes compound/non-allowlisted exec to human approval rather than denial."
  },
  {
   "kind": "data_state",
   "description": "The rm/curl operand resolves to at least one existing path (or an 'does not exist' row), so 'affected' is non-empty and the catch-all note is suppressed."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent crafts a single compound exec whose first segment is a benign rm (or curl) and whose later segment performs the real destructive/exfil-shaped action, so the approval card shows only the benign deletion.",
  "payloads": [
   "rm /workspace/harmless.txt; dd if=/dev/zero of=/workspace/important.db bs=1M count=10",
   "rm /workspace/harmless.txt && printf x > /workspace/important.db",
   "rm /workspace/a.txt; mv /workspace/secret.key /workspace/public.txt"
  ],
  "instructions": [
   "In the sbx5 sandbox, import agentbox.sandbox and call SandboxManager.preview as an unbound method on a dummy object providing _container/_expand/_walk that model the given /workspace files (the rm/curl-only and catch-all logic under test is pure source; _expand/_walk only shell out to resolve globs).",
   "Invoke preview with each payload and a file set where the rm operand and the destructive target both exist.",
   "Inspect the returned dict's 'affected' and 'notes' fields.",
   "Compare against the lone 'dd if=/dev/zero of=/workspace/important.db' (no rm) baseline."
  ],
  "observed_result": "For all three compound payloads preview returned affected=[{path: the rm target, effect:'삭제'}] and notes=[] — the dd/redirection/mv effect on important.db / secret.key is entirely absent and no warning note is present. The lone-dd baseline (no rm) returned affected=[] and notes=['시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.'], proving the catch-all is the intended safety net and is suppressed precisely by the rm row. Captured in agents/h-preview/artifacts/h.out."
 },
 "remediation": {
  "strategy": "Make the impact preview fail-closed per segment rather than globally. For every _split_segments segment whose verb is not in the small set the preview can fully model (rm, curl), append an explicit note identifying the unhandled segment (e.g. '세그먼트 \"dd …\"의 영향을 계산하지 못함; 명령 원문을 확인할 것'). Decouple the catch-all so it also fires when any segment was unrecognized, not only when the whole affected list is empty. Optionally extend the substitution-warning heuristic (line 818) to also flag '>' / '>>' write-redirection. Keep showing the raw command, but never present the affected table as complete when any segment was dropped.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "# in preview(): track unhandled segments\n        unhandled = 0\n        for seg in _split_segments(command):\n            if not seg:\n                continue\n            name = seg[0].rsplit('/', 1)[-1]\n            if name == 'rm':\n                ...  # existing rm handling\n            elif name == 'curl':\n                ...  # existing curl handling\n            else:\n                unhandled += 1\n                notes.append(f\"세그먼트 '{' '.join(seg)[:80]}'의 영향을 자동 계산하지 못함. 명령 원문을 확인할 것.\")\n        if len(affected) > limit:\n            notes.append(f\"영향 항목 {len(affected)}개 중 앞의 {limit}개만 표시.\")\n            affected = affected[:limit]\n        if not affected and not notes:\n            notes.append('시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.')\n        return {'command': command, 'cwd': WORKSPACE, 'affected': affected, 'notes': notes}"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "The agent fully controls the exec command string and the default policy routes compound exec to approval; crafting 'rm benign; <destructive>' is trivial and needs no special conditions."
  },
  "impact": {
   "score": "medium",
   "reason": "A human approver is deceived into authorizing file overwrite/rename/destruction they were not shown, under their own approval authority, breaking informed consent for the gated action. Bounded to /workspace within a network=none sandbox, and decide() does take an unconditional pre-execution AP-2 snapshot that enables manual recovery, but the deception means the human does not know to restore and the audit record carries the same misleading preview."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "The preview-building boundary failure is established by source and demonstrated by a bounded local harness that exercises the real preview() function logic; the only live-Docker dependency (_expand/_walk container output) was faithfully stubbed and its newline-split / rm-curl-only behavior is pure, directly-readable source. Both renderer sinks and the policy routing were confirmed in source."
 }
}
```


# Linked coverage-unit checks

[
 {
  "coverage_id": "approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls%20%28agentbox%2Fsandbox.py%23preview%2C%20agentbox%2Fservice.py%23_preview%2F_capture%2C%20agentbox%2Ftemplates%2F_approvals.html%2C%20agentbox%2Fcli.py%23_show_approval%29::agentbox%2Fsandbox.py%23preview%20%2B%20_split_segments%20%2B%20_expand%20%2B%20_walk%3A%20the%20system-computed%20%27affected%27%20list%20and%20%27system-captured%27%20screenshot%20shown%20to%20the%20human%20must%20reflect%20what%20the%20stored%20args%20will%20actually%20do::agentbox%2Fsandbox.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding",
  "local_checks": [
   {
    "agent_id": "h-preview",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "The system-computed 'affected' impact list shown on the approval card must reflect every destructive effect of the stored exec command, or warn the human when it cannot.",
    "method": "local",
    "result": "Harness calling SandboxManager.preview (with a faithful _expand/_walk stub; the function's rm/curl-only and catch-all logic is pure source) on compound commands 'rm harmless; dd of=important', 'rm harmless && printf x > important', and 'rm a; mv secret public' returned affected=[only the rm deletion] and notes=[] in all three cases. A lone 'dd of=important' (no rm) correctly produced the catch-all 'could not compute, check raw command' note. This shows unrecognized destructive segments are silently dropped and the safety note is suppressed whenever any rm/curl row is present.",
    "artifact": "agents/h-preview/artifacts/h.out"
   },
   {
    "agent_id": "h-preview",
    "reviewed_paths": [
     "agentbox/policy.py",
     "agentbox/default_policy.yaml"
    ],
    "invariant": "Arbitrary non-allowlisted compound exec commands route to REQUIRE_APPROVAL (not DENY), so they reach the preview/approval card.",
    "method": "source",
    "result": "default_policy.yaml rule 'rm-curl-needs-approval' sends any command containing rm/curl to require_approval; catch-all 'exec-needs-approval' sends every other non-read-only exec to require_approval; no DENY rule exists. A command like 'rm x; dd ...' thus reaches _preview and an approval card.",
    "artifact": null
   },
   {
    "agent_id": "h-preview",
    "reviewed_paths": [
     "agentbox/templates/_approvals.html",
     "agentbox/cli.py"
    ],
    "invariant": "Both approval renderers must not present a partial affected list as authoritative without a discrepancy warning.",
    "method": "source",
    "result": "templates/_approvals.html:13-16 renders a.preview.affected under the label '시스템이 계산한 영향' (system-computed impact) and iterates a.preview.notes for warnings; cli.py:204-212 prints the same affected list and notes. Neither adds any warning of its own; both faithfully display whatever preview produced, so the partial list and empty notes from the harness render as a trustworthy, complete-looking benign impact summary. decide() (service.py ~424) then runs the full stored args.",
    "artifact": null
   }
  ]
 }
]

Artifacts are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

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

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Pending-action and user-presence confusion -->
**Pending-action and user-presence confusion**
Notification, widget, shortcut, share sheet, biometric prompt, or deferred operation authorizes a different action than displayed, executes after expiry, or uses another profile's pending state. Bind confirmation to normalized action, resource, account, and current foreground state.

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

# Execution boundary and paths

- Agent ID `v17`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/v17/scratch/`. Never edit target files, the ledger, findings, or other agents' directories.
- Read source only from `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` and cite its lines. `/home/user/agentbox` carries later fixes; do not use it for lines.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 v17 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Shell utilities such as bash, timeout and sleep are available inside it.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/v17/artifacts/<file>`.
- No prior record has this fingerprint. Related current record: agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized (v13, confirmed) spoofs the same approval card through bidi characters in the command text; this candidate is about the system-computed impact list, judge its own root cause.

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

Return exactly one JSON object: {"decision": ..., "record": {...}, "artifacts_to_promote": [...]} with no prose and no markdown fence. Severity rules: overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
