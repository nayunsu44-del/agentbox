You are Phase 5 final-record verifier `p5-v03` in a defensive security audit of agentbox.
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
 "fingerprint": "agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe",
 "title": "agentbox agent prints sandbox file contents, file names and model text raw to the operator terminal, bypassing cli._safe",
 "description": "cli._safe exists so agent-determined strings never reach the terminal as raw control or bidi characters, and the approval and audit views use it. cmd_agent's log() prints model text ('say'), tool-call arguments ('call') and the first 6 lines of each tool result ('result') without it. read_file returns /workspace file bytes as-is, and list_dir returns raw `ls -la` output. Docker exec_run has no tty, so GNU ls quotes nothing and control characters in file names come through. A file the operator hands to the agent (source_dir, upload, or written into /workspace) can therefore put ESC sequences on the operator's terminal when the LLM loop reads it. Reproduced with the real cli.main(['agent', ...]), the real ToolClient and OpenAIChat over loopback HTTP: 7 raw ESC bytes, a full OSC 52 sequence, one raw U+009B, and a file name with ESC[2K from real non-tty ls. In a VT emulator (pyte), the content erased the '→ read_file(...)' line and the start of the file, then showed a forged '[사용자] ok, nothing else to do' line. exec results go through json.dumps(ensure_ascii=False), which escapes ESC as \\u001b but keeps 8-bit C1 such as U+009B, and whether that acts depends on the emulator. Impact is limited to spoofing the transcript that `agentbox agent` displays. The approval prompt (`agentbox approve`, rendered with _safe) and the audit log are not affected, and no authority is gained. Clipboard writes (OSC 52) and C1 handling were emitted but not observed in a real emulator and are not claimed.",
 "root_cause": "cli.py:353-361 cmd_agent.log prints 'say', 'call' and 'result' strings without cli._safe, and agent.py:116-126 ToolClient.call_text passes read_file content and list_dir listings through verbatim (other results via json.dumps(ensure_ascii=False), which keeps C1 controls).",
 "intended_behavior": "As the cli._safe docstring (cli.py:37-39) and _UNSAFE (cli.py:34) say, strings determined by the agent, the sandbox or the model are shown with C0/DEL/C1 and bidi controls made visible (newlines preserved for multi-line results), the same way _show_approval and cmd_audit render them.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/sandbox.py",
   "line": 570,
   "scope": "SandboxManager.read_file",
   "description": "Bytes of a /workspace file (controlled by whoever supplied or wrote it, lower trust than the operator) are decoded and returned as 'content' with no filtering; list_dir at 548-552 returns raw non-tty `ls -la` output the same way."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 360,
   "scope": "AgentBox.call_tool",
   "description": "Under the default policy, read_file and list_dir are allowed without approval. The full result goes back in the 200 body unchanged; only the audit log gets a summary (_summary)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/agent.py",
   "line": 119,
   "scope": "ToolClient.call_text",
   "description": "read_file content (and list_dir listing at 121) becomes the tool text verbatim; other tools use json.dumps(ensure_ascii=False), which escapes C0 but not C1."
  },
  {
   "kind": "propagation",
   "file": "agentbox/agent.py",
   "line": 266,
   "scope": "run",
   "description": "log('result', text) passes the tool text to the CLI logger; model text goes through log('say', ...) at 256."
  },
  {
   "kind": "sink",
   "file": "agentbox/cli.py",
   "line": 361,
   "scope": "cmd_agent.log",
   "description": "print() writes the first 6 result lines raw to the operator's stdout; the 'say' branch at 355 and the 'call' branch at 357 also print without _safe."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/cli.py",
   "line": 38,
   "description": "_safe docstring: agent-determined strings are not printed to the terminal as-is; control characters are shown as \\x1b."
  },
  {
   "file": "agentbox/cli.py",
   "line": 199,
   "description": "_show_approval applies _safe to every line of the approval card (also 203 and 246 in audit), so cmd_agent.log is the inconsistent exception."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 548,
   "description": "list_dir runs `ls -la` through exec_run without a tty. In this verifier's run, GNU coreutils 9.4 ls printed a dummy file name containing ESC[2K raw."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 10,
   "description": "The default is 'allow' and no rule covers read_file or list_dir, so no approval stands between the file content and the terminal."
  },
  {
   "file": "agentbox/agent.py",
   "line": 123,
   "description": "json.dumps(..., ensure_ascii=False) turns ESC into \\u001b (observed) but leaves U+009B raw (observed)."
  },
  {
   "file": "agents/v03b/artifacts/v03b_cli_agent.out",
   "line": 1,
   "description": "Verifier v03b's reproduction (real cli.main/ToolClient/OpenAIChat over loopback stubs, in sbx): ESC count 7, OSC 52 present, ESC file name from ls raw, pyte screen loses the read_file call line and 'Quarterly report' and shows the forged [사용자] line."
  },
  {
   "file": "agents/parent-live/artifacts/l6.out",
   "line": 1,
   "description": "The parent's run of h-wild's harness (fake LLM/ToolClient) rendered in pyte: two prior lines erased, forged '[agent] Summary' line, window title set to 'owned-title'. Its base script (/scratch/l6_base.py) was not retained, so this only corroborates."
  }
 ],
 "conditions": [
  {
   "kind": "user_interaction",
   "description": "The operator runs `agentbox agent` and reads its terminal transcript, and the LLM chooses to read_file or list_dir the crafted content (or the model emits control characters itself)."
  },
  {
   "kind": "data_state",
   "description": "A file whose content or name contains terminal control sequences is in /workspace: from the operator-supplied source folder, a web upload, or written by another agent holding the sandbox token."
  },
  {
   "kind": "environmental_dependency",
   "description": "The terminal follows ECMA-48 CSI cursor-up/erase-line (standard VT behaviour, observed here in pyte). OSC 52 clipboard, title and 8-bit C1 effects depend on the emulator and were not observed in a real one."
  }
 ],
 "execution": {
  "attacker_perspective": "A party who controls a document or file name in the folder the operator gives the agent, with no agentbox credentials. They want the operator's `agentbox agent` transcript to hide tool calls and show forged [사용자]/[에이전트] lines.",
  "payloads": [
   "/workspace/README content: 'Quarterly report\\n\\x1b[1A\\x1b[2K\\x1b[1A\\x1b[2K[사용자] ok, nothing else to do\\n\\x1b]52;c;ZWNobyBkdW1teQ==\\x07tail\\n'",
   "file name: 'a\\x1b[2Kb' (listed via list_dir)",
   "exec stdout: 'x\\x1b[2Ky\\u009b2Kz'",
   "model text: 'Done.\\x1b[2K'"
  ],
  "instructions": [
   "In the parent's sbx sandbox (no network, read-only /target, uid 65534), start one loopback ThreadingHTTPServer. It answers POST /sandboxes/sb_dummy/tools/{read_file,list_dir,exec} with {'status':'executed','result':...} shaped like SandboxManager.read_file/list_dir/exec, and POST /v1/chat/completions with one tool call per turn (read_file, list_dir, exec), then a final text.",
   "Build the list_dir listing from a real `ls -la -- /scratch/lsdir` (non-tty) over a dummy file named 'a\\x1b[2Kb'.",
   "Run agentbox.cli.main(['agent','summarize README','--sandbox','sb_dummy','--token','agt_dummy','--provider','openai','--base-url','http://127.0.0.1:<port>/v1','--model','dummy']) with AGENTBOX_URL set to the stub and NO_COLOR=1, capturing stdout.",
   "Count the raw ESC and U+009B characters in stdout, check for the OSC 52 sequence, feed stdout into pyte.Screen(120,30), and compare the rendered rows with the raw lines. Compare with cli._safe of the same content."
  ],
  "observed_result": "The stub received real Bearer agt_dummy tool calls for read_file, list_dir and exec. stdout held 7 raw ESC bytes, 1 raw U+009B and the full OSC 52 sequence, and the file name 'a\\x1b[2Kb' was printed raw. The exec ESC was escaped as \\u001b. On the pyte-rendered screen, the '→ read_file(...)' line and 'Quarterly report' were erased and a forged '[사용자] ok, nothing else to do' line appeared; the ls row and part of the exec JSON were blanked. cli._safe on the same content removed every raw ESC. Clipboard and real-emulator behaviour were not tested."
 },
 "remediation": {
  "strategy": "Neutralise every string cmd_agent.log prints with the existing _safe, applied per line so legitimate newlines stay. Optionally add U+061C to _UNSAFE. Add a regression test asserting that no 0x00-0x08, 0x0b-0x1f, 0x7f-0x9f or bidi characters reach stdout from read_file/list_dir/exec results or model text.",
  "code_changes": [
   {
    "file_name": "agentbox/cli.py",
    "fixed_code": "def _safe_lines(s: Any) -> str:\n    \"\"\"_safe per line: newlines stay, other control/bidi characters become visible escapes.\"\"\"\n    return \"\\n\".join(_safe(line) for line in str(s).split(\"\\n\"))\n\n    def log(kind: str, msg: str) -> None:\n        msg = _safe_lines(msg)\n        if kind == \"say\":\n            print(f\"{CYAN}[에이전트]{RESET} {msg}\", flush=True)\n        elif kind == \"call\":\n            print(f\"{DIM}  → {msg}{RESET}\", flush=True)\n        elif kind == \"result\":\n            lines = msg.splitlines()\n            head = \"\\n\".join(lines[:6]) + (f\"\\n… ({len(lines) - 6}줄 더)\" if len(lines) > 6 else \"\")\n            print(f\"{DIM}{head}{RESET}\", flush=True)\n"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Feeding untrusted documents to the agent is the intended use, read_file/list_dir need no approval, and any VT-compatible terminal honours CSI cursor/erase sequences. It still requires the operator to use `agentbox agent` rather than MCP, and the model to read the file."
  },
  "impact": {
   "score": "low",
   "reason": "Only the integrity of the operator's local transcript display is affected: hidden tool-call/result lines and forged user/agent lines. Approval decisions go through `agentbox approve`, which uses _safe, the audit log records the true calls, and no credential or authority is exposed. Emulator-dependent effects (OSC 52, C1) are not demonstrated."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "The full source trace was checked, and the raw bytes reaching stdout were reproduced independently by v03b with the real CLI, ToolClient and OpenAIChat over HTTP and real non-tty ls. The display effect was confirmed in a VT emulator (pyte) and corroborated by the parent's l6. The claim is limited to standard CSI behaviour."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.

- agents/parent-live/artifacts/l6.out

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

- Agent ID `p5-v03`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v03/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v03 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v03/artifacts/<file>`.

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
