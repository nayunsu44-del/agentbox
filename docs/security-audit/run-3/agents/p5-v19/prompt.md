You are Phase 5 final-record verifier `p5-v19` in a defensive security audit of agentbox.
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
 "fingerprint": "agentbox/sandbox.py:gui-burst:home-desktop-autostart-write-survives-snapshot-and-reexecutes-on-restore",
 "title": "GUI-burst write to /home/desktop/.config/autostart is invisible to gui_changes, persists into later snapshots, and re-executes as uid 1001 after a human restore",
 "description": "The agent's GUI tools (key/type, no approval gate by design) drive an xfce4-terminal that runs as uid 1001 `desktop`. From that terminal the agent can write ~/.config/autostart/*.desktop. The burst change tracking (`workspace_manifest`, `gui_changes`) only scans /workspace, and stray-kill only stops processes, so an inert file under /home/desktop is neither recorded nor removed. The burst-open snapshot predates the write and stays clean. A later `docker commit` captures the file: the next burst's `next_burst` snapshot, an AP-2 pre-snapshot, an interval snapshot, or a manual snapshot. When a human restores to such a snapshot, `restore()` recreates the container from the committed image and re-runs `agentbox-desktop-start`, which execs `startxfce4` as uid 1001. XFCE runs the autostart entry's Exec= line at session start. The command runs as uid 1001 with a live X session and /workspace write access (group agent), outside any GUI burst. No `gui_changes` or `gui_processes_stopped` event records it, and `gui_strays` would exempt it anyway because it is in the next burst's baseline. The decisive end-to-end reproduction is the parent's live run against the real desktop image (`agents/parent-live/artifacts/l12_autostart.py` and `.out`). I could not run Docker, so I did not redo it; I re-read the script and it exercises the claimed path. The hunter's three blockers are resolved by that run. The hunter's 'restart' variant is not supported by the source: the only recreate path is the human-only `POST /sandboxes/{sid}/restore`, and pause/unpause keeps processes. The finding therefore covers restore only.",
 "root_cause": "GUI-burst containment is scoped to /workspace and to running processes. `workspace_manifest` runs `find /workspace -xdev`. `_close_gui_burst` diffs only that manifest and `gui_strays` only kills processes. The burst principal (uid 1001) also owns /home/desktop, and the XFCE session re-reads ~/.config/autostart on every container start. Nothing captures, flags, or sanitizes /home/desktop between the burst, the `docker commit`, and the restore re-exec. Restore reintroduces the executable state without re-authorization or logging.",
 "intended_behavior": "Changes an agent makes through the GUI are meant to be visible to the human (`gui_changes`) or contained by stray-kill, so a restore point is trustworthy. Restoring a snapshot should not silently re-run agent-planted code outside a burst.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 106,
   "scope": "SandboxService tool dispatch for GUI_TOOLS (key/type, GUI_INPUT)",
   "description": "The agent token reaches GUI input with no approval. It opens an xfce4-terminal as uid 1001 and writes ~/.config/autostart/t.desktop. The live run used key ctrl+alt+t, type, and key Return, and all three returned 200."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 206,
   "scope": "_open_gui_burst",
   "description": "The burst records only `workspace_manifest` plus the baseline pids. The burst-open snapshot is taken before the write, so it does not contain the payload."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 499,
   "scope": "SandboxManager.workspace_manifest",
   "description": "The manifest `find` is limited to /workspace (-xdev), so a file under /home/desktop never enters the diff."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 240,
   "scope": "_close_gui_burst",
   "description": "`diff_manifest` runs over the /workspace-only manifest and `_stop_gui_strays` only kills processes. No gui_changes or gui_processes_stopped event is written for the autostart file. The live run printed 'gui_changes mention /home/desktop: False'."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 478,
   "scope": "SandboxManager.snapshot",
   "description": "`c.commit(...)` captures the whole container filesystem, including /home/desktop/.config/autostart. The live run took a manual snapshot after the burst closed."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 517,
   "scope": "SandboxManager.restore -> _run_container(tpl, snapshot image)",
   "description": "Restore recreates the container from the committed image and re-runs the template command `/usr/local/bin/agentbox-desktop-start` (config.py:74). That script execs `dbus-launch ... startxfce4` as uid 1001 (agentbox-desktop-start:30). XFCE autostart then runs the planted Exec= line. Live result: PROOF_autostart.txt appeared in /workspace with content 1001."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 499,
   "description": "`find {WORKSPACE} -xdev ! -type d` is the only change manifest. Nothing under /home is scanned."
  },
  {
   "file": "agentbox/service.py",
   "line": 240,
   "description": "The `gui_changes` diff is computed only over that manifest. There is no hook for /home/desktop."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 216,
   "description": "`gui_strays` skips pids already in the baseline and only ever returns pids, so it cannot remove a file. A payload launched at container boot is in the next burst's baseline. The hunter's harness agents/h-autostart/artifacts/h.out shows `[]` for the baseline case and `[200]` for the in-burst case."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 478,
   "description": "The commit captures the full filesystem, so the payload persists into every later snapshot."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 517,
   "description": "Restore reruns the template command on the committed image."
  },
  {
   "file": "agentbox/config.py",
   "line": 74,
   "description": "The desktop template command is the XFCE start script."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 30,
   "description": "The script runs `startxfce4` as uid 1001 with HOME=/home/desktop on every container start."
  },
  {
   "file": "images/desktop/Dockerfile",
   "line": 27,
   "description": "uid 1001 `desktop` owns /home/desktop (mode 700, line 28). Only this principal can write there; the uid 1000 agent cannot, so the GUI path is required."
  },
  {
   "file": "agents/parent-live/artifacts/l12_autostart.out",
   "line": 1,
   "description": "Parent-live output against the real image. Agent GUI tools created t.desktop (observed by root). No gui_changes or gui_processes_stopped event named /home/desktop. After snapshot and human restore, PROOF_autostart.txt appeared with content 1001."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "An agent token with GUI tools on a desktop-template sandbox, assumed prompt-injected."
  },
  {
   "kind": "user_interaction",
   "description": "A human must restore to a snapshot taken after the write. The burst-open snapshot of the writing burst is clean. Later snapshots (next_burst, AP-2, interval, manual) carry the file, and no audit event warns that they do."
  },
  {
   "kind": "environmental_dependency",
   "description": "The desktop image's XFCE session honours ~/.config/autostart, which the live run confirmed. The container has network_mode none and the sandbox boundary is not crossed."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding only its own agt_ token and the GUI tools on a desktop sandbox.",
  "payloads": [
   "key ctrl+alt+t",
   "type: mkdir -p ~/.config/autostart && printf '[Desktop Entry]\\nType=Application\\nName=t\\nExec=sh -c \"id -u > /workspace/PROOF_autostart.txt\"\\n' > ~/.config/autostart/t.desktop; exit",
   "key Return"
  ],
  "instructions": [
   "Create a disposable desktop sandbox with dummy tokens and a scratch AGENTBOX_HOME.",
   "As the agent, call the key, type, and key tools with the payloads above.",
   "Close the burst (idle) and confirm the audit log has no gui_changes or gui_processes_stopped entry naming /home/desktop.",
   "Take a snapshot after the burst, then run the human POST /sandboxes/{sid}/restore for that snapshot.",
   "Wait for the display and check that /workspace/PROOF_autostart.txt exists. Stop there.",
   "This is reproduced by agents/parent-live/artifacts/l12_autostart.py and .out, the parent's run on the real image. Docker was not available to v19."
  ],
  "observed_result": "The parent-live run printed: agent key/type/key all 200; root observer saw t.desktop; PROOF before restore False; gui_changes mention /home/desktop False; human snapshot snap_9051d98e; restore running; PROOF after restore (autostart re-executed) True; PROOF content (uid) 1001; no gui_changes or gui_processes_stopped events in the audit trail."
 },
 "remediation": {
  "strategy": "Treat /home/desktop as part of the GUI-burst change surface and neutralize it at restore. At burst close, also manifest-diff the persistent session config (/home/desktop/.config/autostart, ~/.config/xfce4, shell rc files, /etc/xdg/autostart) and log changes. At restore and start, the start script should wipe or reset ~/.config/autostart and similar session-startup paths (or use an XDG_CONFIG_DIRS/autostart-free profile) before launching startxfce4. Alternatively mount /home/desktop as tmpfs, or recreate it from the pristine image skeleton on each start, so agent-written session state cannot survive a snapshot.",
  "code_changes": [
   {
    "file_name": "images/desktop/agentbox-desktop-start",
    "fixed_code": "# before launching startxfce4 (as root, before as_desktop ... startxfce4):\nrm -rf \"$D/.config/autostart\" \"$D/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-session.xml\" \"$D/.bashrc\" \"$D/.profile\" \"$D/.bash_profile\" \"$D/.xprofile\" \"$D/.xsessionrc\"\n# plus log a gui_changes-style diff of these paths at burst close in agentbox/sandbox.py"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Needs a prompt-injected agent with GUI tools on a desktop sandbox, and a human restore to a snapshot taken after the write. The restore is human-only and the burst-open snapshot of the writing burst is clean. The control plane has no restart path other than restore."
  },
  "impact": {
   "score": "low",
   "reason": "Re-executes agent-chosen commands as uid 1001 inside a network-none, cap-dropped container. Those commands could already run during the GUI burst, since GUI input is ungated by design. The gain is unlogged, post-restore execution that defeats gui_changes, stray-kill, and the trust placed in restore points. It crosses neither the container boundary nor the approval authority."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Every trace line was re-read in the audited source. The hunter's local harness shows the baseline exemption. The parent-live run on the real image shows the full chain: agent GUI write, no audit record, snapshot, human restore, uid 1001 execution. The decisive reproduction is the parent's, not v19's, because v19 cannot run Docker. The 'restart' variant from the hunter is not supported by the source and is dropped."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.

- agents/parent-live/artifacts/l12_autostart.out
- agents/parent-live/artifacts/l12_autostart.py

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

- Agent ID `p5-v19`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v19/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v19 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v19/artifacts/<file>`.

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
