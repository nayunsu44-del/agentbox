You are candidate verifier `v19` in a defensive security audit of agentbox (audited source, read-only: `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/`, a worktree at commit 8e4db9e; agentbox/ identical to 0e4b958).


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


# Candidate (proposed by wave-3 hunter h-autostart; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:gui-burst:home-desktop-autostart-write-survives-snapshot-and-reexecutes-on-restore",
 "title": "GUI-burst write to /home/desktop/.config/autostart escapes gui_changes/stray-kill, persists into snapshots, and re-executes as uid 1001 on restore/restart",
 "description": "A prompt-injected agent can drive the desktop GUI tools (the run-2 N-1 path that opens an xfce4-terminal as uid 1001 desktop) to write a Desktop Entry file at /home/desktop/.config/autostart/evil.desktop. This write lands outside /workspace, so it is never recorded by the GUI burst's gui_changes diff (which only scans /workspace), and the autostart file is inert on disk so the burst-close stray-kill (which only stops processes) does not remove it. When the control plane later docker-commits the container (AP-2 pre-snapshot before a destructive action, an interval GUI snapshot, or a manual/human snapshot), the autostart file is captured into the snapshot image. On a subsequent restore (human reverting to a 'clean' restore point) or restart, the desktop template re-runs its start script, which execs startxfce4 as uid 1001; XFCE session startup honours ~/.config/autostart, re-executing the attacker's Exec= command as the desktop user with a live X session, outside any GUI burst and with no gui_changes record. Because the re-executed process launches at container boot it is always inside the next burst-open baseline, so gui_strays exempts it from stray-kill. The result is attacker-controlled code that persists across snapshot/restore and silently re-arms itself, defeating the restore-point and GUI-burst monitoring the human relies on.",
 "claimed_root_cause": "GUI-burst change tracking (workspace_manifest/gui_changes) and the snapshot restore lifecycle scope file-mutation visibility to /workspace, but the desktop session's HOME (/home/desktop) is both writable by the burst principal (uid 1001) and re-executed at session start via ~/.config/autostart. No control captures, re-authorizes, or sanitizes /home/desktop between the burst, the docker commit, and the restore re-exec; and gui_strays structurally exempts any process present at burst open, which an autostart payload always is after a restart.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 206,
   "scope": "SandboxService._open_gui_burst / GUI tool call",
   "description": "Agent GUI tool (click/type/key) opens a burst and drives an xfce4-terminal as uid 1001 desktop (run-2 N-1); inside it the agent writes /home/desktop/.config/autostart/evil.desktop."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 499,
   "scope": "SandboxManager.workspace_manifest",
   "description": "The burst manifest find is scoped to /workspace (-xdev), so a write under /home/desktop is outside scope and never enters the gui_changes diff computed in service.py:237-248."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 216,
   "scope": "gui_strays",
   "description": "The written .desktop file is not a process (stray-kill cannot touch it); after restore the autostart-launched process is present at burst open, so p['pid'] in baseline exempts it from the stray list."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 478,
   "scope": "SandboxManager.snapshot",
   "description": "docker commit captures the entire container filesystem including /home/desktop/.config/autostart, persisting the payload into the snapshot image."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 517,
   "scope": "SandboxManager.restore -> _run_container(tpl.command)",
   "description": "Restore rebuilds from the committed image and re-runs tpl.command = /usr/local/bin/agentbox-desktop-start (config.py:74), which execs startxfce4 (agentbox-desktop-start:30); XFCE autostart re-executes the payload as uid 1001 with a live X session, outside any burst and unlogged."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 499,
   "description": "workspace_manifest: find {WORKSPACE} -xdev ! -type d — manifest/gui_changes only ever covers /workspace, never /home/desktop."
  },
  {
   "file": "agentbox/service.py",
   "line": 240,
   "description": "_close_gui_burst computes diff_manifest(burst['manifest'], manifest) over the /workspace-only manifest, so writes outside /workspace produce no gui_changes record."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 216,
   "description": "gui_strays: processes whose pid is in baseline are skipped; an autostart process launched at container boot is always in the burst-open baseline after restore/restart."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 478,
   "description": "snapshot: c.commit(...) of the whole container captures /home/desktop including any autostart entry."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 517,
   "description": "restore: _run_container(tpl, snaps[snap_id]['image'], ...) rebuilds from the committed image and re-runs the template command."
  },
  {
   "file": "agentbox/config.py",
   "line": 74,
   "description": "desktop Template command = ['/usr/local/bin/agentbox-desktop-start'], so restore/restart re-executes the XFCE start script."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 30,
   "description": "Start script execs 'dbus-launch --exit-with-session startxfce4' as uid 1001 desktop with HOME=/home/desktop on every container start."
  },
  {
   "file": "images/desktop/Dockerfile",
   "line": 28,
   "description": "desktop user uid 1001 owns /home/desktop mode 700, so the burst principal can create ~/.config/autostart/*.desktop; it is in the agent group sharing /workspace."
  }
 ],
 "blockers": [
  "Live desktop image fact: whether xfce4-session in agentbox-desktop:0.1 reads ~/.config/autostart (XDG_CONFIG_HOME default) and executes the Exec= line of a .desktop entry at session start. Standard XDG autostart behaviour, but image-specific and not source-visible; requires running the image.",
  "Live control-plane fact: whether the agent's GUI tools can actually create /home/desktop/.config/autostart/evil.desktop via an xfce4-terminal as uid 1001 within a burst (run-2 N-1 is only partially mitigated). Requires the Docker-backed control plane.",
  "Live Docker fact: whether docker commit + restore (sandbox.py:478,517) re-runs the start script from the committed image and thereby re-executes the autostart payload. Requires the Docker daemon; sbx5 has no Docker and no network."
 ],
 "validation_plan": {
  "local": "Already performed in sbx5 (python3.13, no net/Docker, uid 65534, importing agentbox.sandbox from /target): harness agents/h-autostart/artifacts/h.out shows (1) workspace_manifest's find is scoped to {WORKSPACE} with no /home component, and (2) gui_strays returns [] for a uid-1001 payload present in the burst-open baseline (the restore/restart case) while returning [200] for the same payload launched during the burst — proving the baseline exemption and the /workspace-only change scope. The autostart re-execution step cannot be exercised locally because it needs the real desktop image.",
  "deployment": "Owner-observed on this host with Docker: (1) docker run --network none agentbox-desktop:0.1; as uid 1001 desktop write /home/desktop/.config/autostart/t.desktop with [Desktop Entry]/Type=Application/Exec=/bin/sh -c 'touch /home/desktop/PROOF_$(date +%s)'/X-GNOME-Autostart-enabled=true/Hidden=false. (2) docker commit the container to an image. (3) docker run that image with the same CMD (/usr/local/bin/agentbox-desktop-start) and, after startxfce4 comes up, check for /home/desktop/PROOF_* — its presence confirms autostart re-execution as uid 1001 on restore/restart. (4) Through the control plane: as an agent token, drive GUI tools to open xfce4-terminal and create the same autostart file, run a GUI burst to idle-close, and confirm no gui_changes event names /home/desktop; then take a snapshot and POST /sandboxes/{sid}/restore and confirm the payload ran and no gui_processes_stopped entry lists it. Use only dummy /home/desktop/PROOF_* markers; stop at first proof, do not extend to broader persistence."
 }
}
```


# Linked coverage-unit checks

[
 {
  "coverage_id": "GUI-burst%20writes%20outside%20%2Fworkspace%20%28uid%201001%20%2Fhome%2Fdesktop%3A%20.config%2Fautostart%2C%20xfce%20session%2C%20.bashrc%29%20that%20a%20later%20snapshot%20captures%20and%20that%20restore%20or%20restart%20re-executes::agentbox%2Fsandbox.py%23restore%20re-running%20images%2Fdesktop%2Fagentbox-desktop-start%20%28startxfce4%20as%20desktop%29%20%2B%20workspace_manifest%20scope%20%28%2Fworkspace%20only%29%20%2B%20gui_strays%20baseline%20after%20restore::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries",
  "local_checks": [
   {
    "agent_id": "h-autostart",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/service.py",
     "agentbox/config.py",
     "images/desktop/agentbox-desktop-start",
     "images/desktop/Dockerfile"
    ],
    "invariant": "Every file mutation reachable from a GUI burst that can later re-execute must be captured by the burst's change tracking (gui_changes) or neutralized by stray-kill before a snapshot can persist it.",
    "method": "source",
    "result": "The desktop template command is ['/usr/local/bin/agentbox-desktop-start'] (config.py:74), whose start script execs startxfce4 as uid 1001 desktop with HOME=/home/desktop (agentbox-desktop-start:13-14,30). /home/desktop is mode 700 owned by desktop (Dockerfile:28-30), so the burst principal (uid 1001, reachable via the run-2 N-1 xfce4-terminal path) can write /home/desktop/.config/autostart/*.desktop. workspace_manifest's find is scoped to {WORKSPACE} (/workspace) only (sandbox.py:499), so _close_gui_burst's diff_manifest (service.py:237-248) never records a write under /home/desktop. snapshot() docker-commits the whole container including /home/desktop (sandbox.py:478). restore() rebuilds from the committed image and re-runs tpl.command (sandbox.py:516-520), re-executing startxfce4 and any ~/.config/autostart entry as uid 1001 outside any burst. The re-executed process launches at container boot, so it is always present in the burst-open baseline and exempt from gui_strays (sandbox.py:216). Net: a GUI-burst write outside /workspace is invisible to gui_changes, survives into snapshots, and re-executes on restore/restart with no monitoring.",
    "artifact": null
   },
   {
    "agent_id": "h-autostart",
    "reviewed_paths": [
     "agentbox/sandbox.py"
    ],
    "invariant": "gui_strays must stop a uid-1001 payload that an autostart entry launches after a restore/restart.",
    "method": "local",
    "result": "sbx5 harness importing agentbox.sandbox (python3.13, no net/Docker). Confirmed (1) workspace_manifest's find is scoped to {WORKSPACE} with no /home component; (2) gui_strays([session, autostart-payload], window_pids=set(), baseline={1,100,200}) returns [] (payload survives) when the payload is present at burst open (the restart case, since autostart runs at boot before any burst), whereas the identical payload launched DURING the burst (baseline={1,100}) is returned [200] (killed). This demonstrates the baseline exemption that lets a re-executed autostart process evade stray-kill after restore/restart.",
    "artifact": "agents/h-autostart/artifacts/h.out"
   }
  ]
 }
]

Artifacts are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter)

The parent ran the following bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium (playwright-core) on loopback. You cannot run Docker or a browser; treat these as owner-observed local evidence: re-read every script, confirm it exercises the claimed path, and judge whether its output establishes the claim. Say so in your record if the decisive reproduction is the parent's rather than yours.

- agents/parent-live/artifacts/l12_autostart.py
- agents/parent-live/artifacts/l12_autostart.out

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

<!-- ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries -->
**Chained vulnerabilities and trust boundaries** (subagent_type: `general`)
Individually allowed or contained behavior can become a vulnerability when another component or lifecycle step relies on a stronger guarantee:
- **Multi-step boundary failures**: Map what a low-privilege principal may read, write, invoke, and retain, then connect only concrete outputs to later trust decisions. Confirm each prerequisite and do not assume a downstream effect.
- **Cross-component trust gaps**: Component A validates input and passes it to component B. Compare the exact guarantee A produces with what B assumes, including truncation, type coercion, normalization, tenant scope, and plugin/extension access.
- **Second-order use**: Data safe when stored may become dangerous in a later context. A field name becomes a JSON path, a slug becomes a file path, escaped text enters raw rendering, or a stored string becomes a URL, regex, template, or policy expression.
- **Scope and capability growth**: Token, API-key, plugin, OAuth, MCP, or AI capabilities become broader after delegation, refresh, caching, role change, or composition. Name the concrete operation the resulting principal should not have.
- **Timing and ordering**: Review setup, migration, soft-delete, revoke/cache expiry, check/use, and validate/consume windows. Confirm stale state is accepted before reporting.
- **Rollback and recovery**: Undelete, restore, revision rollback, and cancellation must apply current ownership, validation, and authorization. Confirm which invalid state is restored.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state -->
**Restore reintroduces invalid state**
Backup, undo, undelete, or replica recovery restores data, credentials, memberships, or permissions that current policy no longer allows. Re-authorize restored state and reapply lifecycle changes made after the snapshot.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

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

# Execution boundary and paths

- Agent ID `v19`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/v19/scratch/`. Never edit target files, the ledger, findings, or other agents' directories.
- Read source only from `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` and cite its lines. `/home/user/agentbox` carries later fixes; do not use it for lines.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 v19 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Shell utilities such as bash, timeout and sleep are available inside it.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/v19/artifacts/<file>`.
- No prior record has this fingerprint. Related current records: agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause (v12, confirmed) and agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process (v15, needs_validation) weaken the same GUI-burst controls; this candidate is persistence outside /workspace re-executed on restore, judge its own root cause. The parent-live l12 run (after the hunter finished) drove the whole chain with agent GUI tools.

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
