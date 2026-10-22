You are hunter `h-autostart` in a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage unit, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

# architecture.md (verbatim)

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

# Assigned coverage units

{
 "coverage_id": "GUI-burst%20writes%20outside%20%2Fworkspace%20%28uid%201001%20%2Fhome%2Fdesktop%3A%20.config%2Fautostart%2C%20xfce%20session%2C%20.bashrc%29%20that%20a%20later%20snapshot%20captures%20and%20that%20restore%20or%20restart%20re-executes::agentbox%2Fsandbox.py%23restore%20re-running%20images%2Fdesktop%2Fagentbox-desktop-start%20%28startxfce4%20as%20desktop%29%20%2B%20workspace_manifest%20scope%20%28%2Fworkspace%20only%29%20%2B%20gui_strays%20baseline%20after%20restore::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries",
 "surface": "GUI-burst writes outside /workspace (uid 1001 /home/desktop: .config/autostart, xfce session, .bashrc) that a later snapshot captures and that restore or restart re-executes",
 "boundary": "agentbox/sandbox.py#restore re-running images/desktop/agentbox-desktop-start (startxfce4 as desktop) + workspace_manifest scope (/workspace only) + gui_strays baseline after restore",
 "subsystem": "agentbox/sandbox.py",
 "attack_class": "ATTACK-CLASSES.md#Chained vulnerabilities and trust boundaries",
 "starting_paths": [
  "agentbox/sandbox.py",
  "agentbox/service.py",
  "images/desktop/agentbox-desktop-start",
  "images/desktop/Dockerfile"
 ],
 "ordinary_attack_class_block": null,
 "selected_companion_blocks": [
  "DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state",
  "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy",
  "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves",
  "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules"
 ],
 "excluded_blocks": [
  {
   "block": "CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure",
   "reason": "Owned by the container hardening unit."
  },
  {
   "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
   "reason": "Owned by the gui_lock lifecycle unit."
  }
 ],
 "prior_status": "new"
}

## Parent-provided reconnaissance leads (unverified; settle each one either way, do not assume)

This unit was proposed by the post-wave-2 coverage critic and deferred for budget; it is now assigned to you in wave 3. Critic's reason:
- proposed by post-wave-2 critic (critic-2); Rank 3. Desktop session start on restore honours ~/.config/autostart written by uid 1001; never in gui_changes; needs live-image validation.

Parent-observed facts about the shipped desktop image `agentbox-desktop:0.1` (from `docker run --network none` on this host earlier in this run; you cannot run Docker yourself):
- Installed: xdotool, python3 (ctypes finds libX11.so.6), perl, tclsh/wish (Tk 8.6.14), xfce4-terminal, xauth. NOT installed: xprop, wmctrl, xterm, zenity, gcc, crontab, at.
- `id desktop`: uid 1001, groups desktop(1001), agent(1000). /home/desktop is mode 700 owned by desktop. /etc/xdg/autostart has xfsettingsd.desktop and xscreensaver.desktop; /etc/xdg/xfce4 has panel, xfconf, xinitrc, helpers.rc.
- Agent GUI tools (key/type/click) can open xfce4-terminal as uid 1001 (run-2 N-1, partially mitigated by burst snapshot, gui_changes and stray kill).

For anything that needs the live Docker-backed control plane or the desktop image, make the claim as precise as possible and give an exact local validation plan; the parent will run it in Docker.

# Selected attack-class blocks (verbatim)

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

# Excluded blocks

- `CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure`: Owned by the container hardening unit.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation`: Owned by the gui_lock lifecycle unit.

# Core hunting method

```text
## Defensive vulnerability-finding method

Your goal is to find source-grounded security invariant failures and the smallest fix,
not to expand harm beyond the boundary result. Stay within source review and bounded local execution.
Do not contact deployed endpoints, provider APIs, registries, identity systems,
message brokers, shared services, or other users. Use local dummy data only.

READ THE CODE AT DEPTH. Follow each assigned input through parsing, identity,
authorization, normalization, state, derived copies, and the final sink. Read sibling,
legacy, batch, retry, cancellation, migration, and error paths that produce the same
effect. Compare sibling controls for equivalence, not only presence, and compare what
one component guarantees with what the next component assumes.

WORK FROM A CONCRETE INVARIANT:
1. Name the lower-trust principal and starting capability.
2. Name the accepted value, action, state transition, or resource selector.
3. Locate the control that should reject, bind, isolate, limit, or revoke it.
4. Trace the exact source path after that decision.
5. Stop at the smallest affected dummy record, wrong return value, process-integrity
   effect, or locally observable shared-resource effect.
6. State a source-level change and regression case that enforce the invariant.

DEPTH BOUND: trace only paths that can reach your assigned boundary or whose
guarantees that boundary relies on. Stop a line of investigation as soon as the
invariant is settled either way, and record the result in your structured output —
a covered, candidate, or blocked disposition, or an `uncovered` entry — instead of
continuing to search.

TEST SAD PATHS AND DISAGREEMENTS. Check absent, empty, zero, negative, maximum,
over-limit, duplicate, mixed encoding, stale, revoked, reordered, concurrent,
partially migrated, failed dependency, and rollback state only where the interface
accepts them. Compare canonicalization and units at every parser or policy handoff.
For multi-step issues, treat each output as a prerequisite and do not assume a later
boundary. If any prerequisite is not established, record a blocker.

When a proposed high or critical candidate reveals a reusable root cause, search paths
owned by the assigned coverage IDs for lexical, structural, and logical variants.
Consolidate the same root cause, but establish each variant's conditions and impact
independently. Do not investigate peer-owned units. Return a variant with no current
coverage unit as `uncovered`.

USE THE NARROWEST LOCAL CHECK THAT SETTLES THE CLAIM. Target-controlled builds,
tests, processes, browsers, emulators, fuzzers, and fixture processing may run only
inside the parent-approved OS-enforced sandbox. It must disable external networking,
start from an empty allowlisted environment, expose target and tools read-only, permit
writes only to your scratch directory, and apply low CPU, memory, process, file-size,
disk, and wall-clock limits. Isolated loopback is allowed only for a local fixture.
If any control is unavailable, do not execute: return needs_validation with that exact
blocker. Prefer an existing unit test, minimal function harness, dummy-tenant service
call, small malformed fixture, deterministic race schedule, or locally rendered policy.
Do not install or fetch tools.

Record the exact input, command, limits, and minimum result. For the environment,
record only allowlisted variable names and safe non-secret values needed to reproduce
the check. Never capture the ambient environment, inherited variables, credentials,
authentication state, or unrelated host paths. The target-controlled process writes
only in scratch. After the sandbox and all its processes terminate, only trusted
parent-side code may promote predeclared scratch-relative files, following the
promotion procedure block included verbatim in this prompt. You and target code never
write retained artifacts. If promotion is unavailable or fails for decisive evidence,
return needs_validation with the exact promotion blocker.
Never stress availability, invoke a live target, use a real credential, publish an
artifact, or continue past the minimum observed effect.

A deployment, browser, provider, broker, OS, proxy, package, secret, or identity fact
outside source is not proof either way. If one such fact is decisive, return a
needs_validation record with the exact missing observation and safe owner-observed check.
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

# Core validation rules

```text
## Candidate gate

1. A candidate needs a complete repository-relative source trace and evidence for the
   claimed root cause, including the strongest source-visible control.
2. A proposed confirmed record needs a bounded local observed result, meaningful impact
   across a stated boundary, complete conditions, and no visible preventing layer.
3. Do not strengthen a crash into code execution, ordinary work into shared availability,
   or a same-principal action into privilege gain.
4. If a required fact is not source-visible or locally observable, use
   needs_validation. Name exact blockers; do not give it severity or speculative completion.
5. A missing best practice with no affected principal/resource is excluded or hardening,
   not a finding. A candidate disproved by source is not needs_validation.
6. Use the same source-derived fingerprint for the same root cause in every state.
   It must match `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` and must not include a line,
   wave, agent, severity, or verdict.
7. Return an empty candidate array when nothing survives these gates.
```

# Exclusions and peer-owned units

Carried same-source prior confirmed exclusions: none.

Current records and leads (do not re-report these root causes; report only new root causes or new variants with independent conditions):
- agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare (needs_validation): same_origin ignores the scheme, so a plaintext http:// page on the same host passes the CSRF origin check of a TLS deployment
- agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines (confirmed): The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view
- agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe (confirmed): agentbox agent prints sandbox file contents, file names and model text raw to the operator terminal, bypassing cli._safe
- agentbox/cli.py:runtime_problem:runc-alias-io.containerd.runc.v2-bypasses-exposed-runc-guard (rejected): Exposed-serve runc guard checks only the literal runtime name 'runc', so the Docker-registered alias io.containerd.runc.v2 bypasses it and suppresses the dev-only warnings
- agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions (confirmed): Rotating the human token does not revoke existing full-admin browser sessions (no revoke-all; sessions persist 12 h across restart)
- agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass (confirmed): source_dir overlap guard compares path strings instead of filesystem identity: a second name for the data dir's project folder (bind mount; case variant on case-insensitive drvfs) bypasses it and copies the human token to the agent
- agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process (needs_validation): gui_strays exempts burst-launched uid-1001 processes from the stray kill based on window ownership, including the client-declared _NET_WM_PID
- agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap (confirmed): Prompt-injected agent writes unbounded, undeletable rows into the shared audit log via uncapped tool-call args
- agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit (needs_validation): GUI burst open treats failed container-side collection as success (empty baseline or no burst) with no audit record
- agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover (needs_validation): Human screen takeover (safety override) blocks behind an untimed agent GUI exec holding gui_lock while the in-container X server is unresponsive
- agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency (confirmed): Idle GUI burst close runs another sandbox's untimed docker execs inline on unrelated tool threads and human approval/audit threads
- agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause (confirmed): GUI burst stray-kill and gui_changes logging are lost across sandbox restore and pause
- agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized (confirmed): Web exec approval card renders the agent's command with raw Unicode bidi controls, letting a prompt-injected agent spoof the human approver's view of what will run
- agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve (needs_validation): Cookie-authenticated web UI and desktop page set no frame-ancestors/X-Frame-Options, so a same-site origin can frame /ui/sandboxes/{sid} (or the desktop page) and a single disguised click approves a pending agent action or takes over the desktop
- agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion (parent-observed lead under separate validation): An allowlisted exec such as 'tail -f /dev/null & ' x1100 fills the sandbox pids cgroup; bash then fails to fork and exits 254 before GNU timeout fires, so the group kill never happens and ~1000 uid-1000 tail processes stay. The sandbox remains at pids.max after the exec returns (even a root docker exec pkill could not run), which also keeps GUI-burst collection failing (v09).

Peer-owned coverage IDs (do not duplicate; report a different boundary under `uncovered`):
- agent%20tool%20calls%20that%20require%20approval%20%28POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%20-%3E%20REQUIRE_APPROVAL%29%20on%20desktop%20templates::agentbox%2Fservice.py%23_call_tool%20approval%20creation%3A%20no%20per-sandbox%20pending-approval%20cap%2C%20plus%20a%20per-approval%20PNG%20written%20to%20settings.home%2Fcaptures%20that%20is%20never%20removed%20on%20decision%2C%20expiry%20or%20sandbox%20delete::agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps
- agent-controlled%20audit%20content%20%28tool%20args%2C%20file%20names%2C%20process%20args%29::agentbox%2Faudit.py%23hash%20chain%20%2B%20append-only%20triggers%20%2B%20event%20provenance::agentbox%2Faudit.py::ATTACK-CLASSES.md%23Business%20logic
- agentbox%2Fagent.py%23LLM%20loop%20%2B%20agentbox%2Fmcp_server.py%20tools::agentbox%2Fagent.py%23prompt-injection%20to%20tool%20action%20%28approval%20is%20only%20control%29::agentbox%2Fagent.py::AI-AND-LLM.md%23Indirect%20injection%20through%20retrieved%20or%20ingested%20content
- agentbox%2Fapi.py%23GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%20%2B%20takeover%2Fhandback%20%2B%20state::agentbox%2Fdesktop.py%23ticket%20redeem%20%2B%20session%20scope%20%2B%20lease::agentbox%2Fdesktop.py::WEB-PROTOCOL-AND-AUTH.md%23Session%20fixation%20and%20invalidation
- agentbox%2Fapi.py%23POST%20%2Fapprovals%2F%7Baid%7D%20%2B%20agentbox%2Fcli.py%23cmd_approve::agentbox%2Fservice.py%23decide%20executes%20the%20agent%27s%20original%20args%20after%20human%20approval::agentbox%2Fservice.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%20source_dir%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes::agentbox%2Fsandbox.py%23create%20source_dir%20overlap%20check::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Feature%20abuse%20and%20data%20leakage
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover%20%2B%20handback%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%28end_desktop%29::agentbox%2Fservice.py%23desktop.gui_lock%20held%20across%20untimed%20_x%20GUI%20execs%20%2B%20desktop%20lifecycle%20serialization%20%28takeover%2Fhandback%2Fend_desktop%2Frestore%29::agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%2Cscreenshot%7D::agentbox%2Fservice.py%23GUI%20burst%20snapshot%20%2B%20gui_changes%20%2B%20stray%20kill%20%28N-1%20partial%20mitigation%29::agentbox%2Fservice.py::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D::agentbox%2Fapi.py%23tool_pool%20%2B%20agentbox%2Fservice.py%23call_tool%20tool_concurrency::agentbox%2Fapi.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bwrite_file%2Cdelete_file%2CGUI%7D::agentbox%2Fservice.py%23snapshot%20quota%20%2B%20_snap_locks%20%2B%20GUI%20burst%20snapshots::agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps
- agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2Fexec::agentbox%2Fpolicy.py%23Policy.decide%20read-only-exec%20allowlist::agentbox%2Fpolicy.py::ATTACK-CLASSES.md%23Injection
- agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws::agentbox%2Fapi.py%23cookie%20session%20%2B%20same_origin%20%2B%20lease%20on%20WebSocket::agentbox%2Fapi.py::CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use
- agentbox%2Fapi.py%23all%20JSON%20and%20browser%20routes::agentbox%2Fapi.py%23principal%20%2B%20human_only%20%2B%20screen_human%20%2B%20desktop_human::agentbox%2Fapi.py::ATTACK-CLASSES.md%23Access%20control
- agentbox%2Fapi.py%23tools%20read_file%2Fwrite_file%2Fdelete_file%2Flist_dir%20%2B%20POST%20files%20%2B%20GET%20outbox::agentbox%2Fsandbox.py%23safe_path%20%2B%20_workspace_path%20%2B%20clean_name%20%2B%20FIFO%20guard::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Resource%20and%20file%20handling
- agentbox%2Fcli.py%23cmd_serve%20%2B%20agentbox%2Fapi.py%23create_app%20factory%20%2B%20deploy%2F%2A::agentbox%2Fcli.py%23bind_problem%20%2B%20runtime_problem%20%2B%20sandbox.py%20runtime%20selection::agentbox%2Fcli.py::CLOUD-AND-DEPLOYMENT.md%23Security-control%20precedence%20drift
- agentbox%2Fweb.py%23%2Fui%20%28approval%20approve%2Fdeny%20buttons%2C%20restore%2Fdelete%2Fsnapshot%20forms%29%20%2B%20agentbox%2Fdesktop.py%23page%20%28takeover%2Fhandback%20controls%29%20rendered%20in%20a%20frame::absence%20of%20frame-ancestors%2FX-Frame-Options%20on%20cookie-authenticated%20pages%20%2B%20SameSite%3DStrict%20%2B%20same_origin::agentbox%2Fweb.py::CLIENT-SIDE.md%23Clickjacking
- agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF
- approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls%20%28agentbox%2Fsandbox.py%23preview%2C%20agentbox%2Fservice.py%23_preview%2F_capture%2C%20agentbox%2Ftemplates%2F_approvals.html%2C%20agentbox%2Fcli.py%23_show_approval%29::agentbox%2Fsandbox.py%23preview%20%2B%20_split_segments%20%2B%20_expand%20%2B%20_walk%3A%20the%20system-computed%20%27affected%27%20list%20and%20%27system-captured%27%20screenshot%20shown%20to%20the%20human%20must%20reflect%20what%20the%20stored%20args%20will%20actually%20do::agentbox%2Fsandbox.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding
- code%20running%20inside%20the%20sandbox%20container%20%28uid%201000%20agent%2C%20uid%201001%20desktop%29::agentbox%2Fsandbox.py%23container%20hardening%20flags%20%2B%20root-run%20docker%20execs::agentbox%2Fsandbox.py::CLOUD-AND-DEPLOYMENT.md%23Host%20or%20control-plane%20capability%20exposure
- container%20output%20and%20agent%20request%20bodies::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps::agentbox%2Fsandbox.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality
- container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fsandbox.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Business%20logic
- container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%29::agentbox%2Fweb.py%23describe%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fweb.py::AI-AND-LLM.md%23Insecure%20output%20rendering
- every%20audit%20append%20%28tool%20args%2C%20results%2C%20errors%2C%20GUI%20records%29::agentbox%2Faudit.py%23mask_text%20%2B%20_mask::agentbox%2Faudit.py::ATTACK-CLASSES.md%23Cryptography%20and%20secrets
- whole-repo%23basic%20exposures::whole-repo%23obvious%20controls%20%28secrets%2C%20debug%2C%20cookies%2C%20CORS%2C%20redirects%2C%20errors%29::whole-repo::ATTACK-CLASSES.md%23Obvious%20things
- whole-repo%23undocumented%2Fedge%20surfaces::whole-repo%23feature%20interactions%20not%20covered%20by%20other%20units::whole-repo::ATTACK-CLASSES.md%23Wildcard

# Your paths, sandbox and result contract

- Agent ID: `h-autostart`. Audited source (read-only): `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at 8e4db9e; agentbox/, images/, deploy/, tests/ identical to source_ref 0e4b958). Read source there with Read/Grep/Glob or read-only shell; report repository-relative paths and line numbers of that tree. `/home/user/agentbox` is the working branch with later fixes; do not use it for lines. Never edit target files, ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `/home/user/agentbox/docs/security-audit/run-3/agents/h-autostart/scratch/`. Retained artifacts: `/home/user/agentbox/docs/security-audit/run-3/agents/h-autostart/artifacts/` — parent-owned, never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, running unit tests, harnesses): `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 h-autostart <cmd...>`. Inside it: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3.13`. Example: write `/home/user/agentbox/docs/security-audit/run-3/agents/h-autostart/scratch/h.py`, then run `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 h-autostart /usr/bin/python3.13 /scratch/h.py > /home/user/agentbox/docs/security-audit/run-3/agents/h-autostart/scratch/h.out 2>&1`. For pytest: `/usr/bin/python3.13 -m pytest -p no:cacheprovider --basetemp=/scratch/pt -q /target/tests/test_unit.py`.
- Never run agentbox code outside `sbx5`. Never use the Docker daemon, start servers, or contact the network. If a claim needs the real Docker-backed control plane or the desktop image at runtime, say so: the parent will reproduce it live during validation. Record such a claim as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan, or as `confirmed` only if your sandboxed harness alone demonstrates the boundary result.
- Promotion allowlist: list every scratch-relative file you want retained in a top-level `"artifacts_to_promote": ["h.out", ...]` array in your JSON (max 256 KiB each, 1 MiB total, regular files only). The parent promotes them after you finish; reference them in checks as `agents/h-autostart/artifacts/<file>`. If you have no local check, use `method: "source"` and `artifact: null`.
- Time box: aim to finish within roughly 40 tool calls. Stop each line of investigation once the invariant is settled.

## Structured hunter result

Return exactly one JSON object, with no surrounding prose:

```json
{
  "units": [
    {
      "coverage_id": "one assigned ID",
      "disposition": "covered|candidate|blocked",
      "reviewed_paths": ["repo/relative/path"],
      "checks": [
        {
          "agent_id": "canonical owner of this check",
          "reviewed_paths": ["repo/relative/path owned by this check"],
          "invariant": "specific control checked for this unit",
          "method": "source|local",
          "result": "what source or the bounded check established",
          "artifact": "agents/<agent-id>/artifacts/file for local, null for source"
        }
      ],
      "candidate_fingerprints": [],
      "unresolved": []
    }
  ],
  "candidates": [],
  "hardening": ["concrete non-finding note"],
  "uncovered": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "reason": "why this needs its own deterministic coverage unit"
    }
  ]
}
```

Each `candidates` entry is schema-shaped except that it uses `proposed_verdict` in place of `verdict`:

- `proposed_verdict: "confirmed"`: include every field required by the `confirmed` branch of `report-schema.json` other than `verdict`: `fingerprint`, title, description, `root_cause`, `intended_behavior`, ordered `trace`, `evidence`, `conditions`, target-neutral `execution`, `remediation`, `severity`, and `confidence`. The execution instructions describe only the bounded local check already performed. `payloads` holds the minimum test input, fixture, or native invocation. `observed_result` records actual local output. Overall severity must not exceed observed impact.
- `proposed_verdict: "needs_validation"`: include every field required by that schema branch other than `verdict`: `fingerprint`, title, description, `claimed_root_cause`, ordered `trace`, `evidence`, nonempty `blockers`, and `validation_plan` with at least one applicable `local` or `deployment` step. Do not invent an inapplicable context. Do not include severity, execution, remediation, reason, or a confirmed `root_cause`. `deployment` is an owner-observed check, not a request to probe a live target.

Every assigned coverage ID appears exactly once in `units`. A `covered` unit needs an owner, nonempty `reviewed_paths` and `checks`, no unresolved fact, and no candidate. A `candidate` unit has the same owned evidence and is the only state that carries linked fingerprints. A `blocked` unit is an owned partial review with nonempty paths, checks, and unresolved facts but no fingerprint. All source paths are repository-relative, never absolute or traversal paths. A trace with several entries begins at `entrypoint`, ends at `sink`, and labels intermediate steps `propagation`. Every check has its own canonical lowercase `agent_id` and nonempty `reviewed_paths`; the unit-level list is exactly the union of those owned paths. A `source` check uses `artifact: null`. A `local` check uses one successfully parent-promoted regular file beneath `agents/<check.agent_id>/artifacts/`; this permits a verifier to add independently owned evidence without taking ownership from the hunter. Never link scratch, an output-root file, or another check owner's artifact.


## report-schema.json branches (verbatim): confirmed, needs_validation

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
```

Return exactly one JSON object (the structured hunter result plus `artifacts_to_promote`), with no surrounding prose and no markdown fence.
