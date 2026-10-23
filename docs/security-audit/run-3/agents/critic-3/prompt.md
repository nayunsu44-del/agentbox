You are `critic-3`, the post-wave coverage critic after wave 3 of a defensive security audit of agentbox (audited source, read-only: /tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited, a worktree at 8e4db9e identical to 0e4b958 for agentbox/, images/, deploy/, tests/; cite its lines). You read source but do not write any file, run target code, or contact the network. You propose coverage, not findings.

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


# Full coverage ledger

Read it at /home/user/agentbox/docs/security-audit/run-3/coverage-ledger.json (26 units; every unit is terminal: covered or candidate, each with its assignment block map, status, checks, reviewed paths and linked fingerprints; x_hardening holds hunter hardening notes, attempts holds archived reassignments). Wave 3 assigned the three units critic-2 proposed (approval card impact/capture, approval queue and captures, /home/desktop autostart persistence).

# Current records and candidates

[
 {
  "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
  "state": "final record: needs_validation",
  "title": "same_origin ignores the scheme, so a plaintext http:// page on the same host passes the CSRF origin check of a TLS deployment"
 },
 {
  "fingerprint": "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines",
  "state": "final record: confirmed",
  "title": "The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view"
 },
 {
  "fingerprint": "agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe",
  "state": "final record: confirmed",
  "title": "agentbox agent prints sandbox file contents, file names and model text raw to the operator terminal, bypassing cli._safe"
 },
 {
  "fingerprint": "agentbox/cli.py:runtime_problem:runc-alias-io.containerd.runc.v2-bypasses-exposed-runc-guard",
  "state": "final record: rejected",
  "title": "Exposed-serve runc guard checks only the literal runtime name 'runc', so the Docker-registered alias io.containerd.runc.v2 bypasses it and suppresses the dev-only warnings"
 },
 {
  "fingerprint": "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions",
  "state": "final record: confirmed",
  "title": "Rotating the human token does not revoke existing full-admin browser sessions (no revoke-all; sessions persist 12 h across restart)"
 },
 {
  "fingerprint": "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass",
  "state": "final record: confirmed",
  "title": "source_dir overlap guard compares path strings instead of filesystem identity: a second name for the data dir's project folder (bind mount; case variant on case-insensitive drvfs) bypasses it and copies the human token to the agent"
 },
 {
  "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
  "state": "final record: needs_validation",
  "title": "gui_strays exempts burst-launched uid-1001 processes from the stray kill based on window ownership, including the client-declared _NET_WM_PID"
 },
 {
  "fingerprint": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
  "state": "final record: confirmed",
  "title": "Prompt-injected agent writes unbounded, undeletable rows into the shared audit log via uncapped tool-call args"
 },
 {
  "fingerprint": "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit",
  "state": "final record: needs_validation",
  "title": "GUI burst open treats failed container-side collection as success (empty baseline or no burst) with no audit record"
 },
 {
  "fingerprint": "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover",
  "state": "final record: needs_validation",
  "title": "Human screen takeover (safety override) blocks behind an untimed agent GUI exec holding gui_lock while the in-container X server is unresponsive"
 },
 {
  "fingerprint": "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency",
  "state": "final record: confirmed",
  "title": "Idle GUI burst close runs another sandbox's untimed docker execs inline on unrelated tool threads and human approval/audit threads"
 },
 {
  "fingerprint": "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause",
  "state": "final record: confirmed",
  "title": "GUI burst stray-kill and gui_changes logging are lost across sandbox restore and pause"
 },
 {
  "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
  "state": "final record: confirmed",
  "title": "Web exec approval card renders the agent's command with raw Unicode bidi controls, letting a prompt-injected agent spoof the human approver's view of what will run"
 },
 {
  "fingerprint": "agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve",
  "state": "final record: needs_validation",
  "title": "Cookie-authenticated web UI and desktop page set no frame-ancestors/X-Frame-Options, so a same-site origin can frame /ui/sandboxes/{sid} (or the desktop page) and a single disguised click approves a pending agent action or takes over the desktop"
 },
 {
  "fingerprint": "agentbox/sandbox.py:preview:unrecognized-destructive-segment-omitted-and-catchall-note-suppressed-by-rm-curl-row",
  "state": "wave-3 candidate (confirmed), awaiting Phase 3",
  "title": "Approval impact table omits destructive command segments and suppresses its 'could-not-compute' warning whenever any rm/curl segment is present"
 },
 {
  "fingerprint": "agentbox/service.py:_call_tool:approval-capture-png-and-pending-approval-never-reclaimed",
  "state": "wave-3 candidate (confirmed), awaiting Phase 3",
  "title": "Prompt-injected agent fills control-plane host disk with per-approval screenshot PNGs that are never reclaimed (no pending-approval cap)"
 },
 {
  "fingerprint": "agentbox/sandbox.py:gui-burst:home-desktop-autostart-write-survives-snapshot-and-reexecutes-on-restore",
  "state": "wave-3 candidate (needs_validation), awaiting Phase 3",
  "title": "GUI-burst write to /home/desktop/.config/autostart escapes gui_changes/stray-kill, persists into snapshots, and re-executes as uid 1001 on restore/restart"
 },
 {
  "fingerprint": "agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion",
  "state": "parent-observed lead, Phase 3 verifier v16 running",
  "title": "Background processes started by an approval-free exec outlive the exec's timeout and can pin the sandbox at its pids limit"
 }
]

# Hunter-reported `uncovered` boundaries from wave 3

[]

# Prior-run gap summary

run-1 (7fc501f, standard, source-only) covered 15 units; run-2 validated its records live and all 9 confirmed records have since been fixed (PR #1-#5). run-1 had no deferred/blocked units. Prior needs_validation records were all resolved in run-2. Prior rejected claim (desktop.py redeem -> unscoped session) is re-checked in this run's desktop session unit. The N-1 GUI approval bypass is only partially mitigated (burst snapshot, gui_changes, stray kill) and is accepted/documented; units covering its mitigation are blocked (hunter h-gui stopped early) and need reassignment.

# Your task (verbatim from the skill)

## Coverage-critic waves

Immediately after each hunter wave, spend the reserved invocation on one fresh `research` post-wave coverage critic. It receives `architecture.md`, the full coverage ledger including each assignment block map, current candidate fingerprints and states, and the prior-ledger gap summary. It reads source but does not write or run targets. Require exactly this JSON:

```json
{
  "missing_units": [
    {
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{"block": "FILE.md#section", "reason": "..."}],
      "reason": "source-backed coverage gap"
    }
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}
```


The critic checks for unmapped entry points, unchecked parallel paths, missing lifecycle modes, selected companion classes without a unit, unjustified exclusions, units closed without paths/checks, and prior `needs_validation` or changed-source gaps that no unit addresses. It proposes coverage, not findings. `stop` is the critic's own assessment: `true` only when it accepts no `missing_units` and no `reassign_ids`.

Notes: blocked units are reassignable (use their coverage_id in `reassign_ids` with a source-backed reason in a sibling field `reassign_reasons` mapping id -> reason). Keep `missing_units` to genuinely distinct boundaries (surface x boundary x subsystem x attack class) that no unit already owns; the budget allows at most about 3 more hunters. Cite repository-relative files. Return exactly one JSON object, no prose, no markdown fence.


Budget note: The owner raised the cap to 80; 69 are committed or reserved (hunters, this critic, the final-clean critic, Phase 3 and Phase 5 for the four open candidates). About 4 more hunters fit if you find material gaps; rank them by importance and propose only distinct boundaries no unit already owns.
