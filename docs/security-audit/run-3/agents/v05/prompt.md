You are candidate verifier `v05` in a defensive security audit of agentbox (target /home/user/agentbox, read-only, commit 8e4db9e on main; agentbox/ identical to 0e4b958).


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


# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions",
 "title": "Rotating the human token does not revoke existing full-admin browser sessions (no revoke-all; sessions persist 12 h across restart)",
 "description": "Web UI cookie sessions (scope '*') are stored in ui_sessions with only a cookie hash, scope and expiry; nothing ties them to the human token that authorised them. When the owner rotates the admin secret (new AGENTBOX_HUMAN_TOKEN or deleted data/human_token) and restarts, the old token is rejected but every cookie minted under it stays valid for the rest of its 12 h life: restart deletes only expired rows and session_scope checks only hash and expiry. No revoke-all exists: logout ends only the presented cookie, and logging in or redeeming a ticket over an existing cookie leaves the replaced session valid. A holder of a stolen or earlier-minted agentbox_session cookie keeps full UI authority after the owner revokes the credential: approve/deny agent actions, delete/restore sandboxes, upload files, create sandboxes with a host source_dir.",
 "root_cause": "Session validity is independent of the credential that created it: ui_sessions schema (desktop.py:35-37) has no token-generation column, __init__ (84-93) prunes only expired rows, session_scope (133-145) checks hash and expiry only, and no path deletes all sessions (end_session 127-131 removes one hash).",
 "intended_behavior": "Rotating the human token invalidates all browser sessions and tickets derived from it; the owner has an explicit revoke-all; replacing a session cookie ends the replaced server session.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 117,
   "scope": "login",
   "description": "POST /login compares the form token with the current human_token and calls start_session."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 116,
   "scope": "DesktopControl.new_session",
   "description": "Inserts (hash, public, created, expires=now+12h, scope='*'); no record of the authorising token."
  },
  {
   "kind": "propagation",
   "file": "agentbox/config.py",
   "line": 88,
   "scope": "Settings.human_token",
   "description": "Rotation = new AGENTBOX_HUMAN_TOKEN or regenerated data/human_token, read at start; api.build (api.py:66) uses it only for comparisons."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 91,
   "scope": "DesktopControl.__init__",
   "description": "On restart only expired rows are deleted."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 115,
   "scope": "screen_principal",
   "description": "Without Authorization, accepts the cookie via session_scope (hash + expiry) -> Principal('human', scope='*')."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 204,
   "scope": "decide (/ui/approvals/{aid}/{decision})",
   "description": "browser_human admits the stale cookie to approval decisions and every other /ui admin route."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/desktop.py",
   "line": 35,
   "description": "ui_sessions: hash, public, created, expires, scope only."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 127,
   "description": "end_session deletes exactly one hash; no bulk revocation anywhere."
  },
  {
   "file": "agentbox/web.py",
   "line": 129,
   "description": "Logout revokes only the presented cookie."
  },
  {
   "file": "agentbox/api.py",
   "line": 306,
   "description": "Ticket redemption sets a new cookie without ending the previous session; harness shows the replaced '*' session still valid."
  },
  {
   "file": "README.md",
   "line": 370,
   "description": "README says sessions last 12 h and survive restart; nothing about rotation or revocation."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds a previously valid '*' agentbox_session cookie (shared browser profile, leak, or minted with a since-leaked token)."
  },
  {
   "kind": "system_configuration",
   "description": "Owner rotates the human token and restarts against the same agentbox.db (default)."
  },
  {
   "kind": "timing_dependency",
   "description": "Use within 12 h of minting (fixed TTL, not renewable without the token)."
  }
 ],
 "execution": {
  "attacker_perspective": "A former holder of a full-UI browser session cookie, after the owner rotated the human token to cut them off.",
  "payloads": [
   "POST /login token=hum_OLD_dummy_token_aaaaaaaaaaaa -> capture agentbox_session",
   "restart: api.build() with AGENTBOX_HUMAN_TOKEN=hum_NEW_dummy_token_bbbbbbbbbbbb on the same AGENTBOX_HOME/agentbox.db",
   "GET /ui/approvals, /ui/sandboxes, /ui, POST /ui/approvals/apr_dummy/deny with the old cookie"
  ],
  "instructions": [
   "Ran scratch/h_session.py in sbx (no network/Docker, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s); Docker replaced by a dummy client (info() -> runc); Jinja stubbed (absent in sbx; auth runs before rendering).",
   "Built the real app via agentbox.api.build() with token A, logged in with TestClient, closed and rebuilt with token B on the same DB.",
   "Sent the requests above and recorded status codes."
  ],
  "observed_result": "After rotation: Bearer hum_OLD -> 401; form login hum_OLD -> no cookie; old cookie -> /ui 200, /ui/approvals 200, /ui/sandboxes 200, POST /ui/approvals/apr_dummy/deny 200 (passed authorization); session row 43200 s left. No revoke method. Ticket redemption over the old cookie left the old '*' session valid."
 },
 "remediation": {
  "strategy": "Bind sessions and tickets to a fingerprint of the human token: delete mismatching rows at start and reject mismatches in session_scope. Add a revoke-all (CLI + human-only API) deleting all ui_sessions/ui_tickets and closing screen connections/leases. End the previous session when a new cookie is set over a valid one. Regression test: token A login, rebuild with token B, old cookie -> 401 on /ui/approvals and WS 4401.",
  "code_changes": [
   {
    "file_name": "agentbox/desktop.py",
    "fixed_code": "# ui_sessions gains gen TEXT NOT NULL DEFAULT ''\n# __init__(..., token_gen=''): migrate column; DELETE FROM ui_sessions WHERE gen != ?; DELETE FROM ui_tickets\n# new_session inserts gen; session_scope: WHERE hash = ? AND gen = ?\ndef revoke_all(self): ..."
   },
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "desktop=D.DesktopControl(..., token_gen=hashlib.sha256(human_token.encode()).hexdigest()[:16])"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Requires prior possession of a valid '*' cookie or the old token; window at most 12 h."
  },
  "impact": {
   "score": "high",
   "reason": "Stale session keeps full admin UI authority after the owner revokes the only credential, and survives restart."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Complete source trace and a bounded harness with the real app factory and auth dependencies."
 }
}
```


# Linked coverage-unit checks

[
 {
  "coverage_id": "agentbox%2Fapi.py%23GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%20%2B%20takeover%2Fhandback%20%2B%20state::agentbox%2Fdesktop.py%23ticket%20redeem%20%2B%20session%20scope%20%2B%20lease::agentbox%2Fdesktop.py::WEB-PROTOCOL-AND-AUTH.md%23Session%20fixation%20and%20invalidation",
  "local_checks": [
   {
    "agent_id": "h-session",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/api.py",
     "agentbox/web.py",
     "agentbox/config.py",
     "README.md"
    ],
    "invariant": "Browser sessions minted under a human token are invalidated when the token is rotated, and the owner can revoke all sessions.",
    "method": "local",
    "result": "Fails. ui_sessions has no binding to the human token (desktop.py:35-37); session_scope checks only hash + expiry (133-145); restart deletes only expired rows (91-93). Harness: login with hum_OLD -> '*' cookie; rebuild with AGENTBOX_HUMAN_TOKEN=hum_NEW on the same DB: old token 401 / no cookie, but old cookie -> 200 on /ui, /ui/approvals, /ui/sandboxes and POST /ui/approvals/{aid}/deny passed auth; row had 43200 s left. No revoke-all; logout ends only the presented cookie (desktop.py:127-131, web.py:129-137).",
    "artifact": "agents/h-session/artifacts/h_session.out"
   },
   {
    "agent_id": "h-session",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "Prior rejected claim re-check: a sandbox-scoped ticket/session cannot act as a '*' session on any cookie route.",
    "method": "local",
    "result": "Holds. redeem deletes the ticket first and requires scope == sid (desktop.py:105-114); /login redeems only '*' tickets (web.py:110-115). Harness: scoped cookie -> 403 on /ui/approvals, /ui/sandboxes, outbox, capture.png, other sid's state/takeover/handback; /ui redirects to /login.",
    "artifact": "agents/h-session/artifacts/h_session.out"
   },
   {
    "agent_id": "h-session",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/service.py",
     "agentbox/api.py"
    ],
    "invariant": "Lease ownership keyed on public hs_ id (32 bits) cannot be assumed by a principal who learns another session's public id.",
    "method": "local",
    "result": "Holds: ids are disclosed in 409 details/audit but no route accepts a public id as input; lease comparisons use the cookie-derived id. Collision needs ~2^16 human-minted sessions (hardening).",
    "artifact": "agents/h-session/artifacts/h_session.out"
   },
   {
    "agent_id": "h-session",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/service.py",
     "agentbox/web.py"
    ],
    "invariant": "Takeover/handback/state and ticket issue/redeem reachable only by intended principals; header handback force-release human only; GET redemption not drivable by lower trust.",
    "method": "source",
    "result": "Holds. desktop_human rejects agents; takeover requires a cookie session; header handback (session=None) only after the human token matched; agents on state limited to own sid; tickets human_only, 60 s, hashed, one-time, sid-bound; cookies minted server-side so fixation is impossible.",
    "artifact": null
   },
   {
    "agent_id": "h-session",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/desktop.py",
     "agentbox/web.py"
    ],
    "invariant": "Logout and expiry end the session's screen connections and hand back its lease.",
    "method": "local",
    "result": "Holds for the presented session (end_ui_session, service.py:517-527); WS re-checks every 30 s (api.py:391-404). Cross-session gaps folded into the candidate.",
    "artifact": "agents/h-session/artifacts/h_session.out"
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

## Core discipline (include in every agent prompt for this domain)

```
- Establish the realistic local or remote-content attacker: another app, another OS user, a sandboxed child, an untrusted document, or a remote origin. Self-harm within the same account and authority is not a boundary violation.
- Paths, process names, bundle/package IDs, and claimed sender fields are not peer authentication. Use OS peer credentials, code identity, capability handles, or protected channel state.
- The native bridge or helper must authorize each operation and final resource after parsing. A trusted UI or broker does not make attacker-influenceable arguments trusted.
- OS sandbox, signing, entitlements, permissions, keychain ACLs, exported-component policy, and prompt behavior are real controls when pinned and visible.
- Use `confirmed` for source evidence plus bounded local/emulator tests. Use `needs_validation` when signing, manifest merge, OS version, device policy, installer ACL, or packaging is required but not observable.
```

## Validation rules (apply before reporting ANY finding here)

1. Name the attacker starting capability, OS/app principal crossed, entry channel, accepted argument or state, and unauthorized operation or disclosure.
2. Confirm OS sandbox, peer credential, signing, entitlement, permission, user-consent, and installer controls that apply. Unknown packaging/runtime facts require `needs_validation`.
3. For webview bridges, cite both navigation/origin control and privileged native sink. For IPC, cite peer authentication and per-resource authorization. For helpers, verify final normalized destination.
4. Keep local tests bounded and use dummy content/accounts. Stop after proving the boundary result; do not extend proof into persistence or broader system modification.
5. Return `confirmed` only with a complete source and local evidence chain. Return `needs_validation` with the exact OS, manifest, signing, ACL, or device-lifecycle fact required.

## Core discipline (include in every agent prompt for this domain)

```
- Framing and cache findings require two interpretations of the same request, response, or key. Name both components and the exact normalized value on each side.
- For every credential, find the signature or secret verification and every binding required for its role: issuer, audience, origin, RP, client, session, principal, resource, assurance, expiry, and one-time state.
- Host, Forwarded, X-Forwarded-*, Origin, Referer, redirect targets, callback state, and request-derived URLs are trust decisions. Trace each to the affected identity or response.
- A missing header, cookie attribute, MFA prompt, or rate limit is not a finding alone. Require an accepted invalid request, cross-principal impact, assurance downgrade, or credential disclosure.
- Classify `confirmed` only from complete source evidence and bounded local request/token tests. Use `needs_validation` when proxy, IdP, browser, certificate, secret, or deployed configuration is required but not visible.
```

## Validation rules (apply before reporting ANY finding here)

1. Apply a source-visibility gate. Proxy chains, edge cache keys, IdP policy, certificate trust, browser cookie behavior, secrets, and deployed auth modes may be outside the repository. Record a precise `needs_validation` candidate instead of asserting missing infrastructure behavior.
2. For framing and cache findings, name both components and the divergent parse/key. Confirm cross-request, cross-user, or private-response impact with bounded local fixtures.
3. For token, MFA, passkey, account-link, recovery, API-key, and mTLS findings, cite the verification line and missing principal/session/resource/origin/audience/action/assurance binding. Prove the server accepts the invalid transition or credential.
4. For CSRF, name the ambient credential, state-changing route, accepted cross-site request shape, browser cookie policy, and missing effective check. Read-only actions and routes requiring a non-ambient bearer token do not qualify.
5. Verify framework and library defaults. If version or configuration is unknown, use `needs_validation`; do not turn an unverified critical claim into a lower-severity confirmed finding.
6. Return `confirmed` only with a complete source trace and observable unauthorized identity, state, or disclosure. For `needs_validation`, name the missing fact and safe local or owner-observed check that resolves it.

# Execution boundary and paths

- Agent ID `v05`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/v05/scratch/`. Never edit target files, the ledger, findings, or other agents' directories.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/sbx v05 <cmd...>` (target at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. jinja2 is not importable there; stub templating if needed.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/v05/artifacts/<file>`.
- No prior record has this fingerprint. Related prior root causes (run-2, all fixed): N-1 GUI tools bypass exec approval (partially mitigated), exec output buffering, threadpool starvation, snapshot quota, source_dir overlap, terminal approval escape spoof.

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
