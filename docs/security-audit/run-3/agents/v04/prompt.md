You are candidate verifier `v04` in a defensive security audit of agentbox (target /home/user/agentbox, read-only, commit 8e4db9e on main; agentbox/ identical to 0e4b958).


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
 "fingerprint": "agentbox/cli.py:runtime_problem:runc-alias-io.containerd.runc.v2-bypasses-exposed-runc-guard",
 "title": "Exposed-serve runc guard checks only the literal runtime name 'runc', so the Docker-registered alias io.containerd.runc.v2 silently bypasses it and suppresses every dev-only warning",
 "description": "cmd_serve refuses to expose a control plane whose sandbox runtime is runc unless --allow-runc/AGENTBOX_ALLOW_RUNC is set. runtime_problem tests `runtime != \"runc\"`, and the UI badge, desktop page badge, healthz dev_only and CLI warnings compare against the same literal. Docker 23+ registers the same runc shim as io.containerd.runc.v2, listed on this host. With AGENTBOX_RUNTIME=io.containerd.runc.v2, _detect_runtime accepts it (it is in Docker's runtime list), the exposed control plane starts without --allow-runc, and the UI, healthz and desktop page show no 'runc: dev only (weak isolation)' warning. Prompt-injected agents then run on the host kernel behind an exposed plane while humans are told isolation is not runc. Plausible by accident: AGENTBOX_RUNTIME=runsc on a host without gVisor fails with an error listing 'io.containerd.runc.v2' first among available runtimes, and README documents pinning AGENTBOX_RUNTIME to any runtime name.",
 "root_cause": "runtime_problem and the warning sites decide on the runtime name string rather than its isolation class; a denylist of exactly 'runc' misses other names Docker maps to runc (io.containerd.runc.v2, crun, nvidia), while _detect_runtime accepts any name Docker reports.",
 "intended_behavior": "Any runtime without a separate kernel boundary is treated as runc for the exposed-serve gate and every dev-only warning; equivalently, exposed serve requires a strong-runtime allowlist (kata-*, runsc) or explicit --allow-runc.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/config.py",
   "line": 31,
   "scope": "Settings.runtime",
   "description": "Operator-supplied AGENTBOX_RUNTIME becomes Settings.runtime."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 296,
   "scope": "SandboxManager._detect_runtime",
   "description": "Explicit runtime accepted if in Docker's Runtimes list (includes io.containerd.runc.v2); the rejection error prints that list."
  },
  {
   "kind": "propagation",
   "file": "agentbox/cli.py",
   "line": 108,
   "scope": "cmd_serve",
   "description": "exposed is True for TLS, behind-proxy or non-loopback bind; runtime_problem(box.sandboxes.runtime, exposed) consulted."
  },
  {
   "kind": "propagation",
   "file": "agentbox/cli.py",
   "line": 84,
   "scope": "runtime_problem",
   "description": "Returns None when runtime != 'runc', so the alias passes; the local warning at cli.py:116 uses the same literal."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 383,
   "scope": "SandboxManager._run_container",
   "description": "Every sandbox created with runtime=io.containerd.runc.v2 behind an exposed plane; healthz (api.py:443), base.html:44 and desktop.py:342 report it as not dev-only."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/cli.py",
   "line": 84,
   "description": "`if runtime != \"runc\" or not exposed: return None` is a literal-name check."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 300,
   "description": "Explicit AGENTBOX_RUNTIME accepted whenever Docker lists it; error at 301 enumerates sorted(available) including io.containerd.runc.v2."
  },
  {
   "file": "agentbox/api.py",
   "line": 443,
   "description": "healthz dev_only is runtime == \"runc\"."
  },
  {
   "file": "agentbox/templates/base.html",
   "line": 44,
   "description": "UI weak-isolation badge only when runtime == \"runc\"."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 342,
   "description": "Desktop page badge only when runtime == \"runc\"."
  },
  {
   "file": "README.md",
   "line": 81,
   "description": "README promises exposed serve refuses to start whenever it would run on runc."
  }
 ],
 "conditions": [
  {
   "kind": "system_configuration",
   "description": "Operator sets AGENTBOX_RUNTIME=io.containerd.runc.v2 (or another runc-class name), e.g. after the runsc-not-found error lists it."
  },
  {
   "kind": "system_configuration",
   "description": "Control plane exposed (--tls-cert, --behind-tls-proxy/compose, or non-loopback host) with no strong runtime."
  },
  {
   "kind": "environmental_dependency",
   "description": "Docker registers io.containerd.runc.v2 (default on Docker 23+, present on Docker 29.9.1 here)."
  }
 ],
 "execution": {
  "attacker_perspective": "No attacker action opens the gap: an operator configuration the guard is meant to refuse is accepted silently. The affected principal is the prompt-injected agent's sandbox, isolated only by the shared host kernel on an exposed plane, while humans see no weak-isolation warning.",
  "payloads": [
   "AGENTBOX_RUNTIME=io.containerd.runc.v2 with Docker Runtimes {io.containerd.runc.v2, runc}; cli.runtime_problem(selected, exposed=True)"
  ],
  "instructions": [
   "Inside the sbx sandbox (no network, no Docker socket), import agentbox.cli and agentbox.sandbox from the read-only target.",
   "Build a SandboxManager via __new__ with Settings() and a fake client whose info() returns Runtimes {'io.containerd.runc.v2','runc'}; for AGENTBOX_RUNTIME in auto, runc, runsc, io.containerd.runc.v2 call _detect_runtime(), cli.runtime_problem(selected, exposed=True) and evaluate selected == 'runc'.",
   "Command: sbx h-deploy /usr/bin/python3.13 /scratch/rt.py > runtime_guard.out"
  ],
  "observed_result": "auto -> 'runc': REFUSE, dev_only True. runc -> 'runc': REFUSE, dev_only True. runsc -> startup error listing ['io.containerd.runc.v2', 'runc']. io.containerd.runc.v2 -> selected; runtime_problem None (exposed serve allowed without --allow-runc), healthz dev_only False, UI runc badge hidden."
 },
 "remediation": {
  "strategy": "Classify runtimes by isolation strength, not by literal name. Gate exposed serve and all dev-only warnings on 'runtime not in a strong allowlist' through one helper used by cli.py, api.py healthz, base.html and desktop.page. Regression test: runtime_problem('io.containerd.runc.v2', True) and runtime_problem('crun', True) are non-None.",
  "code_changes": [
   {
    "file_name": "agentbox/cli.py",
    "fixed_code": "STRONG_RUNTIMES = (\"runsc\", \"kata\")\n\ndef weak_runtime(runtime: str) -> bool:\n    return not runtime.startswith(STRONG_RUNTIMES)\n\ndef runtime_problem(runtime: str, exposed: bool) -> str | None:\n    if not weak_runtime(runtime) or not exposed:\n        return None\n    return (...)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Requires an explicit operator choice of the alias, though the startup error suggests it when runsc is missing."
  },
  "impact": {
   "score": "low",
   "reason": "Grants nothing beyond --allow-runc; the harm is loss of refuse-by-default and false assurance in UI/healthz."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Real runtime_problem/_detect_runtime exercised in a sandboxed harness; literal comparisons visible at every warning site."
 }
}
```


# Linked coverage-unit checks

[
 {
  "coverage_id": "agentbox%2Fcli.py%23cmd_serve%20%2B%20agentbox%2Fapi.py%23create_app%20factory%20%2B%20deploy%2F%2A::agentbox%2Fcli.py%23bind_problem%20%2B%20runtime_problem%20%2B%20sandbox.py%20runtime%20selection::agentbox%2Fcli.py::CLOUD-AND-DEPLOYMENT.md%23Security-control%20precedence%20drift",
  "local_checks": [
   {
    "agent_id": "h-deploy",
    "reviewed_paths": [
     "agentbox/cli.py",
     "agentbox/sandbox.py",
     "agentbox/config.py",
     "agentbox/api.py",
     "agentbox/desktop.py",
     "agentbox/templates/base.html",
     "README.md"
    ],
    "invariant": "An exposed control plane must refuse runc-class isolation unless --allow-runc/AGENTBOX_ALLOW_RUNC, and UI/healthz must flag runc as dev-only",
    "method": "local",
    "result": "sbx harness on real cli.runtime_problem and SandboxManager._detect_runtime with a fake client reporting ['io.containerd.runc.v2','runc']: auto->runc and runc->runc refused when exposed; runsc fails at startup listing 'io.containerd.runc.v2' as available; AGENTBOX_RUNTIME=io.containerd.runc.v2 is selected, runtime_problem returns None (exposed serve starts without --allow-runc), healthz dev_only False, UI runc badge hidden. Auto never picks the alias; a failing preferred runtime raises, no fallback to runc.",
    "artifact": "agents/h-deploy/artifacts/runtime_guard.out"
   },
   {
    "agent_id": "h-deploy",
    "reviewed_paths": [
     "agentbox/cli.py",
     "deploy/docker-compose.yml",
     "deploy/Dockerfile",
     "deploy/Caddyfile"
    ],
    "invariant": "The compose deployment renders to TLS-gated, runc-refusing serve settings",
    "method": "source",
    "result": "CMD agentbox serve --host 0.0.0.0 --behind-tls-proxy + AGENTBOX_BEHIND_TLS_PROXY=1 -> bind_problem None, exposed True; AGENTBOX_ALLOW_RUNC default empty -> guard enforced; AGENTBOX_RUNTIME not passed -> auto, so on this host compose refuses to start unless the operator opts in. 8765 only exposed on the compose bridge; sandboxes are network none.",
    "artifact": null
   },
   {
    "agent_id": "h-deploy",
    "reviewed_paths": [
     "agentbox/cli.py",
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "Trusted-proxy '*' must not let a non-proxy peer forge identity or authorization",
    "method": "source",
    "result": "No bypass: no auth uses request.client or forwarded addresses; auth is Bearer token or hashed cookie session. X-Forwarded-Proto only changes request.url.scheme (secure_cookie already forced when behind; base_url in the human-only MCP snippet, web.py:167). same_origin compares Origin with Host, not rewritten by the proxy middleware.",
    "artifact": null
   },
   {
    "agent_id": "h-deploy",
    "reviewed_paths": [
     "agentbox/api.py",
     "README.md"
    ],
    "invariant": "Bare uvicorn create_app factory must not be a maintained deployment that skips serve gates",
    "method": "source",
    "result": "create_app (api.py:448-450) skips bind/TLS/runtime checks; documented only in its docstring; README and deploy/ use agentbox serve; operator must choose it and a non-loopback host deliberately. Hardening, not a finding.",
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

## Core discipline (include in every agent prompt for this domain)

```
- Do not infer a live exposure from a manifest alone. Establish which environment consumes it, what defaults or overlays modify it, and whether the source path is active.
- Map each workload's identity to specific operations and resources. Broad policy is a finding only when lower-trust input can reach an unauthorized action.
- Ingress, proxies, service mesh, metadata services, and admission policy are real boundaries, but only count a control when its configuration and attachment are visible.
- Secret references are not secret disclosure. Require a lower-trust reader, output, artifact, log path, or unsafe fallback.
- Use `confirmed` for active in-repo configurations and local rendering/policy validation. Use `needs_validation` for account policy, network attachment, runtime admission, hosted metadata, or drift that needs owner observation.
```

## Validation rules (apply before reporting ANY finding here)

1. Establish the active source path and effective deployment object; otherwise use `needs_validation` and state which rendered manifest or owner-observed attachment is missing.
2. Name the lower-trust caller/workload, cloud or application identity, controllable selector, affected resource, and unauthorized operation or disclosure.
3. Verify provider and orchestrator defaults at the pinned version. Do not assume a public IP, reachable metadata service, permissive firewall, or absent admission attachment.
4. Local validation may render templates, evaluate policy, inspect container/user namespaces in an isolated fixture, or run an emulator with dummy identities. Do not probe live endpoints or alter shared cloud resources.
5. Return `confirmed` only with a complete active source trace and concrete boundary result. Return `needs_validation` with the exact deployed policy, identity attachment, overlay, network, or drift observation needed.

# Execution boundary and paths

- Agent ID `v04`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/v04/scratch/`. Never edit target files, the ledger, findings, or other agents' directories.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/sbx v04 <cmd...>` (target at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. jinja2 is not importable there; stub templating if needed.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/v04/artifacts/<file>`.
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
