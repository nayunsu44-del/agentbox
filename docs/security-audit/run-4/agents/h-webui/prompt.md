You are hunter `h-webui` in run-4 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

# architecture.md (verbatim)

# agentbox architecture summary (run-4)

Source ref: `9805d91` (`main`, after refactor PRs #11-#14). Profile `standard`, whole repo, budget 50. Built from recon-1a..1d (`agents/recon-*/result.md`). Line numbers below were re-checked by the parent; recon-1b and recon-1c cite some `api.py`, `web.py` and `preview.py` lines that do not exist in this tree, so treat their numbers as approximate.

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
| Agent → approval gate (GUI) | none by design; burst snapshot, fail-closed open, `gui_changes`, stray kill (N-1 partial) |
| Agent → human authority | token kinds, `human_only`, scope checks, `samefile` source_dir overlap check |
| Agent → control-plane availability | `tool_pool`, tool concurrency, `_Head`, snapshot quota, pending cap, `_timed` X/manifest execs |
| Container output → control plane | `_parse_ps`, `_parse_manifest`, `_parse_outbox`, preview parsing; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin`, XFO/frame-ancestors |
| Desktop-link session → rest of UI | `scope`, `desktop_human` |
| Network → control plane | `bind_problem`; proxy trust `*`; unauthenticated login/novnc routes |

## 6. Starting paths

`agentbox/service.py`, `gui_bursts.py`, `gui_state.py`, `sandbox.py`, `sandbox_desktop.py`, `sandbox_common.py`, `preview.py`, `api.py`, `desktop_ws.py`, `web.py`, `display.py`, `desktop.py`, `policy.py`, `audit.py`, `approvals.py`, `cli.py`, `config.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `templates/`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

Prior ledgers: run-1 (`7fc501f`) and run-3 (`0e4b958`/`8e4db9e`, incomplete, 29 units); run-2 validated run-1 live. Every run-3 confirmed record (11) was fixed and the refactor moved the code, so all are `prior_confirmed_changed_source` revalidation units, not hunter exclusions. Five run-3 `needs_validation` records (v01 same_origin scheme, v09 burst open, v10 gui_lock, v14 framing, v15 `gui_strays` window ownership) are current work. Three critic-3 units deferred in run-3 (GUI-burst state races, disk/SQLite pressure, pre-auth work) are current work. Two rejected claims (runc alias, backgrounded-children pid exhaustion) suppress only those exact claims. No same-source confirmed exclusions. Recon-flagged seams: lifecycle methods without `gui_lock`/`_snap_locks`, `decide` outside the snapshot lock, synchronous burst closes on human threads, unbounded/untimed preview and listing execs, error/preview strings that bypass the audit arg cap, unauthenticated audit growth, x11vnc remote-control plus `from_exec` stray exemption, root `/tmp` operations in the desktop start script.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent work consumes shared pools, memory, SQLite and host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: htmx UI and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 helper inspected and killed by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader, lifecycle consolidation.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release or signing path; CI runs tests with read-only contents), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker or RPC beyond HTTP/WS/MCP stdio covered elsewhere).

# Assigned coverage units

[
 {
  "coverage_id": "agentbox%2Fweb.py%23%2Fui%20pages%20%2B%20agentbox%2Fdesktop.py%23page%20rendered%20in%20a%20frame::agentbox%2Fapi.py%23X-Frame-Options%20%2B%20CSP%20frame-ancestors%20%27self%27%20on%20cookie-authenticated%20pages%20%2B%20SameSite%3DStrict%20%2B%20same_origin::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fdesktop.py::CLIENT-SIDE.md%23Clickjacking",
  "surface": "agentbox/web.py#/ui pages + agentbox/desktop.py#page rendered in a frame",
  "boundary": "agentbox/api.py#X-Frame-Options + CSP frame-ancestors 'self' on cookie-authenticated pages + SameSite=Strict + same_origin",
  "subsystem": "agentbox/api.py + agentbox/web.py + agentbox/desktop.py",
  "attack_class": "CLIENT-SIDE.md#Clickjacking",
  "starting_paths": [
   "agentbox/api.py",
   "agentbox/web.py",
   "agentbox/desktop.py"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "CLIENT-SIDE.md#Core discipline",
   "CLIENT-SIDE.md#Clickjacking",
   "CLIENT-SIDE.md#Client-side navigation confusion",
   "CLIENT-SIDE.md#Universal moves",
   "CLIENT-SIDE.md#Validation rules",
   "WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport"
  ],
  "excluded_blocks": [
   {
    "block": "MEMORY-SAFETY-AND-BINARY.md#Core discipline",
    "reason": "No native code in scope."
   },
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "reason": "No release, signing or update path."
   },
   {
    "block": "PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline",
    "reason": "No broker/RPC."
   }
  ],
  "prior_status": "prior_needs_validation"
 },
 {
  "coverage_id": "agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF",
  "surface": "agentbox/web.py#/ui/* + /login + /logout",
  "boundary": "agentbox/api.py#same_origin + SameSite=Strict HttpOnly cookie",
  "subsystem": "agentbox/api.py + agentbox/web.py",
  "attack_class": "WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF",
  "starting_paths": [
   "agentbox/api.py",
   "agentbox/web.py",
   "agentbox/desktop.py"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
   "WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF",
   "WEB-PROTOCOL-AND-AUTH.md#Host and forwarded-header trust",
   "WEB-PROTOCOL-AND-AUTH.md#Universal moves",
   "WEB-PROTOCOL-AND-AUTH.md#Validation rules"
  ],
  "excluded_blocks": [
   {
    "block": "MEMORY-SAFETY-AND-BINARY.md#Core discipline",
    "reason": "No native code in scope; all control-plane code is Python."
   },
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "reason": "No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage)."
   },
   {
    "block": "PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline",
    "reason": "No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions."
   },
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "AI-AND-LLM.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLIENT-SIDE.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLOUD-AND-DEPLOYMENT.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   }
  ],
  "prior_status": "prior_needs_validation"
 },
 {
  "coverage_id": "container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%2C%20approval%20cards%29::agentbox%2Fdisplay.py%23escape_controls%20%2B%20agentbox%2Fweb.py%23describe%2F_shown%2Ffinalize%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fcli.py%20%2B%20agentbox%2Ftemplates::AI-AND-LLM.md%23Insecure%20output%20rendering",
  "surface": "container-controlled strings rendered to humans (outbox names, gui_changes paths, ps args, exec output, errors, approval cards)",
  "boundary": "agentbox/display.py#escape_controls + agentbox/web.py#describe/_shown/finalize + Jinja autoescape + agentbox/cli.py#_safe",
  "subsystem": "agentbox/display.py + agentbox/web.py + agentbox/cli.py + agentbox/templates",
  "attack_class": "AI-AND-LLM.md#Insecure output rendering",
  "starting_paths": [
   "agentbox/display.py",
   "agentbox/web.py",
   "agentbox/cli.py",
   "agentbox/templates"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "AI-AND-LLM.md#Core discipline",
   "AI-AND-LLM.md#Insecure output rendering",
   "AI-AND-LLM.md#Universal moves",
   "AI-AND-LLM.md#Validation rules",
   "CLIENT-SIDE.md#Core discipline",
   "CLIENT-SIDE.md#DOM-based XSS",
   "CLIENT-SIDE.md#Universal moves",
   "CLIENT-SIDE.md#Validation rules"
  ],
  "excluded_blocks": [
   {
    "block": "MEMORY-SAFETY-AND-BINARY.md#Core discipline",
    "reason": "No native code in scope; all control-plane code is Python."
   },
   {
    "block": "SUPPLY-CHAIN-AND-RELEASE.md#Core discipline",
    "reason": "No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage)."
   },
   {
    "block": "PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline",
    "reason": "No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions."
   },
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "WEB-PROTOCOL-AND-AUTH.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "CLOUD-AND-DEPLOYMENT.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   },
   {
    "block": "DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline",
    "reason": "Not on this unit's boundary; covered by the units that select it."
   }
  ],
  "prior_status": "prior_confirmed_changed_source"
 }
]

## Prior-run records linked to these units (changed source: revalidate, do not assume)

All relevant source changed since run-3 (fixes and a behaviour-preserving refactor). For each prior confirmed record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can (candidate with the same fingerprint as confirmed, needs_validation, or record in your unit check why it no longer holds). A prior rejected claim may be re-reported only with changed evidence.

- `agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve` — run-3 needs_validation : Cookie-authenticated web UI and desktop page set no frame-ancestors/X-Frame-Options, so a same-site origin can frame /ui/sandboxes/{sid} (or the desktop page) and a single disguised click approves a pending agent action or takes over the desktop
  Root cause (run-3 wording): Cookie-authenticated HTML (render() in web.py sets only Cache-Control/X-AB-Version; desktop_page sets only Cache-Control; Caddyfile adds no headers; no middleware in api.build) carries no framing policy, and the state-changing UI actions rely only on SameSite=Strict plus same_origin() -- neither of which stops a same-site framer or a click induced inside the framed agentbox document. SameSite=Strict blocks only genuinely cross-site framers; it does not scope by port or subdomain, so a same-site origin defeats it.
- `agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare` — run-3 needs_validation : same_origin ignores the scheme, so a plaintext http:// page on the same host passes the CSRF origin check of a TLS deployment
  Root cause (run-3 wording): api.py:108-110: same_origin() accepts when urlsplit(origin).netloc == headers['host'] with no scheme comparison, so the cross-origin defence degrades to the browser treating http/https of one host as cross-site; nothing in source emits Strict-Transport-Security (deploy/Caddyfile, agentbox/ and images/ set none), so an active network attacker can serve http://H.
- `agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe` — run-3 confirmed low: agentbox agent prints sandbox file contents, file names and model text raw to the operator terminal, bypassing cli._safe
  Root cause (run-3 wording): cli.py:353-361 cmd_agent.log prints 'say', 'call' and 'result' strings without cli._safe, and agent.py:116-126 ToolClient.call_text passes read_file content and list_dir listings through verbatim (other results via json.dumps(ensure_ascii=False), which keeps C1 controls).
- `agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized` — run-3 confirmed medium: Web exec approval card renders the agent's command with raw Unicode bidi controls, letting a prompt-injected agent spoof the human approver's view of what will run
  Root cause (run-3 wording): _approvals.html:8 relies on HTML autoescape, which neutralises markup but not Unicode bidi/control characters; the web UI has no equivalent of cli._safe (cli.py:34-39) for approval args, and base.html:23's pre style applies no unicode-bidi isolation. The terminal path escapes these characters (cli.py:196-199) but the web path does not, so the two human-facing surfaces disagree about the same command.

## Parent-provided reconnaissance leads

Recon leads (unverified): escape_controls omits U+061C, U+2028/2029 and zero-width characters; non-string values render via str(); outbox filename flows into a browser Notification body (base.html); request.base_url (Host/forwarded headers) is written into the MCP config shown at create time.
Settle each lead either way from current source; they are not findings.

# Selected attack-class blocks (verbatim)

<!-- CLIENT-SIDE.md#Clickjacking -->
**Clickjacking**
A framed, state-changing action lacks effective `frame-ancestors`, `X-Frame-Options`, or equivalent UI isolation. Require the sensitive action and confirm it can complete in the framed state; missing headers on read-only content are hardening notes.

<!-- CLIENT-SIDE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A client-side candidate needs a controllable source and an executing or disclosing sink. Name both and show attacker-influenced data reaching the sink.
- The impact must reach a victim's session, another origin, or shared persistence. Self-injection and disclosure of the attacker's own data are not findings.
- Framework escaping, browser same-origin policy, CSP, COOP/CORP, service-worker scope, and modern noopener defaults are real controls. Verify them before assigning impact.
- Browser storage and caches are shared by origin and may outlive login state. Identify who writes, who reads, and which account, tenant, or worker lifecycle clears each record.
- Use `confirmed` only for complete source evidence plus bounded local browser tests. Use `needs_validation` when renderer, extension permission, deployed header, or browser-policy behavior is required but unavailable.
```

<!-- CLIENT-SIDE.md#Client-side navigation confusion -->
**Client-side navigation confusion**
A client source controls redirect or navigation without scheme and destination policy, including executable `javascript:` or `data:` destinations. Reverse tabnabbing applies only where code explicitly keeps `window.opener`, uses `window.open` without isolation, or supports a browser without implicit `noopener`.

<!-- CLIENT-SIDE.md#Universal moves -->
## Universal moves (apply across the above)

- Start from DOM, navigation, worker, message, and storage sinks, then trace backward to browser-only and server-controlled sources. Record the browser policy that should stop the path.
- Test account switch, logout, worker update, offline fallback, and stale-tab state with a local test origin and dummy accounts. Do not use production users, origins, or shared services.
- For XS-Leaks, list only predicates proved by source and local browser behavior. Then identify the response headers or rendering choice that would remove the oracle.

<!-- CLIENT-SIDE.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Cite the source, sink, browser policy, affected origin/session, and observable mutation or disclosure.
2. For prototype pollution, prove the recursive write and a security-relevant gadget. For DOM clobbering, prove the markup survives and the shadowed value is used.
3. For service workers and storage, prove lifecycle reachability: an attacker-controlled write or cache entry must reach a different account, tenant, or later authorization state.
4. For messaging, CORS, WebSocket, and XS-Leaks, show exact origin/source validation and the protected state or action exposed. Confirm that CSP, COOP/CORP, cookies, and SameSite policy do not already block it.
5. Return `confirmed` findings only with a complete client path and bounded local evidence. Return `needs_validation` with the precise deployed header, extension permission, browser version, or renderer behavior an owner must verify.

<!-- WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport -->
**Cookie scope and transport**
A sensitive cookie has an over-broad `Domain` or `Path`, can cross an insecure transport, or conflicts with a sibling cookie that another component selects differently. Bare missing flags remain hardening notes unless a realistic less-trusted origin, network position, or browser path can gain or replace the credential.

<!-- WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF -->
**Ordinary CSRF**
A browser sends ambient credentials to a state-changing endpoint that accepts a cross-site request without an effective anti-CSRF token, same-site request binding, or strict Origin/Referer validation. Inventory every cookie-authenticated mutation, including form, JSON-like, multipart, method-override, and legacy routes. SameSite is effective only for the cookie and browser contexts actually used; login CSRF and cross-site subresource requests can have different requirements.

<!-- WEB-PROTOCOL-AND-AUTH.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Framing and cache findings require two interpretations of the same request, response, or key. Name both components and the exact normalized value on each side.
- For every credential, find the signature or secret verification and every binding required for its role: issuer, audience, origin, RP, client, session, principal, resource, assurance, expiry, and one-time state.
- Host, Forwarded, X-Forwarded-*, Origin, Referer, redirect targets, callback state, and request-derived URLs are trust decisions. Trace each to the affected identity or response.
- A missing header, cookie attribute, MFA prompt, or rate limit is not a finding alone. Require an accepted invalid request, cross-principal impact, assurance downgrade, or credential disclosure.
- Classify `confirmed` only from complete source evidence and bounded local request/token tests. Use `needs_validation` when proxy, IdP, browser, certificate, secret, or deployed configuration is required but not visible.
```

<!-- WEB-PROTOCOL-AND-AUTH.md#Host and forwarded-header trust -->
**Host and forwarded-header trust**
Untrusted host/proxy metadata determines absolute URLs, tenant routing, callbacks, reset links, cache keys, or the client address used by authorization. Confirm who can supply the header and whether trusted ingress removes client-provided copies.

<!-- WEB-PROTOCOL-AND-AUTH.md#Universal moves -->
## Universal moves (apply across the above)

- Walk issue → store → transmit → consume → refresh → revoke for every credential and challenge. Compare normal, error, retry, migration, legacy, and account-switch paths.
- Enumerate every door to the same identity and every route to the same sensitive operation. The effective policy is the weakest parallel path, not the most polished UI.
- Diff parser, proxy, router, cache, and application normalization side by side. For local validation, feed identical bounded request fixtures into each component rather than sending traffic to a live deployment.
- For recovery and linking, draw the account before/after graph. Each edge must name the current principal, proof of the new identity, required assurance, callback/session binding, and revocation effect.

<!-- WEB-PROTOCOL-AND-AUTH.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Apply a source-visibility gate. Proxy chains, edge cache keys, IdP policy, certificate trust, browser cookie behavior, secrets, and deployed auth modes may be outside the repository. Record a precise `needs_validation` candidate instead of asserting missing infrastructure behavior.
2. For framing and cache findings, name both components and the divergent parse/key. Confirm cross-request, cross-user, or private-response impact with bounded local fixtures.
3. For token, MFA, passkey, account-link, recovery, API-key, and mTLS findings, cite the verification line and missing principal/session/resource/origin/audience/action/assurance binding. Prove the server accepts the invalid transition or credential.
4. For CSRF, name the ambient credential, state-changing route, accepted cross-site request shape, browser cookie policy, and missing effective check. Read-only actions and routes requiring a non-ambient bearer token do not qualify.
5. Verify framework and library defaults. If version or configuration is unknown, use `needs_validation`; do not turn an unverified critical claim into a lower-severity confirmed finding.
6. Return `confirmed` only with a complete source trace and observable unauthorized identity, state, or disclosure. For `needs_validation`, name the missing fact and safe local or owner-observed check that resolves it.

<!-- AI-AND-LLM.md#Insecure output rendering -->
**Insecure output rendering**
Model output reaches an executing HTML, Markdown, template, URL, or command sink without the sink's required encoding and policy. For browser rendering, verify auto-loaded resources and CSP or sanitization in `CLIENT-SIDE.md`; renderer behavior outside the repository makes the candidate `needs_validation`.

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

<!-- CLIENT-SIDE.md#DOM-based XSS -->
**DOM-based XSS**
Trace `location` fields, `document.referrer`, `window.name`, message data, storage, and browser-controlled document state into `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs, executable URLs, jQuery HTML APIs, or framework escape hatches. Interpolation escaped by the framework is not a finding.

# Excluded blocks

- `MEMORY-SAFETY-AND-BINARY.md#Core discipline`: No native code in scope.
- `SUPPLY-CHAIN-AND-RELEASE.md#Core discipline`: No release, signing or update path.
- `PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline`: No broker/RPC.
- `MEMORY-SAFETY-AND-BINARY.md#Core discipline`: No native code in scope; all control-plane code is Python.
- `SUPPLY-CHAIN-AND-RELEASE.md#Core discipline`: No release, signing or update path; CI only runs tests (separate wildcard/obvious coverage).
- `PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline`: No broker or RPC framework; HTTP/WS/MCP stdio are covered by web, client-side and AI companions.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `AI-AND-LLM.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `CLIENT-SIDE.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `CLOUD-AND-DEPLOYMENT.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.
- `WEB-PROTOCOL-AND-AUTH.md#Core discipline`: Not on this unit's boundary; covered by the units that select it.

# Core hunting method (verbatim)

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

# Core validation rules (verbatim)

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

Carried same-source prior confirmed exclusions: none (no unit is same-source).

Peer-owned coverage IDs (do not investigate these; report a different boundary you notice under `uncovered`):
- `GUI-burst%20writes%20outside%20%2Fworkspace%20by%20uid%201001%20%28%2Fhome%2Fdesktop%2C%20%2Ftmp%2C%20%2Fdev%2Fshm%2C%20%2Frun%2Fuser%2C%20XDG%20dirs%29%20that%20persist%20through%20snapshot%2C%20restore%20or%20restart::images%2Fdesktop%2Fagentbox-desktop-start%23%2Fhome%2Fdesktop%20reset%20at%20start%20%2B%20agentbox%2Fgui_state.py%23workspace%20manifest%20scope::images%2Fdesktop%20%2B%20agentbox%2Fsandbox.py%23restore%2Fstart%20%2B%20agentbox%2Fgui_bursts.py::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries` (owner h-container)
- `Host-disk%20and%20SQLite%20pressure%20caused%20by%20agent%20actions%20%28audit%20rows%2C%20approval%20rows%2C%20captures%20PNGs%2C%20docker%20commit%20snapshots%2C%20sources%20dirs%29%20and%20by%20human%20read%20paths%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20%2Fui%2Fverify%2C%20%2Faudit%2Fverify%2C%20cmd_verify%2C%20GET%20%2Fapprovals%29::Agent-grown%20data%20-%3E%20one%20process-wide%20audit%20lock%20and%20one%20SQLite%20file%20shared%20by%20four%20connections%20%28AuditLog%2C%20ApprovalStore%2C%20SandboxManager%2C%20DesktopControl%29.%20AuditLog.verify%28%29%20and%20list%28%29%20run%20fetchall%20of%20the%20whole%20table%20under%20the%20same%20lock%20that%20every%20append%20needs%20%28agentbox%2Faudit.py%3A196-215%2C%20152-187%29.%20_safe_log%20swallows%20AuditWriteError%20after%20execution%20%28agentbox%2Fservice.py%3A362-369%29%2C%20while%20_close_gui_burst%20has%20already%20popped%20the%20burst%20before%20logging%20gui_changes%20or%20gui_processes_stopped.%20ApprovalStore%20claim%2C%20finish%20and%20create%20raise%20raw%20sqlite3%20errors%20%28approvals.py%3A49-92%29%2C%20not%20AuditWriteError.::agentbox%2Faudit.py%23append%20%2B%20list%20%2B%20verify%3B%20agentbox%2Fservice.py%23_safe_log%20%2B%20_close_gui_burst%20%2B%20decide%20%2B%20expire_stale%3B%20agentbox%2Fapprovals.py%23create%2Fclaim%2Ffinish%3B%20agentbox%2Fapi.py%23list_audit%2Fverify%3B%20agentbox%2Fweb.py%23verify_frag%2Faudit_frag::Failure%20and%20recovery%20under%20resource%20exhaustion%3A%20read-side%20lock%20hold%20time%20and%20memory%20on%20the%20shared%20audit%20lock%3B%20fail-closed%20%28503%29%20versus%20fail-open%20%28silently%20dropped%20post-hoc%20records%2C%20approvals%20stuck%20in%20approved%29%20behaviour%20at%20disk-full%20or%20lock%20contention` (owner h-audit)
- `Unauthenticated%20network%20requests%20handled%20before%20any%20principal%20check%3A%20JSON%20and%20multipart%20bodies%20on%20POST%20%2Fsandboxes%2C%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%2C%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%2C%20%2Fapprovals%2F%7Baid%7D%20and%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Ffiles%3B%20the%20POST%20%2Flogin%20form%3B%20GET%20%2Fstatic%2Fnovnc%2F%7Bpath%7D%3B%20GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%3Fticket%3D%3B%20GET%20%2Fhealthz::Network%20attacker%20with%20no%20token%20-%3E%20control-plane%20memory%2C%20the%20%2Ftmp%20multipart%20spool%2C%20the%20Docker%20daemon%20and%20the%20audit%20chain.%20FastAPI%20reads%20and%20parses%20the%20body%20before%20it%20resolves%20the%20principal%20and%20screen_human%20dependencies%20%28agentbox%2Fapi.py%3A206-224%2C%20models%20at%2044-60%29.%20The%20tool-args%20body%20cap%20that%20critic%20checks%20only%20guard%20authenticated%20agent%20args.%20extract_novnc%20runs%20docker%20create%2C%20get_archive%20into%20memory%20and%20extractall%20per%20request%20%28agentbox%2Fsandbox.py%3A774-798%2C%20api.py%3A431-437%29.%20Each%20failed%20POST%20%2Flogin%20appends%20a%20ui_login_failed%20audit%20row%20%28agentbox%2Fweb.py%3A117-123%29.%20deploy%2FCaddyfile%20has%20no%20request_body%20limit.::agentbox%2Fapi.py%23build%20route%20and%20dependency%20ordering%20%28principal%2C%20screen_principal%2C%20put_files%2C%20novnc%29%3B%20agentbox%2Fsandbox.py%23extract_novnc%3B%20agentbox%2Fweb.py%23login%3B%20deploy%2FCaddyfile::Pre-authentication%20work%20imbalance%20%28unbounded%20body%20buffering%20and%20temp-file%20spooling%20before%20auth%2C%20unauthenticated%20Docker-daemon%20work%2C%20unauthenticated%20audit-row%20growth%29` (owner h-preauth)
- `agent-controlled%20audit%20content%20%28tool%20args%2C%20file%20names%2C%20process%20args%29%20and%20timeline%20readers%20%28GET%20%2Faudit%2C%20%2Fui%2Faudit%2C%20agentbox%20audit%29::agentbox%2Faudit.py%23hash%20chain%20%2B%20append-only%20triggers%20%2B%20list%20ordering%2Flimit::agentbox%2Faudit.py%20%2B%20agentbox%2Fweb.py%23audit%20%2B%20agentbox%2Fcli.py%23cmd_audit::ATTACK-CLASSES.md%23Business%20logic` (owner h-audit)
- `agentbox%2Fagent.py%23LLM%20loop%20%2B%20agentbox%2Fmcp_server.py%20tools::agentbox%2Fagent.py%23prompt-injection%20to%20tool%20action%20and%20operator%20terminal%20output%20%28approval%20is%20the%20only%20control%29::agentbox%2Fagent.py%20%2B%20agentbox%2Fmcp_server.py%20%2B%20agentbox%2Fcli.py%23cmd_agent::AI-AND-LLM.md%23Indirect%20injection%20through%20retrieved%20or%20ingested%20content` (owner h-wild)
- `agentbox%2Fapi.py%23GET%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%20%2B%20takeover%2Fhandback%20%2B%20state%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fdesktop.py%23ticket%20redeem%20%2B%20session%20scope%20%2B%20session%20revocation%20on%20human-token%20rotation%20%2B%20lease::agentbox%2Fdesktop.py%20%2B%20agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Session%20fixation%20and%20invalidation` (owner h-session)
- `agentbox%2Fapi.py%23POST%20%2Fapprovals%2F%7Baid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fapprovals%2F%7Baid%7D%2F%7Bdecision%7D%20%2B%20agentbox%2Fcli.py%23cmd_approve::agentbox%2Fservice.py%23decide%20executes%20the%20agent%27s%20original%20args%20after%20human%20approval::agentbox%2Fservice.py%20%2B%20agentbox%2Fapprovals.py::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding` (owner h-policy)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%20source_dir%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes::agentbox%2Fsandbox.py%23create%20source_dir%20overlap%20check%20%28filesystem%20identity%29%20%2B%20NonRecursive%20bind::agentbox%2Fsandbox.py%23create::ATTACK-CLASSES.md%23Feature%20abuse%20and%20data%20leakage` (owner h-files)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Ftakeover%20%2B%20handback%20%2B%20POST%20%2Fsandboxes%2F%7Bsid%7D%2Frestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%28end_desktop%29::agentbox%2Fservice.py%23desktop.gui_lock%20held%20across%20timed%20_x%20GUI%20execs%20%2B%20takeover%2Fhandback%2030%20s%20bound%20%2B%20takeover-pending%20gate::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox_desktop.py%20%2B%20agentbox%2Fdesktop.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-gui-race)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshots%7Crestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes%2F%7Bsid%7D%2Fsnapshot%7Crestore%7Cdelete::agentbox%2Fservice.py%23AgentBox.pause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%20ordering%20%28audit%2C%20end_desktop%2C%20bursts%2C%20captures%2C%20timers%29%20%2B%20api%2Fweb%20guard::agentbox%2Fservice.py%23lifecycle%20methods%20%28refactor%20PR%201%29::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use` (owner h-lifecycle)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bclick%2Ctype%2Ckey%2Cscreenshot%7D::agentbox%2Fgui_bursts.py%23GUI%20burst%20snapshot%20%2B%20fail-closed%20baseline%20%2B%20gui_changes%20%2B%20stray%20kill%20%28N-1%20partial%20mitigation%29::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_run_tool::ATTACK-CLASSES.md%23Chained%20vulnerabilities%20and%20trust%20boundaries` (owner h-gui-burst)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%20%2B%20every%20expire_stale%20caller::agentbox%2Fapi.py%23tool_pool%20%2B%20agentbox%2Fservice.py%23call_tool%20tool_concurrency%20%2B%20agentbox%2Fgui_bursts.py%23burst%20close%20pool::agentbox%2Fservice.py%20%2B%20agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fapi.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-pool)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Btool%7D%20-%3E%20REQUIRE_APPROVAL%20on%20desktop%20templates::agentbox%2Fservice.py%23_call_tool%20approval%20creation%3A%20per-sandbox%20pending%20cap%20%2B%20capture%20PNG%20lifecycle%20%28drop_captures%20on%20decide%2Fexpire%2Fdelete%29::agentbox%2Fservice.py%20%2B%20agentbox%2Fapprovals.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps` (owner h-queue)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2F%7Bwrite_file%2Cdelete_file%2CGUI%7D%20%2B%20snapshot%20routes::agentbox%2Fservice.py%23snapshot%20quota%20%2B%20_snap_locks%20%2B%20GUI%20burst%20snapshots::agentbox%2Fservice.py%20%2B%20agentbox%2Fsandbox.py%23snapshot::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps` (owner h-pool)
- `agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Ftools%2Fexec::agentbox%2Fpolicy.py%23Policy.decide%20read-only-exec%20allowlist::agentbox%2Fpolicy.py%20%2B%20agentbox%2Fsandbox.py%23exec::ATTACK-CLASSES.md%23Injection` (owner h-policy)
- `agentbox%2Fapi.py%23WebSocket%20%2Fsandboxes%2F%7Bsid%7D%2Fdesktop%2Fws%20-%3E%20agentbox%2Fdesktop_ws.py%23relay::agentbox%2Fapi.py%23cookie%20session%20%2B%20same_origin%20%2B%20lease%20on%20WebSocket%20%2B%20agentbox%2Fdesktop_ws.py%23session%20re-check::agentbox%2Fdesktop_ws.py%20%2B%20agentbox%2Fapi.py::CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use` (owner h-session)
- `agentbox%2Fapi.py%23all%20JSON%20and%20browser%20routes::agentbox%2Fapi.py%23principal%20%2B%20human_only%20%2B%20screen_human%20%2B%20desktop_human::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::ATTACK-CLASSES.md%23Access%20control` (owner h-preauth)
- `agentbox%2Fapi.py%23tools%20read_file%2Fwrite_file%2Fdelete_file%2Flist_dir%20%2B%20POST%20files%20%2B%20GET%20outbox::agentbox%2Fsandbox.py%23safe_path%20%2B%20_workspace_path%20%2B%20clean_name%20%2B%20FIFO%20guard::agentbox%2Fsandbox.py::ATTACK-CLASSES.md%23Resource%20and%20file%20handling` (owner h-files)
- `agentbox%2Fcli.py%23cmd_serve%20%2B%20agentbox%2Fapi.py%23create_app%20factory%20%2B%20deploy%2F%2A::agentbox%2Fcli.py%23bind_problem%20%2B%20runtime_problem%20%2B%20sandbox.py%20runtime%20selection::agentbox%2Fcli.py%20%2B%20deploy::CLOUD-AND-DEPLOYMENT.md%23Security-control%20precedence%20drift` (owner h-lifecycle)
- `agentbox%2Fgui_bursts.py%23GuiBursts%20state%20shared%20by%20tool-pool%20threads%20%28call_tool%2C%20decide%29%20and%20human%20threads%20%28expire_stale%20polls%2C%20takeover%2C%20handback%2C%20end_desktop%2C%20lifecycle%20methods%29::agentbox%2Fgui_bursts.py%23GuiBursts%20open%2Fclose%2Fclose_idle%2Fend%2Freset_timers%20ordering%20%2B%20per-sandbox%20burst%20locks%20%2B%20_busy_lock::agentbox%2Fgui_bursts.py%20%2B%20agentbox%2Fservice.py%23_snapshot%2F_run_tool%2Ftakeover%2F_handback_locked%2Fend_desktop%2Fdecide::Race%20and%20check-then-act%20on%20security-control%20state%3A%20burst%20open%20versus%20idle-close%20ordering%2C%20double%20close%20or%20open%2C%20approved-path%20parity%20with%20call_tool%2C%20control-plane%20restart%20dropping%20bursts.%20Mitigation%20is%20only%20partial%20%28the%20accepted%20N-1%20GUI%20bypass%29.` (owner h-gui-race)
- `approval%20card%20impact%20table%20and%20request-time%20screen%20capture%20for%20gated%20exec%2FGUI%20calls::agentbox%2Fpreview.py%23preview%20%2B%20split_segments%20%2B%20expand%2Fwalk%20callbacks%3A%20system-computed%20%27affected%27%20list::agentbox%2Fpreview.py%20%2B%20agentbox%2Fsandbox.py%23preview%20%2B%20agentbox%2Fservice.py%23_preview%2F_capture::AI-AND-LLM.md%23Action-confirmation%20and%20approval%20binding` (owner h-policy)
- `code%20running%20inside%20the%20sandbox%20container%20%28uid%201000%20agent%2C%20uid%201001%20desktop%29::agentbox%2Fsandbox.py%23container%20hardening%20flags%20%2B%20root-run%20docker%20execs%20%28sandbox.py%2C%20sandbox_desktop.py%29::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_desktop.py%20%2B%20images%2Fdesktop::CLOUD-AND-DEPLOYMENT.md%23Host%20or%20control-plane%20capability%20exposure` (owner h-container)
- `container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality` (owner h-queue)
- `container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fgui_state.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fgui_state.py%20%2B%20agentbox%2Fsandbox_desktop.py%23desktop_processes%2Fkill_processes::ATTACK-CLASSES.md%23Business%20logic` (owner h-gui-burst)
- `every%20audit%20append%20%28tool%20args%2C%20results%2C%20errors%2C%20GUI%20records%29::agentbox%2Faudit.py%23mask_text%20%2B%20_mask::agentbox%2Faudit.py::ATTACK-CLASSES.md%23Cryptography%20and%20secrets` (owner h-audit)
- `whole-repo%23basic%20exposures::whole-repo%23obvious%20controls%20%28secrets%2C%20debug%2C%20cookies%2C%20CORS%2C%20redirects%2C%20errors%29::whole-repo::ATTACK-CLASSES.md%23Obvious%20things` (owner h-preauth)
- `whole-repo%23undocumented%2Fedge%20surfaces::whole-repo%23feature%20interactions%20not%20covered%20by%20other%20units::whole-repo::ATTACK-CLASSES.md%23Wildcard` (owner h-wild)

# Your paths, sandbox and result contract

- Agent ID: `h-webui`. Audited source (read-only): `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` (git worktree of main at 9805d91). Read it with Read/Grep/Glob or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-webui/scratch/`. Retained artifacts: `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-webui/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-webui <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target). Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte are importable). This host is Windows, so the wrapper is a Python script and every sandbox call starts with `python`: write `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-webui/scratch/h.py`, then run `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-webui /usr/bin/python3 /scratch/h.py`; inside PowerShell capture output with `| Out-File -Encoding utf8 <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/h-webui/scratch/h.out` or have the script write its own file. Unit tests (cwd must be /target; the tests open repo-relative paths and pytest cannot write there, so pass --capture=sys): `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py h-webui /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"` (93 pass in ~27 s; the 120 s wall clock leaves room only for a subset, so prefer one file or -k).
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/h-webui/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
- Time box: aim to finish within roughly 50 tool calls. Stop each line of investigation as soon as the invariant is settled.
- Your final message must be ONLY the JSON object (no prose, no code fence).

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

## report-schema.json `confirmed` branch (verbatim)

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

## report-schema.json `needs_validation` branch (verbatim)

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
