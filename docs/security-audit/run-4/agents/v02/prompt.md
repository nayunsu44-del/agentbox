You are candidate verifier `v02` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
 "title": "same_origin compares only the Origin netloc with Host, so an http:// page on the same host passes the CSRF origin check of a TLS deployment and can clear the session cookie",
 "description": "Every cookie-authenticated mutation in agentbox funnels through one origin check, api.same_origin (api.py:131-133), which compares urlsplit(Origin).netloc with the Host header and never the scheme, and also accepts a missing Origin. A page served as plaintext http://H is a different web origin from https://H but has the same netloc, so the check passes. Locally the app accepted Origin http://agentbox.example with Host agentbox.example and then ran the handler for POST /ui/approvals/{aid}/approve (with a real session cookie), POST /ui/sandboxes and POST /logout, while a foreign host, Origin: null and a userinfo-tricked Origin were rejected. Two consequences: with a cookie attached (browsers without schemeful same-site) the cross-scheme POST executes the human action - approve/deny, sandbox creation with an attacker-chosen source_dir, or session end; and even where the SameSite=Strict cookie is not attached, POST /logout still answers a cross-scheme request with a 303 that unconditionally carries a cookie-clearing Set-Cookie for the https origin, so an on-path attacker who can answer http://H can force the operator's browser to drop its session cookie without ending the server-side session.",
 "claimed_root_cause": "api.py:131-133: same_origin() returns True when urlsplit(origin).netloc == headers.get('host') (and when Origin is absent); the scheme is never compared and nothing in agentbox/ or deploy/ emits Strict-Transport-Security, so the CSRF gate degrades to whatever same-site semantics the browser applies to http://H versus https://H.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 217,
   "scope": "decide - POST /ui/approvals/{aid}/{decision} (peers: create web.py:174, logout web.py:142)",
   "description": "Cookie-authenticated, form-encodable mutations with no anti-CSRF token; the only origin binding is same_origin."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 145,
   "scope": "screen_principal",
   "description": "Resolves the browser cookie via box.desktop.session_scope() and then calls same_origin(request.headers); logout calls the same closure directly at web.py:144."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 133,
   "scope": "same_origin",
   "description": "Netloc-only comparison, no scheme check, missing Origin accepted - verified locally: Origin http://agentbox.example with Host agentbox.example passes, http://evil.example, null and the userinfo trick fail."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 223,
   "scope": "box.decide (also web.py:178 create_sandbox, web.py:146 end_ui_session)",
   "description": "With the request accepted the human-scoped action runs: decide executes the agent's stored args with actor='human', create builds a sandbox for an attacker-chosen source_dir, and logout ends the session when the cookie did arrive."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 133,
   "description": "urlsplit(origin).netloc == headers.get('host'): the scheme component is dropped, so http://H and https://H are indistinguishable to the gate."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 60,
   "description": "The session cookie is SameSite=strict and Secure in TLS deployments; whether it travels on a cross-scheme POST is browser policy (schemeful same-site), which is the decisive unknown."
  },
  {
   "file": "agentbox/web.py",
   "line": 149,
   "description": "logout builds a 303 and calls delete_cookie unconditionally (web.py:149-150), even when end_ui_session returned None because no cookie was attached."
  },
  {
   "file": "docs/security-audit/run-4/agents/h-webui/artifacts/h.out",
   "line": 1,
   "description": "Origin matrix and cookie-bearing cases: cross-scheme Origin accepted on /login, /ui/approvals approve, /ui/sandboxes and /logout; cross-scheme /logout returns 303 with an empty Set-Cookie even with no cookie, and ends the server session when a valid cookie is supplied."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 4,
   "description": "Bare reverse_proxy block: no Strict-Transport-Security, and grep over agentbox/ and deploy/ finds none, so the browser is never forced to upgrade http://H."
  },
  {
   "file": "agentbox/cli.py",
   "line": 102,
   "description": "secure_cookie is forced for direct TLS and for --behind-tls-proxy, i.e. exactly the deployments where the http/https scheme fork exists."
  }
 ],
 "blockers": [
  "Decisive browser fact: whether a browser in use lacks schemeful same-site, so that the SameSite=Strict Secure cookie is attached to a cross-scheme http://H -> https://H POST. Run-3 parent-live Chromium 141 did not attach it; Firefox and WebKit are unobserved and older engines are unverified, and no browser runs in sbx, so the scripted check cannot decide it.",
  "Deployment fact: whether an attacker can serve plaintext http://H on the same host name (an on-path network attacker or a plaintext listener on that name). No HSTS is emitted anywhere in agentbox/ or deploy/, so nothing forces the upgrade; whether an on-path attacker is in scope is an owner decision.",
  "Deployment fact: whether the deployment exposes both schemes at the same effective netloc (direct TLS on 443 plus plaintext 80, or behind-proxy mode where the proxy owns the http-to-https redirect). In a loopback http-only deployment the scheme fork does not exist."
 ],
 "validation_plan": {
  "local": "Repo-side half already executed (agents/h-webui/artifacts/h.out): api.build with the Docker client stubbed, driven over ASGI - cross-scheme Origin accepted for /login, /ui/approvals approve (200, handler ran) and /ui/sandboxes (reached create_sandbox), foreign host 403, and cross-scheme /logout returns 303 with the cookie-clearing Set-Cookie whether or not a cookie is sent. Next, a loopback-only browser lab: one https listener with a dummy human token plus a plaintext page on the same host name that auto-submits to /logout and /ui/sandboxes; confirm in a schemeful browser that the cookie is withheld (only the forced logout happens) and in a non-schemeful browser or version that it is attached and the mutation lands (a ui_logout row in /audit, a new sandbox). Regression: after comparing scheme and netloc, both cross-scheme requests must return 403 and the forced logout must disappear.",
  "deployment": "Owner confirms whether the deployment hostname sends HSTS or is on the preload list, and which browser engines and versions operators use; if HSTS is present or every browser is schemeful, only the forced-logout residual remains and the same scheme check removes it. No probing of live endpoints."
 },
 "x_proposed_by": "h-webui"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "agentbox%2Fweb.py%23%2Fui%2F%2A%20%2B%20%2Flogin%20%2B%20%2Flogout::agentbox%2Fapi.py%23same_origin%20%2B%20SameSite%3DStrict%20HttpOnly%20cookie::agentbox%2Fapi.py%20%2B%20agentbox%2Fweb.py::WEB-PROTOCOL-AND-AUTH.md%23Ordinary%20CSRF",
  "surface": "agentbox/web.py#/ui/* + /login + /logout",
  "boundary": "agentbox/api.py#same_origin + SameSite=Strict HttpOnly cookie",
  "local_checks": [
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "Every cookie-authenticated state-changing route is bound to the same single origin gate.",
    "method": "source",
    "result": "Inventory: the cookie dependency screen_principal calls same_origin unconditionally at api.py:145; the routes behind it are POST /ui/sandboxes (web.py:174), POST /ui/approvals/{aid}/{decision} (web.py:217), POST /ui/sandboxes/{sid}/snapshots (web.py:245), /restore/{snap_id} (web.py:252), /delete (web.py:259), POST /sandboxes/{sid}/files (api.py:276), POST /sandboxes/{sid}/desktop/takeover (api.py:332) and /handback (api.py:338); POST /login (web.py:132) and POST /logout (web.py:144) call same_origin explicitly, and the desktop WebSocket checks it at api.py:347. No cookie-authenticated mutation lacks the gate.",
    "artifact": null
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/api.py",
     "agentbox/cli.py"
    ],
    "invariant": "The ambient credential is scoped and transported so that only a same-site browser context can present it.",
    "method": "source",
    "result": "desktop.py:58-60 sets the session cookie httponly=True, samesite='strict', max_age=12h, with no Domain attribute (host-only) and the default Path=/; secure is settings.secure_cookie or request.url.scheme == 'https' (api.py:135-136, web.py:113-114) and cli.py:102 forces secure_cookie for direct TLS and for --behind-tls-proxy. Sessions and tickets carry the token_gen fingerprint and are dropped when the human token rotates (desktop.py:99-105).",
    "artifact": null
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "The origin gate must reject an Origin whose scheme differs from the served origin, and must not be bypassable with a crafted Origin value.",
    "method": "local",
    "result": "ASGI fixtures in sbx: POST /login with Origin http://agentbox.example + Host agentbox.example -> 200 (accepted; scheme never compared), Origin https://agentbox.example -> 200, Origin http://evil.example -> 403, Origin: null -> 403, Origin http://agentbox.example@evil.example -> 403, no Origin -> 200. With a real session cookie from desktop.new_session('*'): POST /ui/approvals/apr_000000000000/approve with the cross-scheme Origin -> 200 (handler ran; approval-not-found rendered) and with Origin https://evil.example -> 403; POST /ui/sandboxes with the cross-scheme Origin reached create_sandbox (the Docker stub raised); POST /logout with the cross-scheme Origin -> 303 carrying Set-Cookie agentbox_session empty with Max-Age=0 and Path=/, both with a valid cookie (server session then ended: GET /ui -> 303 /login) and with no cookie at all.",
    "artifact": "agents/h-webui/artifacts/h.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-3 wording)

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
 "title": "same_origin ignores the scheme, so a plaintext http:// page on the same host passes the CSRF origin check of a TLS deployment",
 "description": "Every cookie-authenticated UI mutation ultimately relies on same_origin() (api.py:108-110), which compares only urlsplit(Origin).netloc with the Host header and never the scheme. Verified in-sandbox: http://H, http://H:8765, and http://agentbox.example.com are all accepted against the matching Host, while sibling same-site, wrong port, and null are rejected. In a TLS deployment a page served as plaintext http://H (forgeable by an active network attacker; no Strict-Transport-Security is set anywhere in agentbox/, deploy/ or images/, and Caddy's reverse_proxy adds none) has a different web origin from https://H but passes this check. On a browser WITHOUT schemeful same-site, http://H and https://H count as same-site, so a SameSite=Strict Secure cookie (desktop.py:53) would be attached to the auto-submitted cross-scheme POST and agentbox would accept it. Id-free actions: POST /logout (ends the server session and hands desktop takeover back to the agent) and POST /ui/sandboxes (creates a sandbox with an attacker-supplied source_dir). Approve/deny additionally needs the 48-bit apr_ approval id (approvals.py:51, token_hex(6)), so a blind attacker is limited to the id-free actions. DECISIVE CAVEAT from parent-live evidence (agents/parent-live/artifacts/l3/l4.out, script l4.cjs): on Chromium 141 the cross-scheme POST had same_origin accept its Origin but the Secure SameSite=Strict cookie was NOT attached (schemeful same-site), so the session-ending and create attacks fail there; the only effect was the unconditional r.delete_cookie on the logout response clearing the browser cookie client-side (forced browser logout) WITHOUT ending the server session. Firefox and WebKit were not tested. The finding therefore stands only on browsers without schemeful same-site; the exploitable browser population and the HSTS/active-network-attacker deployment facts remain open.",
 "claimed_root_cause": "api.py:108-110: same_origin() accepts when urlsplit(origin).netloc == headers['host'] with no scheme comparison, so the cross-origin defence degrades to the browser treating http/https of one host as cross-site; nothing in source emits Strict-Transport-Security (deploy/Caddyfile, agentbox/ and images/ set none), so an active network attacker can serve http://H.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 203,
   "scope": "decide (POST /ui/approvals/{aid}/{decision}); also create web.py:160, logout web.py:128",
   "description": "Cookie-authenticated, form-encodable POST routes reachable by a cross-origin auto-submitted form; verified these are the state-changing UI mutations gated only by the cookie session plus same_origin."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 119,
   "scope": "screen_principal",
   "description": "Resolves the cookie session via box.desktop.session_scope(cookie) (api.py:119), then same_origin(request.headers) at api.py:122 is the only origin binding for the cookie principal."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 110,
   "scope": "same_origin",
   "description": "Returns True when urlsplit(origin).netloc equals Host; independently confirmed http://H matches Host H and missing Origin is allowed, so scheme is never compared."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 209,
   "scope": "decide",
   "description": "box.decide(aid, approve, actor='human', session=p.session) executes with the victim's session; peer id-free sinks are create_sandbox at web.py:164 and end_ui_session at web.py:132."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 110,
   "description": "Netloc-only comparison with no scheme check. Reproduced in-sandbox (agents/v01/artifacts/v01_same_origin.out): accepts http://H vs Host H, http://H:8765 vs H:8765, http://agentbox.example.com vs that host, and missing Origin; rejects sibling same-site, wrong port, and null."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 53,
   "description": "set_cookie issues the session cookie HttpOnly, samesite='strict', secure=secure; under non-schemeful same-site http://H and https://H are same-site, so the Strict cookie is not separated by scheme."
  },
  {
   "file": "agentbox/cli.py",
   "line": 106,
   "description": "s.secure_cookie = s.secure_cookie or tls or behind: the Secure attribute is set for direct-TLS and behind-TLS-proxy deployments, which is the deployment class this finding targets."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 4,
   "description": "reverse_proxy site block emits no Strict-Transport-Security; grep over agentbox/, deploy/ and images/ found no HSTS anywhere, so the browser is not forced to upgrade http://H to https."
  },
  {
   "file": "agentbox/web.py",
   "line": 130,
   "description": "logout's only guard is the scheme-blind same_origin (web.py:130); end_ui_session (web.py:132) ends the server session and hands takeover leases back to the agent when the cookie is present."
  },
  {
   "file": "docs/security-audit/run-3/agents/parent-live/artifacts/l3/l4.out",
   "line": 4,
   "description": "Parent-live (not a verifier reproduction) real Chromium 141, script l4.cjs: cross-scheme POST http://127.0.0.1 -> https://127.0.0.1/logout had same_origin accept the http Origin (netloc==Host) but the Secure SameSite=Strict cookie was NOT attached (schemeful same-site); server session not ended, only the delete_cookie forced a client-side logout. Resolves the Chromium 141 case as non-exploitable; Firefox/WebKit untested."
  }
 ],
 "blockers": [
  "Browser behaviour (decisive): whether any operator browser lacks schemeful same-site and so attaches a SameSite=Strict Secure cookie to a cross-scheme form POST from http://H to https://H. Only Chromium 141 was tested (cookie NOT attached, l4.out); Firefox and WebKit current behaviour and the legacy-version cut-offs are untested and cannot be determined from source.",
  "Deployment: whether the production host sends HSTS or is preloaded (none in source), and whether an active on-path network attacker who can serve plaintext http://H is in scope."
 ],
 "validation_plan": {
  "local": "Isolated loopback browser lab: map H to 127.0.0.1, run a dummy agentbox with --tls-cert (self-signed, lab-trusted) on 443 and a plaintext http://H listener on 80 auto-submitting forms to https://H/logout and /ui/sandboxes. The parent already ran this on Chromium 141 and the Secure SameSite=Strict cookie was not attached (agents/parent-live/artifacts/l3/l4.out). Remaining local steps: repeat with current Firefox and WebKit, and with any browser/version or policy that disables schemeful same-site: log in to https://H, open http://H, and check whether agentbox_session is sent and the POST is accepted (303) rather than 403, and whether the server session is actually ended. Regression check on the fix: same_origin({'origin':'http://h','host':'h'}) must return False once the full scheme+netloc origin is compared.",
  "deployment": "Owner confirms whether the production hostname sends HSTS (or is on the preload list) and which browser engines and versions operators actually use; if all are schemeful-same-site browsers and/or HSTS is present, the finding is not reachable. No live probing of deployed endpoints."
 }
}
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

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

# Relevant companion blocks (verbatim)

<!-- WEB-PROTOCOL-AND-AUTH.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Framing and cache findings require two interpretations of the same request, response, or key. Name both components and the exact normalized value on each side.
- For every credential, find the signature or secret verification and every binding required for its role: issuer, audience, origin, RP, client, session, principal, resource, assurance, expiry, and one-time state.
- Host, Forwarded, X-Forwarded-*, Origin, Referer, redirect targets, callback state, and request-derived URLs are trust decisions. Trace each to the affected identity or response.
- A missing header, cookie attribute, MFA prompt, or rate limit is not a finding alone. Require an accepted invalid request, cross-principal impact, assurance downgrade, or credential disclosure.
- Classify `confirmed` only from complete source evidence and bounded local request/token tests. Use `needs_validation` when proxy, IdP, browser, certificate, secret, or deployed configuration is required but not visible.
```

<!-- WEB-PROTOCOL-AND-AUTH.md#Ordinary CSRF -->
**Ordinary CSRF**
A browser sends ambient credentials to a state-changing endpoint that accepts a cross-site request without an effective anti-CSRF token, same-site request binding, or strict Origin/Referer validation. Inventory every cookie-authenticated mutation, including form, JSON-like, multipart, method-override, and legacy routes. SameSite is effective only for the cookie and browser contexts actually used; login CSRF and cross-site subresource requests can have different requirements.

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

# Verifier instructions (verbatim)

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

# Artifact promotion procedure (verbatim)

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

# Execution boundary and paths

- Agent ID `v02`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v02/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v02 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v02 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish.
- Your final message must be ONLY the JSON object `{"decision": ..., "record": {...}}` plus that optional field. No prose, no code fence.

# report-schema.json branches (verbatim)

## `confirmed`

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

## `needs_validation`

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

## `rejected`

```json
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
