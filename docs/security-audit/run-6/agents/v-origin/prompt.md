You are candidate verifier `v-origin` in run-6 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at commit `530b29e` (after fix PRs #24 and #25). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
 "title": "Scheme-blind Origin netloc comparison allows cross-scheme CSRF against cookie-authenticated routes",
 "description": "same_origin compares only the netloc of the Origin header with the Host header and accepts missing Origin headers. When agentbox is deployed behind a TLS-terminating reverse proxy (such as Caddy) without HSTS, or on a host with co-located HTTP services, requests originating from an insecure http:// scheme on the same host match the netloc check and can perform state-changing operations (such as session termination via /logout or approval decisions via /ui/approvals) using the browser's session cookie.",
 "claimed_root_cause": "agentbox/api.py:221-223: same_origin() returns True when urlsplit(origin).netloc == headers.get('host') or when Origin is absent. The closure receives only headers and does not verify whether the Origin scheme matches the request scheme (e.g., https). deploy/Caddyfile:1-17 does not set Strict-Transport-Security, so plain-HTTP contexts on the same host are not upgraded to HTTPS by the browser.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 169,
   "scope": "logout",
   "description": "Browser submits a cross-scheme POST /logout (or other state-changing browser route like /ui/approvals/{aid}/approve) from an http:// origin on the same host."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 221,
   "scope": "same_origin",
   "description": "same_origin() extracts the Origin header, parses netloc with urlsplit, and compares it to Host, ignoring the http vs https scheme mismatch."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 60,
   "scope": "set_cookie",
   "description": "Session cookie is configured with SameSite=Strict and Secure, leaving protection against cross-scheme requests dependent on browser-level Schemeful Same-Site enforcement."
  },
  {
   "kind": "sink",
   "file": "deploy/Caddyfile",
   "line": 16,
   "scope": "reverse_proxy",
   "description": "Reverse proxy config lacks Strict-Transport-Security (HSTS), allowing insecure plaintext HTTP access on the same host to persist."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 223,
   "description": "same_origin() evaluates 'not origin or urlsplit(origin).netloc == headers.get(/"host/")'. Scheme is not compared, and absent Origin evaluates to True."
  },
  {
   "file": "agentbox/api.py",
   "line": 235,
   "description": "screen_principal() validates incoming browser requests using same_origin(request.headers), allowing downgraded-scheme requests to authenticate."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 16,
   "description": "Caddy reverse proxy passes requests without injecting Strict-Transport-Security headers, allowing plaintext HTTP on the same host."
  }
 ],
 "blockers": [
  "Live browser verification is required to determine whether real-world Chromium, Firefox, and Safari browsers enforce Schemeful Same-Site policy strictly enough to suppress 'SameSite=Strict; Secure' cookies on cross-scheme (http:// to https://) requests against the same domain or localhost.",
  "Verification on a live Docker deployment with Caddy reverse proxy to confirm whether port 80 HTTP traffic can trigger session termination (/logout) or administrative actions (/ui/approvals) via cross-scheme forgery in the absence of HSTS."
 ],
 "validation_plan": {
  "local": "Start agentbox locally behind an HTTPS proxy using dummy session cookies. Using a browser (Chromium and Firefox), load a page served from http://localhost and trigger a fetch/form POST to https://localhost/logout and https://localhost/ui/approvals/{aid}/approve. Observe whether the browser attaches the agentbox_session cookie and whether the server processes the request with status 303/200.",
  "deployment": "Deploy the official stack via deploy/docker-compose.yml with Caddy. Authenticate an administrative browser session over HTTPS. Navigate to an insecure HTTP site on the same host/domain and attempt a cross-scheme POST to /logout or an approval endpoint. Observe whether the session is terminated or the approval processed without origin rejection."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Browser-origin%20checks%20on%20cookie-authenticated%20routes%3A%20api.py%20same_origin%20%28api.py%3A221-223%29%20used%20by%20screen_principal%20%28api.py%3A235%2C%20every%20%2Fui%20and%20screen%20route%29%2C%20the%20login%2Fticket%20handlers%20%28web.py%3A159%2C169%29%20and%20the%20desktop%20WebSocket%20upgrade%20%28api.py%3A442%29%3B%20a%20missing%20Origin%20header%20is%20accepted::Cross-site%20or%20downgraded-scheme%20browser%20request%20to%20human%20authority%3A%20same_origin%20compares%20only%20urlsplit%28origin%29.netloc%20to%20the%20Host%20header%2C%20with%20no%20scheme%20check%2C%20and%20treats%20an%20absent%20Origin%20as%20same-origin.%20Behind%20a%20TLS%20proxy%20with%20forwarded_allow_ips%3D%27%2A%27%20a%20plain-HTTP%20origin%20on%20the%20same%20host%20passes.%20This%20is%20run-4%20N1%20%28needs_validation%2C%20source%20unchanged%29%20and%20no%20run-5%20unit%20owns%20it.%20The%20WS%20and%20body-cap%20units%20excluded%20CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use%20by%20pointing%20to%20an%20%27existing%20h-session%20unit%27%20that%20is%20not%20in%20this%20ledger.::agentbox%2Fapi.py%23same_origin%2Fscreen_principal%2Fdesktop_ws%20%2B%20agentbox%2Fweb.py%20login%20and%20ticket%20routes%20%2B%20agentbox%2Fdesktop.py%20cookie%20attributes%20%28SameSite%2C%20Secure%2C%20scope%29%20%2B%20deploy%2FCaddyfile%20Host%2FOrigin%20forwarding::Cross-site%20WebSocket%20and%20cross-origin%20request%20forgery%20against%20cookie%20sessions%20%28scheme%20and%20missing-Origin%20gaps%29",
  "surface": "Browser-origin checks on cookie-authenticated routes: api.py same_origin (api.py:221-223) used by screen_principal (api.py:235, every /ui and screen route), the login/ticket handlers (web.py:159,169) and the desktop WebSocket upgrade (api.py:442); a missing Origin header is accepted",
  "boundary": "Cross-site or downgraded-scheme browser request to human authority: same_origin compares only urlsplit(origin).netloc to the Host header, with no scheme check, and treats an absent Origin as same-origin. Behind a TLS proxy with forwarded_allow_ips='*' a plain-HTTP origin on the same host passes. This is run-4 N1 (needs_validation, source unchanged) and no run-5 unit owns it. The WS and body-cap units excluded CLIENT-SIDE.md#Cross-site WebSocket request use by pointing to an 'existing h-session unit' that is not in this ledger.",
  "local_checks": [
   {
    "agent_id": "h-origin",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/web.py"
    ],
    "invariant": "same_origin verifies both scheme and host origin on cookie-authenticated browser endpoints and rejects missing or downgraded-scheme Origin headers",
    "method": "local",
    "result": "Bounded sandboxed TestClient tests verified that same_origin() evaluates True for 'http://testserver' against https endpoints and True when Origin is omitted entirely, successfully allowing POST /logout (303) and POST /ui/approvals/approve (200) cross-scheme. Origin: null and cross-domain origins (evil.com) are rejected with 403.",
    "artifact": "agents/h-origin/artifacts/h.out"
   },
   {
    "agent_id": "h-origin",
    "reviewed_paths": [
     "agentbox/cli.py",
     "agentbox/desktop.py",
     "agentbox/desktop_ws.py",
     "deploy/Caddyfile"
    ],
    "invariant": "Cookie security attributes and proxy headers enforce secure transport and prevent downgraded cross-scheme session abuse",
    "method": "source",
    "result": "DesktopControl sets SameSite=Strict and Secure cookies when TLS is detected, but same_origin lacks access to the request scheme. deploy/Caddyfile configures reverse_proxy without Strict-Transport-Security (HSTS), leaving origin validation vulnerable to cross-scheme requests if browser SameSite policy permits.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
 "title": "same_origin compares only the Origin netloc with Host, so an http:// page on the same host passes the CSRF origin check of a TLS deployment and can clear the session cookie",
 "description": "Every cookie-authenticated UI mutation funnels through api.same_origin (api.py:131-133), which returns True when Origin is absent or when urlsplit(Origin).netloc equals the Host header; the scheme is never compared. A plaintext http://H page is a different web origin from the TLS deployment https://H but carries the same netloc, so the gate accepts it. Independently reproduced (agents/v02/scratch/v02_origin.py, artifact v02_origin.out; api.build with docker.from_env stubbed, ASGI served as https://agentbox.example): Origin http://agentbox.example was accepted for POST /login (303, issuing the Secure SameSite=strict HttpOnly host-only session cookie), POST /ui/approvals/apr_000000000000/approve (200; box.decide entered with the '*' session and rendered approval-not-found), POST /ui/sandboxes (handler reached box.create_sandbox) and POST /logout (303; end_ui_session entered, server session ended - a later GET /ui with the same cookie redirected to /login). Origin https://agentbox.example was accepted identically; Origin https://evil.example, Origin: null, Origin http://agentbox.example@evil.example and Origin http://agentbox.example:8443 against Host agentbox.example were all 403; a POST with no Origin was accepted. Consequence (1): where a browser attaches the Strict cookie to a cross-scheme POST, the human-scoped action runs - approve/deny for a known apr_ id, a sandbox built for an attacker-chosen source_dir, or server-side session end. Consequence (2), browser-independent once the request is sent: POST /logout answers even a cookieless cross-origin request with 303 plus an unconditional cookie-clearing Set-Cookie (web.py:149-150), so a page served at http://H forces a client-side logout while the server-side session survives. No anti-CSRF token, Referer or Sec-Fetch check exists anywhere in agentbox/ (grep finds none) and the only response-wide guard is X-Object-Frame/CSP frame-ancestors (api.py:66), which stops iframe clickjacking but not a top-level auto-submitted form; no Strict-Transport-Security is emitted in agentbox/ or deploy/ (no response carries one; only audit docs mention it), so nothing forces the upgrade of http://H. The decisive unknown stays the browser's schemeful same-site behaviour: the run-3 loopback Chromium 141 run had the Secure cookie withheld (only the forced browser logout occurred), no browser exists in sbx, and Firefox/WebKit are unobserved, so whether consequence (1) is reachable cannot be decided from source or from this sandbox.",
 "claimed_root_cause": "api.py:131-133: same_origin() returns True when urlsplit(origin).netloc == headers.get('host') (and when Origin is absent); the scheme is never compared, and the closure receives only headers (api.py:131) although the app derives the request scheme elsewhere (api.py:136, web.py:114). Nothing in agentbox/ or deploy/ emits Strict-Transport-Security (deploy/Caddyfile:5 is a bare reverse_proxy), so the CSRF gate degrades to whatever same-site semantics the browser applies to http://H versus https://H.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 217,
   "scope": "decide - POST /ui/approvals/{aid}/{decision} (peers: create web.py:174, logout web.py:142)",
   "description": "Cookie-authenticated, form-encodable mutations with no anti-CSRF token; the only origin binding is same_origin. All three decorators verified in the audited tree."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 145,
   "scope": "screen_principal",
   "description": "Resolves the browser cookie via box.desktop.session_scope() at api.py:142 and then calls same_origin(request.headers) at api.py:145; logout calls the same closure directly at web.py:144. The cookie is checked before the origin, so a cross-scheme request without a cookie gets 401 rather than 403."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 133,
   "scope": "same_origin",
   "description": "Netloc-only comparison, missing Origin accepted - reproduced: Origin http://agentbox.example passes against a request served over https://agentbox.example, foreign host, null, the userinfo trick and a port mismatch fail."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 223,
   "scope": "box.decide (also create_sandbox web.py:178, end_ui_session web.py:146)",
   "description": "With the request accepted the human-scoped action runs: decide executes the stored args with actor='human' and the '*' session, create builds a sandbox for a form-supplied source_dir, and logout ends the session when the cookie did arrive."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/api.py",
   "line": 133,
   "description": "urlsplit(origin).netloc == headers.get('host') drops the scheme component, so http://H and https://H are indistinguishable to the gate; reproduced accepting http://agentbox.example for a request served as https://agentbox.example."
  },
  {
   "file": "agentbox/api.py",
   "line": 131,
   "description": "same_origin is typed to receive only headers, so the served scheme is not even in scope; the app already derives it from request.url.scheme at api.py:136 and web.py:114, which is the seam a fix needs."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 60,
   "description": "set_cookie issues the session cookie httponly=True, samesite='strict', max_age=12h, host-only (no Domain); observed Set-Cookie: HttpOnly; Max-Age=43200; Path=/; SameSite=strict; Secure under the https fixture. Whether it travels on a cross-scheme POST is browser policy (schemeful same-site), the decisive unknown."
  },
  {
   "file": "agentbox/web.py",
   "line": 149,
   "description": "logout builds a 303 and calls r.delete_cookie(D.COOKIE) unconditionally at web.py:150, even when end_ui_session returned None because no cookie was attached; reproduced: cookieless cross-scheme POST /logout -> 303 with agentbox_session cleared (Max-Age=0, Path=/) while the server session state is untouched."
  },
  {
   "file": "agentbox/cli.py",
   "line": 102,
   "description": "s.secure_cookie = s.secure_cookie or tls or behind: the Secure attribute is forced exactly for direct-TLS and behind-TLS-proxy deployments, i.e. the deployments where the http/https scheme fork exists."
  },
  {
   "file": "agentbox/api.py",
   "line": 66,
   "description": "The only response-wide middleware adds X-Frame-Options SAMEORIGIN and CSP frame-ancestors 'self'; there is no CSRF token, Referer or Sec-Fetch-Site validation in agentbox/ (grep over *.py finds none) and no TrustedHostMiddleware, so a top-level form POST is unguarded beyond same_origin."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 5,
   "description": "The site block is a bare reverse_proxy agentbox:8765; no header directive, no HSTS anywhere in deploy/, agentbox/ or images/ (tree-wide grep for Strict-Transport-Security matches only audit docs), and the fixture responses carry no strict-transport-security header."
  },
  {
   "file": "agentbox/cli.py",
   "line": 126,
   "description": "Behind-proxy mode trusts X-Forwarded-Proto (proxy_headers=True, forwarded_allow_ips from AGENTBOX_TRUSTED_PROXIES) and deploy/Caddyfile:2-3 says the proxy supplies Host and X-Forwarded-Proto, so request.url.scheme is a usable served scheme for the regression fix."
  },
  {
   "file": "docs/security-audit/run-4/agents/v02/artifacts/v02_origin.out",
   "line": 1,
   "description": "Verifier's own ASGI reproduction (produced in sbx from agents/v02/scratch/v02_origin.py; session ids redacted): cross-scheme Origin accepted on /login, /ui/approvals approve and /ui/sandboxes, 403 for foreign/null/userinfo/port-mismatch, 303 plus clearing Set-Cookie on /logout both with and without a cookie, and no HSTS on any response."
  },
  {
   "file": "docs/security-audit/run-3/agents/parent-live/artifacts/l3/l4.out",
   "line": 4,
   "description": "Real Chromium 141, run-3 parent-live (not re-run here): the cross-scheme POST had same_origin accept the http Origin but the Secure SameSite=Strict cookie was withheld (schemeful same-site), so only delete_cookie forced a client-side logout; the server session was not ended. Firefox and WebKit are unobserved."
  }
 ],
 "blockers": [
  "Browser behaviour (decisive): whether a browser an operator actually uses attaches the Secure SameSite=strict session cookie to a cross-scheme http://H -> https://H form POST. Chromium 141 withheld it (docs/security-audit/run-3/agents/parent-live/artifacts/l3/l4.out:4, reported, not re-run in run-4); Firefox and WebKit current behaviour and the legacy cut-offs are untested, no browser exists in sbx, and the answer cannot be derived from source. Without the cookie only consequence (2), the client-side forced logout, remains.",
  "Network position: whether an attacker can serve plaintext http://H on the deployment host name at all (on-path network attacker, a plaintext listener on port 80, or a DNS/HTTP hijack). No Strict-Transport-Security is emitted anywhere in agentbox/ or deploy/, so nothing forces the upgrade, but whether an on-path attacker and browser preload state are in scope is an owner decision.",
  "Deployment shape: whether both schemes are exposed at the same effective netloc (direct TLS on 443 plus cleartext 80, or behind-proxy mode where Caddy owns the http->https redirect). In a loopback http-only deployment the scheme fork does not exist, and if HSTS or a preload entry is present the http page never loads."
 ],
 "validation_plan": {
  "local": "Repo-side half is done and reproduced by the verifier: agents/v02/scratch/v02_origin.py builds the real app (api.build with docker.from_env stubbed) and drives it over ASGI as https://agentbox.example - cross-scheme Origin accepted on /login, /ui/approvals approve, /ui/sandboxes and /logout, foreign/null/userinfo/port-mismatch 403, /logout always emitting the clearing Set-Cookie; artifact v02_origin.out. Remaining decisive step is a loopback browser lab run outside sbx (parent-live): map H to 127.0.0.1, start agentbox with --tls-cert/--tls-key (self-signed, lab-trusted) on https://H:443 with a dummy human token, and a plaintext http://H:80 page that auto-submits a top-level form to https://H/logout and to https://H/ui/sandboxes with source_dir set; log in on https://H, open http://H, and record (a) whether agentbox_session is sent on the POST, (b) whether the response is 303/200 (accepted) rather than 403, (c) for /logout whether the server session ends (GET /ui then 303 /login) and whether a ui_logout row appears in /audit, (d) for /ui/sandboxes whether a new sandbox exists. Repeat on current Firefox and WebKit and on any engine or policy that disables schemeful same-site. Regression: change same_origin to compare BOTH the scheme and the netloc, taking the served scheme from request.url.scheme (already used at api.py:136 and web.py:114, and X-Forwarded-Proto-aware under cli.py:126) instead of the headers-only signature at api.py:131; then both cross-scheme POSTs must return 403 and the clearing Set-Cookie must disappear, while Origin https://H with Host H still passes and the existing tests/test_unit.py suite stays green.",
  "deployment": "Owner confirms, without probing live endpoints: (1) whether the operator-facing host name sends Strict-Transport-Security or is on the browser preload list; (2) whether a plaintext http:// listener for that name is reachable (direct TLS on 443 plus cleartext 80, or a TLS proxy fronting the plaintext port where the http->https redirect is the only barrier) and whether an on-path attacker is in scope; (3) which browser engines and versions operators use; (4) whether any operator browser or policy lacks schemeful same-site. If HSTS is present and every browser is schemeful, only the browser-independent forced-logout residual from the unconditional delete_cookie at web.py:149-150 remains, and the same scheme comparison removes it."
 }
}
```

# Parent-live evidence

- `agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/same_origin_live.out` (at `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/same_origin_live.out`)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-6)
Source ref: `530b29e` (`main`, after fix PRs #24 and #25). Profile `standard`, focused follow-up, budget 30 (all subagents `flash`). This file is the run-4/run-5 architecture plus a parent-written delta in section 0 covering every file changed since `346df29` (PRs #24 and #25: 13 non-test files in `agentbox/` and `deploy/`) and the run-5 delta from `9805d91` to `346df29`. No reconnaissance agent was spent in run-6: the parent inspected the full diff `346df29..530b29e`. **Line numbers in section 0.1 are exact at `530b29e`; section 0.2 has `346df29` numbers; sections 1-8 are `9805d91` numbers.**
## 0.1 Run-6 delta (changes in PRs #24 and #25, exact line numbers at `530b29e`)
- **Pre-read credential gate and anonymous body cap (`api.py`, `config.py`, `cli.py`, `deploy/`, PR #25 — run-5 N1 fix).**
  - `api.py:52-54`: `_UPLOAD_PATH = re.compile(r"/sandboxes/[^/]+/files")`, `_ANON_BODY_PATHS = {"/login"}`, `_ANON_BODY_MAX = 64 * 1024`.
  - `api.py:57-128` `_BodyLimit`: takes `authenticated` callback (`api.py:63-65`, wired at `api.py:185-201`). Rejects invalid/over-20-digit/over-cap `Content-Length` with 413 (`api.py:84-86`). Computes `has_body = (length is not None and int(length) > 0) or b"transfer-encoding" in headers` (`api.py:87`). If `has_body` and `scope["path"] in _ANON_BODY_PATHS`, lowers `cap = min(cap, _ANON_BODY_MAX)` (64 KiB) and rechecks `Content-Length` (`api.py:88-91`). Otherwise, if `has_body and self.authenticated and not await run_in_threadpool(self.authenticated, headers)`, rejects with 401 before reading any body (`api.py:92-95`). Streamed bodies remain capped at `cap` in `limited_receive` (`api.py:98-115`).
  - `api.py:185-199` `authenticated(headers)`: checks `Authorization: Bearer <token>` via `secrets.compare_digest` against `human_token` or `box.sandboxes.sandbox_for_token(token) is not None`, else parses `Cookie` with `http.cookies.SimpleCookie` and checks `box.desktop.session_scope(got.value)` for `D.COOKIE`. Route-level authorization (`human_only`, sandbox ownership, `same_origin`) still runs in route dependencies.
  - `config.py:68`: `max_connections` (`AGENTBOX_MAX_CONNECTIONS`, default 256; 0 disables); `cli.py:126-127` passes `limit_concurrency=s.max_connections` to `uvicorn.run`.
  - `deploy/Caddyfile:8-15`: `@upload path_regexp ^/sandboxes/[^/]+/files$` gets `AGENTBOX_PROXY_MAX_BODY` (256MB), `@other` gets `AGENTBOX_PROXY_MAX_JSON` (8MiB). `deploy/docker-compose.yml:20`: `mem_limit: ${AGENTBOX_MEM_LIMIT:-2g}`.
- **Desktop lock split and WebSocket threadpool offload (`desktop.py`, `desktop_ws.py`, `api.py`, PR #24 — run-5 F4 fix).**
  - `desktop.py:93-94`: `DesktopControl` splits `self._lock` (in-memory `_leases`, `_conns`, `_gui_locks`) from `self._db_lock` (SQLite `self._db`). Documented lock order when acquiring both: `_db_lock -> _lock`.
  - Ticket and session methods (`issue_ticket:116`, `redeem:124`, `start_session:139`, `end_session:147`, `session_scope:153`) take only `_db_lock`.
  - Lease and connection methods that touch both (`take:194`, `release:215`, `leftover_leases:235`, `forget_lease:246`, `close_all:299`) take `_db_lock` then `_lock`. In-memory-only methods (`lease`, `touch`, `is_stale`, `gui_lock`, `may_connect`, `add_conn`, `drop_conn`, `conns`, `end_session_conns`) take only `_lock`.
  - `api.py:441`: `desktop_ws` runs `await run_in_threadpool(box.desktop.session, cookie, sid)` before `same_origin(ws.headers)` (`api.py:442`, `same_origin` at `api.py:221-223`).
  - `desktop_ws.py:21-22`: `relay` runs `vnc_command` and `log_human("desktop_connect")` via `run_in_threadpool`. Periodic session recheck (`desktop_ws.py:76`) also uses `run_in_threadpool`. `finally` block (`desktop_ws.py:93-113`) runs `log_best_effort("desktop_disconnect")` on default executor inside `await asyncio.shield(logged)` before `box.desktop.drop_conn(conn)`.
- **GUI burst under takeover lease (`service.py`, PR #24 — run-5 F2 fix).**
  - `service.py:265-284` `_snapshot`: for `tool in GUI_INPUT`, after `sandboxes.snapshot`, acquires `with self._gui_locked(sid, "GUI 구간 열기"):`, runs `self._check_control(sid)`; only if no `HumanControl` is raised does it call `bursts.mark_snapshot(sid)` and `bursts.open(sid, snap["id"])`. Always appends the `snapshot` audit record (`service.py:280-281`), then if `human` was caught calls `self.bursts.reset_timers(sid)` and raises `human` (`service.py:282-284`).
  - `service.py:396-397`: `call_tool` catches `HumanControl` from `_snapshot` and delegates to `_human_blocked` (`service.py:411-419`, returns 423 and logs `tool_blocked`).
  - `service.py:498-514` `decide`: before `_snapshot`, if `tool in GUI_INPUT` and active lease or `_takeover_pending(sid)`, finishes approval as `FAILED` without taking a snapshot or opening a burst; also catches `HumanControl` from `_snapshot` (`service.py:511-514`).
- **Tool argument length cap, policy re-lex skip, and preview caps (`service.py`, `policy.py`, `preview.py`, `sandbox.py`, PR #24 — run-5 F1/F5/F6 fixes).**
  - `service.py:49`: `TOOL_ARG_MAX = 16 * 1024`. In `_call_tool` (`service.py:323-329`), before `tool_request` audit and `policy.decide`, rejects any arg `k != "content"` whose `len(v if isinstance(v, str) else json.dumps(v, default=str)) > TOOL_ARG_MAX` with 413 (`argument_too_long`).
  - `service.py:357-362`: in the `REQUIRE_APPROVAL` branch, applies `preview = bound_payload(preview)` before storing the pending approval row, and re-checks `if actor == "agent" and self.disk_low():` raising 507 before `_capture` and `approvals.create`.
  - `policy.py:27, 40-49, 73`: `_LEX_PUNCT = set(";&|()<>")`; `_relex_changes(t)` returns `False` for tokens consisting solely of `_LEX_PUNCT` or tokens with no whitespace, `_LEX_PUNCT`, quotes, or backslashes (e.g. `'x$'`), avoiding redundant recursive `_words(t, depth + 1)` calls.
  - `preview.py:70-71`: `PREVIEW_CALLS_MAX = 40`, `NOTES_MAX = 50`. `preview_command` (`preview.py:74-160`) deduplicates `rm` operands via `dict.fromkeys(operands)` (`:105`), caps total `expand`/`walk` calls at 40 via `budget()`, appends a Korean note when `skipped > 0` (`:154-156`), and truncates `notes` to `NOTES_MAX` plus a summary note (`:157-159`).
  - `sandbox.py:39, 104-106, 578-594`: `_PREVIEW_TIMEOUT = 10`; `_expand` and `_walk` wrap their container `sh -c` in `_timed(_PREVIEW_TIMEOUT, ...)` and call `_preview_ok(res)` (raises `SandboxError` on exit code 124 or 137).
- **Retention prune post-COMMIT archive safety (`retention.py`, PR #24 — run-5 F3 fix).**
  - `retention.py:104-108`: unlinks partial archive if `_write_archive` raises before the transaction.
  - `retention.py:131-145`: on exception inside the transaction block, rolls back only `if conn.in_transaction`; in the outer handler, queries `SELECT 1 FROM audit_anchor WHERE archive = ? AND archive_sha256 = ?` (defaulting `committed = True` on `sqlite3.Error`) and only unlinks the archive if `not committed`.
## 0.2 Run-5 delta (changes in PRs #16-#23, `346df29` line numbers)
- **Body cap (F1 fix, PR #16)**, **Audit cap (F3 fix, PR #16)**, **GUI gate (F2) and quota recheck (F7, PR #17)**, **Lifecycle lock (F6), F4 NUL-separated preview `_expand`/`_walk`, F5 single-flight `extract_novnc`, F8 login failure rate limit (PR #18)**, **Control-character filter `display.escape_controls` Cc/Cf/Zl/Zp (N5, PR #19)**, **Disk guard `disk_low` and finished-approval compaction (N2 stage 1, PR #20)**, **Host CLI `agentbox prune` and `audit_anchor` (N2 stage 2, PR #21)**, **Window owner via XRes `XResQueryClientIds` (N4, PR #22)**.
- **LLM-provider data path (PR #23)**: documented owner-accepted limitation; out of scope for hunting.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py`): full JSON API (`api.py` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default, and the bare `create_app` factory (`api.py`) that skips the serve-time gates. Container flags (`sandbox.py`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Windows 11 with Docker Desktop WSL2 Linux engine 29.9.2, runtimes `runc`/`io.containerd.runc.v2`, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1`, `agentbox-audit-sbx:1`. Agent-run code goes through `tools/sbx.py` (no network, read-only target at `/target`, writable `/scratch`, uid 65534, 512 MiB, 64 pids, 120 s). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`, `test_m5_unit.py`, `test_retention.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (16 KiB arg cap `TOOL_ARG_MAX` → audit with capped args `_logged_args` → `policy.decide` → quota → approval with bounded preview & `disk_low` recheck or `_snapshot` → `_run_tool`) on the 32-thread `tool_pool`. Pending approvals capped at 20.
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide`: atomic claim, GUI lease check, snapshot, run stored args. Preview (`preview.py` `preview_command` with `_expand`/`_walk` callbacks, 40-call budget, 10 s timeout per call) and capture run before the approval exists.
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per san

# Relevant companion blocks (verbatim)

<!-- CLIENT-SIDE.md#Cross-site WebSocket request use -->
**Cross-site WebSocket request use**
A WebSocket upgrade accepts ambient cookies from an untrusted origin without an `Origin` check or channel-specific token, allowing the victim's session to read or mutate data. Confirm both the upgrade behavior and a security-relevant message handler.

<!-- WEB-PROTOCOL-AND-AUTH.md#Request framing and desynchronization -->
**Request framing and desynchronization**
Front end and back end disagree on request length or header normalization. Review multiple `Content-Length` values, `Transfer-Encoding`, HTTP/2 or HTTP/3 downgrade, header-name normalization, forbidden connection headers, and CR/LF conversion. Confirm which bytes one component assigns to a request and which bytes its peer assigns to the next request.

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

- Agent ID `v-origin`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/v-origin/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-origin <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-origin /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-origin/artifacts/<file>`.
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
