You are Phase 5 final-record verifier `p5-v05` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.
- A fix for this record was committed after Phase 3 as `3587c9c` (`git -C /home/user/agentbox show 3587c9c`). Use it only to judge check 6 (does the proposed remediation enforce the invariant). It is never evidence that the record is wrong for the audited source.

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
 "fingerprint": "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions",
 "title": "Rotating the human token does not revoke existing full-admin browser sessions (no revoke-all; sessions persist 12 h across restart)",
 "description": "Web UI cookie sessions (scope '*') are rows in ui_sessions: sha256(cookie), a public hs_ id, created, expires = creation + 12 h, scope. Nothing ties a row to the human token that authorised it. When the owner rotates the shared admin secret (a new AGENTBOX_HUMAN_TOKEN, or deleting/regenerating data/human_token) and restarts, the old token stops working (Bearer 401; /login issues no cookie), but every '*' cookie minted under it keeps working until its fixed 12 h expiry, because DesktopControl.__init__ deletes only expired rows and session_scope checks only the cookie hash and expiry. There is no bulk revocation: no route, method or CLI command does it; logout and login/ticket redemption act only on the presented/new cookie and never end a replaced one; no API accepts the hs_ id that the audit log records. A holder of an earlier-minted agentbox_session cookie therefore keeps the full browser-UI authority after the owner has withdrawn the only credential: the same Depends(browser_human) gate admits approve/deny of agent actions, sandbox delete/restore/snapshot, file upload, outbox download, sandbox creation with an arbitrary host source_dir (only data-folder overlap is refused) and desktop takeover, and the desktop WebSocket gate accepts the cookie too. README.md documents the 12 h life and persistence across restart as a known limit but is silent on rotation and revocation.",
 "root_cause": "Session validity is independent of the credential that created it: the ui_sessions schema (desktop.py:35-37) has no token-generation or lineage column, DesktopControl.__init__ (desktop.py:91-93) prunes only expired rows, session_scope (desktop.py:133-145) checks hash and expiry only, and no code path deletes more than one session at a time (end_session, desktop.py:127-131), so only the session's own logout or its 12 h expiry ends it. The human token is read once at start-up (config.py:88, api.py:66) and used only for comparisons, so rotating it changes nothing stored in agentbox.db.",
 "intended_behavior": "A browser session is valid only while the human credential that authorised it is still current: rotating the human token (new AGENTBOX_HUMAN_TOKEN or regenerated data/human_token) invalidates every browser session and unredeemed ticket minted under the old one, while a restart with an unchanged token keeps logins (tests/test_m4_acceptance.py::test_login_survives_restart); the owner has an explicit revoke-all that needs no rotation; and a login that replaces a cookie ends the replaced server-side session. The README documents none of the rotation/revocation guarantees, so this is the security expectation for a shared-admin-secret model, not a documented promise.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/web.py",
   "line": 117,
   "scope": "login",
   "description": "POST /login (unauthenticated network client holding the then-current token) compares the form token with human_token (compare_digest, web.py:120) and calls start_session (web.py:95-101), which calls DesktopControl.new_session() with the default scope '*'. GET /login?ticket= (web.py:109-113) and the per-sandbox ticket route (api.py:298-308) mint sessions the same way."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 116,
   "scope": "DesktopControl.new_session",
   "description": "Inserts (sha256(cookie), public hs_ id, created, expires = now + 12 h, scope) at lines 123-124; nothing records which human token authorised the session (schema lines 35-37)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/config.py",
   "line": 88,
   "scope": "Settings.human_token",
   "description": "Rotation = new AGENTBOX_HUMAN_TOKEN or a deleted/regenerated data/human_token, read once at start-up (api.py:66) and used only for compare_digest checks (api.py:96, web.py:120) and log masking; nothing in agentbox.db changes."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 93,
   "scope": "DesktopControl.__init__",
   "description": "On restart only rows with expires < now are deleted (lines 92-93); the table is dropped only for the legacy no-scope schema (lines 86-89)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 115,
   "scope": "screen_principal",
   "description": "With no Authorization header the cookie goes to box.desktop.session_scope (line 119); same_origin (line 122) passes when Origin is absent; returns Principal('human', session, scope) (line 124)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/desktop.py",
   "line": 133,
   "scope": "DesktopControl.session_scope",
   "description": "The only verification: SELECT by sha256(cookie) and reject if expires < now (lines 138-145). No token generation, lineage or revocation check; a cookie minted under the rotated-out token returns (public id, '*')."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 204,
   "scope": "decide (/ui/approvals/{aid}/{decision})",
   "description": "p=Depends(browser_human) = api.screen_human (api.py:126-132) admits the scope-'*' stale session; box.decide(...) runs with the stale session id (web.py:209). The same gate fronts every other /ui admin route, sandbox create (source_dir), delete, restore, snapshot, upload, outbox and takeover."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/desktop.py",
   "line": 35,
   "description": "ui_sessions columns are hash, public, created, expires, scope only (PRAGMA output in agents/v05/artifacts/v05_rotation.out line 4): no token generation."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 93,
   "description": "Start-up prunes only expired sessions. The only other deletions are single-hash logout (130), per-lookup expiry (143), expiry cleanup in new_session (122) and the legacy scope-less table drop (89); nothing deletes sessions in bulk and nothing extends expires (grep of agentbox/)."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 138,
   "description": "session_scope: SELECT by hash, reject only if expires < now."
  },
  {
   "file": "agentbox/desktop.py",
   "line": 127,
   "description": "end_session deletes exactly one hash."
  },
  {
   "file": "agentbox/web.py",
   "line": 129,
   "description": "Logout ends only the presented cookie (via service.end_ui_session, service.py:517-527)."
  },
  {
   "file": "agentbox/web.py",
   "line": 95,
   "description": "start_session (POST /login and GET /login?ticket=) mints a new session without reading or ending a cookie already presented; api.py:306 does the same for per-sandbox tickets (the hunter's api.py:306 evidence covers only that route). Harness: v05_rotation.out lines 38, 41, 43, 47."
  },
  {
   "file": "agentbox/api.py",
   "line": 66,
   "description": "human_token is read once in build(); rotation therefore needs a restart and touches nothing in agentbox.db."
  },
  {
   "file": "README.md",
   "line": 370,
   "description": "Known limitations: login sessions last 12 h and survive a restart; nothing about rotation or revocation (README.md:193 covers only expiry/deletion of one session)."
  },
  {
   "file": "tests/test_m4_acceptance.py",
   "line": 49,
   "description": "test_login_survives_restart pins persistence across a restart with an unchanged token as intended; no test or code considers rotation."
  },
  {
   "file": "agents/v05/artifacts/v05_rotation.out",
   "line": 21,
   "description": "Independent reproduction after rotation + restart on the same agentbox.db: old token 401 (line 12) and no cookie from /login (14); cookie minted under it gets /ui 200 (20), /ui/approvals 200 (21), /ui/sandboxes 200 (22); an approval decision is accepted and audit-logged under the stale session id (25-29); WS gate passed (30); 43199 s left (33); forged/no cookie controls 401 (16-18); regenerated data/human_token gives the same result (51-54)."
  },
  {
   "file": "agents/v05/artifacts/v05_rotation.out",
   "line": 36,
   "description": "Route inventory of the real app: the cookie principal reaches POST /ui/approvals/{aid}/{decision}, POST /ui/sandboxes, POST /ui/sandboxes/{sid}/delete, restore, snapshots, POST /sandboxes/{sid}/files, outbox, capture.png and desktop takeover/handback/state; only /logout matches session/revoke/logout (line 34) and no revoke/logout-all attribute exists (35)."
  },
  {
   "file": "agents/v05/artifacts/v05_fix_check.out",
   "line": 1,
   "description": "Patch validation: a token-generation binding drops sessions and tickets on rotation (lines 2-3), keeps them across a restart under the same token (1, 4-5), adds revoke_all (6-7), migrates legacy databases (8-10); the repo's session/ticket/lease unit tests pass against the patched class (11)."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds a '*' agentbox_session cookie minted before the rotation (former operator, shared browser profile, or a login made with the since-rotated token). The old token alone is not enough after rotation (Bearer 401; /login issues no cookie)."
  },
  {
   "kind": "system_configuration",
   "description": "Owner rotates the human token (new AGENTBOX_HUMAN_TOKEN, or deletes/regenerates data/human_token) and restarts against the same agentbox.db (the default; AGENTBOX_HOME/AGENTBOX_DB unchanged)."
  },
  {
   "kind": "timing_dependency",
   "description": "Use within the cookie's original 12 h life: the expiry is fixed at creation and no code path extends it, so a session minted just before the rotation gives the longest window."
  }
 ],
 "execution": {
  "attacker_perspective": "A former operator (or other holder of an earlier-minted '*' browser session cookie) who is meant to be cut off when the owner rotates the shared human token and restarts the control plane; the attacker sends ordinary browser requests with the old agentbox_session cookie, no Authorization header and no Origin header.",
  "payloads": [
   "POST /login  form token=hum_V05_old_dummy_token_aaaaaaaaaaaaaaaa -> 303, Set-Cookie agentbox_session=<cookie_old>; HttpOnly; Max-Age=43200; SameSite=strict",
   "restart: api.build() with AGENTBOX_HUMAN_TOKEN=hum_V05_new_dummy_token_bbbbbbbbbbbbbbbb on the same AGENTBOX_HOME/agentbox.db (variant: delete data/human_token and restart)",
   "GET /sandboxes with Authorization: Bearer <old token> -> 401; POST /login with the old token -> no cookie",
   "GET /ui, /ui/approvals, /ui/sandboxes, /ui/audit, /ui/notify with Cookie: agentbox_session=<cookie_old> (no Authorization, no Origin) -> 200",
   "POST /ui/approvals/<pending dummy approval id>/deny with the same cookie -> 200; approval becomes denied; audit approval_decision records session=<hs_ id of cookie_old>",
   "WS /sandboxes/sb_v05dummy/desktop/ws?mode=view with Origin http://testserver and the old cookie -> closed 1011 (past the 4401/4403 gates); no or forged cookie -> 4401"
  ],
  "instructions": [
   "Ran agents/v05/artifacts/v05_rotation.py as 'sbx v05 /usr/bin/python3.13 -I -B /scratch/v05_rotation.py' (no network, no Docker socket, read-only target and /usr, scratch-only writes, uid 65534, empty allow-listed environment, 512 MiB, 1 CPU, 64 pids, 120 s).",
   "Docker is replaced by a dummy client (info() -> runc) and Jinja2 (not installed in the sandbox) by a stub registered as fastapi.templating. Authorization runs in route dependencies before any render, so the stub cannot change an auth decision: forged or absent cookie -> 401 on the same routes where the stale cookie gets 200.",
   "Part A: api.build() with AGENTBOX_HUMAN_TOKEN=OLD, POST /login, keep cookie_old, close; api.build() again on the same AGENTBOX_HOME with AGENTBOX_HUMAN_TOKEN=NEW (the restart). Probe with Bearer OLD, form login OLD, forged and no cookie (controls) and cookie_old; create a pending dummy approval for dummy sandbox sb_v05dummy and deny it with cookie_old; open the desktop WebSocket gate for the dummy sandbox id; read ui_sessions and enumerate the routes whose auth dependency accepts the cookie principal.",
   "Part B repeats the rotation by deleting data/human_token and restarting (regenerated token). Part C posts /login, redeems a '*' ticket and a per-sandbox ticket, and logs out, each while presenting an existing cookie, then checks which sessions remain valid. Part D moves the stale row's expiry into the past to show that only the TTL ends it.",
   "Part E (and v05_fix_check.py with desktop_fixed.py, a scratch copy of desktop.py plus the patch below; target files untouched) applies the proposed generation binding in memory and repeats the rotation; the repo's own session/ticket/lease unit tests pass against the patched class."
  ],
  "observed_result": "After rotation + restart on the same database: Bearer OLD -> 401 and POST /login with OLD -> no cookie; forged or absent cookie -> 401 (GET /ui -> 303 /login). The cookie minted under OLD gets GET /ui 200, /ui/approvals 200, /ui/sandboxes 200, /ui/audit 200, /ui/notify 200; POST /ui/approvals/<dummy>/deny -> 200 and the dummy approval became denied, with an approval_decision audit entry carrying the stale session's hs_ id; the WebSocket gate accepted the stale cookie (close 1011 on the non-existent dummy sandbox) while no or forged cookie got 4401; the row had 43199 s left. Deleting/regenerating data/human_token gave the same result (token1 Bearer 401, cookie1 -> 200 on /ui/approvals and /ui/sandboxes). The session table and DesktopControl expose no revoke/logout-all, and the only session route is /logout. Logging in, redeeming a '*' ticket or a per-sandbox ticket while presenting a cookie left the presented session valid, and logout ended only its own cookie. Only expiry (moved into the past) ended the stale session (401). With the generation-binding prototype: old cookie -> 401 after rotation, new-token login 200, restart with an unchanged token keeps the login (200). Not exercised (no Docker): approve, delete, restore, upload, source_dir sandbox creation; they share the same authorization gate."
 },
 "remediation": {
  "strategy": "Bind sessions and tickets to the human token that minted them and give the owner a way to revoke: store a domain-separated hash of the human token (token_gen) in a gen column of ui_sessions and ui_tickets, delete rows whose gen differs at start-up (a rotation then drops all old sessions and unredeemed tickets, while a restart with an unchanged token still keeps logins) and require gen in session_scope; add a human-only revoke-all (DesktopControl.revoke_all, a bearer-authenticated route and an 'agentbox logout-all' command) that deletes all sessions and tickets and cuts live screen connections (the 30 s session_watch re-check in api.py already hands back leases once the rows are gone); end the replaced server-side session when a login or ticket redemption arrives with a cookie. Use a high-entropy token (the default is) because the stored fingerprint is derived from it. Add a regression test: token A login, rebuild with token B, old cookie -> 401 on /ui/approvals and WS 4401. The DesktopControl part of this patch was validated in a scratch copy (rotation drops, same-token restart keeps, revoke_all, legacy-DB migration, repo session tests pass); the api.py route and web.py glue are sketches.",
  "code_changes": [
   {
    "file_name": "agentbox/desktop.py",
    "fixed_code": "--- a/agentbox/desktop.py\n+++ b/agentbox/desktop.py\n@@ SCHEMA\n CREATE TABLE IF NOT EXISTS ui_tickets (\n-  hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL);\n+  hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL, gen TEXT NOT NULL DEFAULT '');\n CREATE TABLE IF NOT EXISTS ui_sessions (\n   hash TEXT PRIMARY KEY, public TEXT NOT NULL, created TEXT NOT NULL, expires REAL NOT NULL,\n-  scope TEXT NOT NULL DEFAULT '*');\n+  scope TEXT NOT NULL DEFAULT '*', gen TEXT NOT NULL DEFAULT '');\n@@ class DesktopControl.__init__\n-                 db_path: str | Path | None = None):\n+                 db_path: str | Path | None = None, token_gen: str = \"\"):\n+        self.gen = token_gen   # fingerprint of the human token these sessions are minted under\n@@ (after self._db.executescript(SCHEMA))\n+        for table in (\"ui_tickets\", \"ui_sessions\"):   # databases from before the token binding\n+            if \"gen\" not in [r[1] for r in self._db.execute(f\"PRAGMA table_info({table})\")]:\n+                self._db.execute(f\"ALTER TABLE {table} ADD COLUMN gen TEXT NOT NULL DEFAULT ''\")\n         now = time.time()\n-        self._db.execute(\"DELETE FROM ui_tickets WHERE expires < ?\", (now,))\n-        self._db.execute(\"DELETE FROM ui_sessions WHERE expires < ?\", (now,))\n+        # expired rows go, and so does everything minted under a different (rotated-out) human token\n+        self._db.execute(\"DELETE FROM ui_tickets WHERE expires < ? OR gen != ?\", (now, token_gen))\n+        self._db.execute(\"DELETE FROM ui_sessions WHERE expires < ? OR gen != ?\", (now, token_gen))\n@@ issue_ticket\n-            self._db.execute(\"INSERT INTO ui_tickets VALUES (?, ?, ?)\", (_h(t), sid, time.time() + self.ticket_ttl))\n+            self._db.execute(\"INSERT INTO ui_tickets (hash, scope, expires, gen) VALUES (?, ?, ?, ?)\",\n+                             (_h(t), sid, time.time() + self.ticket_ttl, self.gen))\n@@ new_session\n-            self._db.execute(\"INSERT INTO ui_sessions (hash, public, created, expires, scope) VALUES (?, ?, ?, ?, ?)\",\n-                             (_h(cookie), public, _now_iso(), now + self.session_ttl, scope))\n+            self._db.execute(\"INSERT INTO ui_sessions (hash, public, created, expires, scope, gen)\"\n+                             \" VALUES (?, ?, ?, ?, ?, ?)\",\n+                             (_h(cookie), public, _now_iso(), now + self.session_ttl, scope, self.gen))\n@@ session_scope\n-            row = self._db.execute(\"SELECT public, expires, scope FROM ui_sessions WHERE hash = ?\",\n-                                   (_h(cookie),)).fetchone()\n+            row = self._db.execute(\"SELECT public, expires, scope FROM ui_sessions WHERE hash = ? AND gen = ?\",\n+                                   (_h(cookie), self.gen)).fetchone()\n@@ new method (owner's \"log out everywhere\")\n+    def revoke_all(self) -> int:\n+        with self._lock:\n+            n = self._db.execute(\"SELECT COUNT(*) FROM ui_sessions\").fetchone()[0]\n+            self._db.execute(\"DELETE FROM ui_sessions\")\n+            self._db.execute(\"DELETE FROM ui_tickets\")\n+            conns = list(self._conns.values())\n+        for c in conns:\n+            c.close()\n+        return n\n"
   },
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "# agentbox/api.py  (add: import hashlib)\n    human_token = settings.human_token()\n    audit.register_secret(human_token)\n    # sessions/tickets are minted under this fingerprint; a rotated token drops them all at start-up\n    token_gen = hashlib.sha256(b\"agentbox-ui-session\\0\" + human_token.encode()).hexdigest()[:32]\n    box = AgentBox(\n        ...\n        desktop=D.DesktopControl(idle=settings.takeover_idle, db_path=settings.db_path, token_gen=token_gen),\n        ...\n    )\n\n    # owner-only 'log out everywhere' without rotating (sketch; also add `agentbox logout-all` calling it)\n    @app.post(\"/ui/sessions/revoke\", include_in_schema=False)\n    def revoke_sessions(p: Principal = Depends(human_only)):\n        n = box.desktop.revoke_all()\n        box.log_human(\"ui_sessions_revoked\", None, {\"count\": n})\n        return {\"revoked\": n}\n"
   },
   {
    "file_name": "agentbox/web.py",
    "fixed_code": "# agentbox/web.py  start_session(): a login that replaces a cookie ends the replaced server-side session\n    def start_session(request: Request, target: str, how: str) -> RedirectResponse:\n        stale = request.cookies.get(D.COOKIE)\n        if stale:\n            box.end_ui_session(stale)\n        cookie, session = box.desktop.new_session()\n        ...\n# agentbox/api.py desktop_page(): same call before box.desktop.redeem(...) mints the per-sandbox cookie\n"
   },
   {
    "file_name": "tests/test_m4_unit.py",
    "fixed_code": "# tests/test_m4_unit.py\ndef test_rotation_drops_sessions_but_restart_keeps_them(tmp_path):\n    db = tmp_path / \"a.db\"\n    a = DesktopControl(db_path=db, token_gen=\"A\")\n    cookie, public = a.new_session()\n    t = a.issue_ticket(\"*\")\n    a.close()\n    assert DesktopControl(db_path=db, token_gen=\"A\").session(cookie) == public      # same token: login survives\n    assert DesktopControl(db_path=db, token_gen=\"B\").session(cookie) is None        # rotated token: dropped\n    assert DesktopControl(db_path=db, token_gen=\"B\").redeem(t, \"*\") is None         # and its unredeemed tickets\n# acceptance (needs the app, no Docker): login with token A, api.build() again with token B on the same\n# AGENTBOX_HOME -> old cookie gets 401 on /ui/approvals and WS close 4401; POST /ui/sessions/revoke empties ui_sessions.\n"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Needs a '*' cookie minted before the rotation (a former operator, a shared browser profile, or a login made with the since-rotated token) and an owner who rotates while that session is alive; the old token alone is useless after rotation (Bearer 401, /login issues no cookie). HttpOnly + SameSite=Strict (+ Secure behind TLS) make remote theft of the cookie hard, and use is capped at the cookie's 12 h life, which is fixed at creation."
  },
  "impact": {
   "score": "high",
   "reason": "The stale session passes the same gate as every admin UI route (demonstrated: UI pages 200 and an approval decision on a dummy approval executed and audit-logged under the stale session id; the route inventory shows approve/deny, delete/restore, upload, outbox, host source_dir sandbox creation and takeover behind that gate, not exercised without Docker). It grants no privilege beyond what the holder already had, the JSON management API stays closed to cookies and exposure ends at expiry, but the owner cannot cut the holder off sooner than 12 h, with rotation or otherwise."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Independently reproduced in the OS sandbox with the real api.build() factory, real DesktopControl/SQLite persistence and the real auth dependencies (only Docker and Jinja2 stubbed), with positive and negative controls (forged/no cookie 401, Bearer OLD 401, expiry 401), both rotation methods, and a source trace checked line by line; corrections to the hunter's wording: start-up prune is lines 92-93, the old token alone gives nothing after rotation, api.py:306 covers only per-sandbox tickets ('*' tickets go through web.py:95), and session_scope (desktop.py:133) was missing from the trace. The architecture summary names no comparable baseline to calibrate against."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

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

- Agent ID `p5-v05`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v05/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v05 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v05/artifacts/<file>`.

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
