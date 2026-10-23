You are final record verifier `r07` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight",
 "title": "Unauthenticated GET /static/novnc/* runs docker create plus a full /usr/share/novnc tar extraction on every request while home/novnc/core/rfb.js is absent, with no single-flight",
 "description": "api.py:355-356 registers GET /static/novnc/{path:path} with no Depends(), principal, cookie or ticket and calls box.sandboxes.extract_novnc(novnc_dir) at api.py:358 before it resolves or validates the requested path. extract_novnc (sandbox_desktop.py:146-169) has one guard: it returns True when dest/core/rfb.js exists (148). While that marker is absent, every request runs self.client.containers.create(desktop_image, [\"true\"], network_mode=\"none\") (152), joins the whole /usr/share/novnc archive into memory with b\"\".join(stream) (156-157), extractall()s it into the control plane's data directory (163-166) and removes the container (160-161). There is no lock, no in-flight marker and no negative cache, so every concurrent caller passes the line-148 check and duplicates the daemon work: measured in the approved sandbox with the Docker client stubbed, six concurrent unauthenticated GETs made six containers.create calls, and twelve concurrent GETs made twelve. The claimed concurrent 500/FileExistsError outcome is fixture-dependent rather than universal: it reproduces (1 x 200, 5 x 500 FileExistsError on '<home>/novnc/core') only when the served tar has no directory members, because tarfile's own os.makedirs(upperdirs) in _extract_member is unguarded; with a directory-complete archive of the kind containers.get_archive('/usr/share/novnc') produces, all six and all twelve concurrent requests returned 200 while still performing six and twelve creates. Failures are still uncaught and unbounded in time: a truncated or corrupt archive raised ReadError outside the narrow ImageNotFound/NotFound/APIError handlers, producing 500 on every request, three creates for three requests and a marker that never appears, and the route also pays the create before it answers 404 (three unauth GETs for /static/novnc/does-not-exist.js each made one create). Once one extraction succeeds the marker makes later requests cheap, so the duplication is confined to the pre-marker window and to broken states.",
 "root_cause": "An unauthenticated static-asset route performs Docker-daemon work and an archive extraction behind a check-then-act test on a single marker file, with no lock, no in-flight flag and no negative cache; exceptions outside the narrow docker-error handlers escape as a 500 without publishing the marker or any bounded negative state, so the expensive state persists and the work is repeatable by any anonymous client.",
 "intended_behavior": "Static assets should not require per-request daemon work: the extraction should happen once (at startup or on the first authenticated desktop route) under a lock that lets one caller do it while the others wait or observe the result, and a failed extraction should leave a bounded negative state instead of being retried by every request. /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 355,
   "scope": "GET /static/novnc/{path:path}",
   "description": "The route decorator adds no Depends() and the handler at 356 takes only the path, so it is exempt from the human, desktop-link and agent principals used everywhere else and is reachable by any network client; deploy/Caddyfile:4-5 exposes it through a bare reverse_proxy with no auth, rate limit or body limit."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 358,
   "scope": "extract_novnc called on every request",
   "description": "The handler calls box.sandboxes.extract_novnc(novnc_dir) before resolving or validating path (360-362), so the only thing that keeps a request cheap is the marker file the function itself is supposed to create."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox_desktop.py",
   "line": 148,
   "scope": "the sole guard is a marker-file existence check",
   "description": "if (dest / \"core\" / \"rfb.js\").exists(): return True - a check-then-act test performed outside any lock, with no in-flight marker and no negative cache, so N concurrent callers all proceed to the sink."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox_desktop.py",
   "line": 152,
   "scope": "containers.create + get_archive + extractall",
   "description": "Each request that finds no marker creates a container from the desktop image (152), pulls the whole /usr/share/novnc tar into memory with b\"\".join(stream) (156-157), extracts it into settings.home (162-166) and removes the container (161)."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 153,
   "description": "Only ImageNotFound/APIError are caught around create, and only NotFound/APIError around get_archive (158-159); the tarfile open/getmembers/extractall at 163-166 and the remove at 161 are outside any handler, so a corrupt archive or a failing remove escapes as a 500."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 166,
   "description": "tf.extractall(dest.parent, members, filter=\"data\") writes the tree into the control plane's data directory with no lock and no in-flight marker, which is why concurrent callers that all passed line 148 duplicate the extract."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 169,
   "description": "The return value is the same marker that the error paths never publish, so a create, remove or extraction failure leaves the expensive state in place and the next request repeats the whole sequence."
  },
  {
   "file": "agentbox/api.py",
   "line": 361,
   "description": "The path-relative check and the is_file()/404 happen only after the extraction attempt, so even a request for a missing asset pays one containers.create (measured: three unauthenticated GETs for /static/novnc/does-not-exist.js made three creates and returned 404 each time)."
  },
  {
   "file": "agentbox/api.py",
   "line": 100,
   "description": "novnc_dir = settings.home / \"novnc\": the extraction target sits in the control plane's persistent data directory, so the unauthenticated request path also writes shared operator-owned state."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 167,
   "description": "The rename at 167-168 is dead at this call site because api.py:358 always passes a dest whose name is already \"novnc\"; it therefore affords no additional race, and the raced work is the tarfile extraction itself."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 5,
   "description": "The only front door is a bare reverse_proxy to agentbox:8765 with no basic_auth, rate limit or request_body limit, so nothing upstream bounds how many concurrent unauthenticated extraction requests reach the route."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "None - the route requires no principal, cookie or ticket."
  },
  {
   "kind": "system_configuration",
   "description": "The desktop image is present (otherwise create raises ImageNotFound and the route is cheap) and home/novnc/core/rfb.js is absent: a fresh install before anyone opened a desktop page, or a state left behind by a failed or partial extraction. Nothing else in the tree calls extract_novnc, so the marker is created by this unauthenticated route on first use."
  },
  {
   "kind": "timing_dependency",
   "description": "Two or more requests must be in flight together to duplicate the daemon work; a single request duplicates nothing, and the first success publishes the marker and ends the window for later requests."
  }
 ],
 "execution": {
  "attacker_perspective": "An unauthenticated client issues GETs to /static/novnc/core/rfb.js (or any path under that prefix), early in a deployment's life and in parallel, so the first-time extraction happens under its timing instead of a real user opening the desktop page, and so one marker miss is multiplied by the number of simultaneous requests.",
  "payloads": [
   "GET /static/novnc/core/rfb.js  (no headers, no cookie) - six copies issued concurrently",
   "GET /static/novnc/core/rfb.js  (no headers, no cookie) - twelve copies issued concurrently",
   "GET /static/novnc/does-not-exist.js  (no headers, no cookie) - sequential, tree deleted before each"
  ],
  "instructions": [
   "In the approved sandbox, patch docker.from_env to return an in-process fake client whose containers.create counts calls and whose get_archive serves a fixed tar containing novnc/core/rfb.js (the sandbox has no daemon), then build the real app with fastapi 'build(Settings(home=<scratch>/home))'.",
   "Delete home/novnc and issue one GET, then a second GET, recording status codes and the number of containers.create calls (marker published, steady state cheap).",
   "Delete home/novnc again and issue six, then twelve, concurrent GETs with asyncio/threads using separate TestClient instances (raise_server_exceptions=False) and an app-level exception handler that records exception types, recording status codes and containers.create calls.",
   "Repeat with an archive that omits directory members, and with a truncated archive, to separate the fixture-dependent FileExistsError outcome from the fixture-independent duplication and 500-on-error outcomes."
  ],
  "observed_result": "With home/novnc deleted, one unauthenticated GET returned 200, made 1 containers.create call and wrote home/novnc/core/rfb.js; the next GET made 0 create calls and returned 200 (marker hit). After deleting the tree, six concurrent unauthenticated GETs made 6 create calls, and in a second run twelve concurrent GETs made 12 create calls; with a directory-complete archive all of those responses were 200 and no exception was raised. With an archive that has no directory members, the same six-request burst returned one 200 and five 500s with FileExistsError: [Errno 17] File exists: '<home>/novnc/core' while still making 6 creates. Three unauthenticated GETs for /static/novnc/does-not-exist.js, each with the tree deleted first, made 3 more create calls and returned 404 each time. With a truncated archive, three sequential unauthenticated GETs each made another containers.create call and returned 500 ReadError: unexpected end of data with the marker still absent, and four concurrent requests against a truncated archive made 4 creates and 4 x 500."
 },
 "remediation": {
  "strategy": "Extract once, under a lock, outside the request path: do it at startup or on the first authenticated desktop route, guard it with a per-directory lock plus an in-flight event so concurrent callers wait for the winner, publish the marker only after a successful extraction, and treat any failure as a bounded negative state (a timestamped failure marker that short-circuits the route for a cooldown). /static/novnc/* should answer 404/503 without creating containers whenever the marker is absent.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "        self.client = docker.from_env()\n        self._lock = threading.Lock()\n        self._novnc_lock = threading.Lock()   # single-flight for extract_novnc"
   },
   {
    "file_name": "agentbox/sandbox_desktop.py",
    "fixed_code": "    def extract_novnc(self, dest: Path) -> bool:\n        marker = dest / \"core\" / \"rfb.js\"\n        if marker.exists():\n            return True\n        with self._novnc_lock:            # one extraction per process\n            if marker.exists():           # a waiter re-checks after the winner finished\n                return True\n            try:\n                c = self.client.containers.create(self.settings.desktop_image, [\"true\"], network_mode=\"none\")\n            except (ImageNotFound, APIError):\n                return False\n            try:\n                stream, _ = c.get_archive(\"/usr/share/novnc\")\n                out = b\"\".join(stream)\n            except (NotFound, APIError):\n                return False\n            finally:\n                try:\n                    c.remove(force=True)\n                except APIError:\n                    pass\n            dest.parent.mkdir(parents=True, exist_ok=True)\n            try:\n                with tarfile.open(fileobj=io.BytesIO(out)) as tf:\n                    members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]\n                    tf.extractall(dest.parent, members=members, filter=\"data\")\n            except (OSError, tarfile.TarError):\n                shutil.rmtree(dest, ignore_errors=True)   # never serve a half tree\n                return False\n            return marker.exists()"
   },
   {
    "file_name": "agentbox/api.py",
    "fixed_code": "    @app.get(\"/static/novnc/{path:path}\")\n    def novnc(path: str):\n        root = novnc_dir.resolve()\n        # 정적 파일은 요청 경로에서 컨테이너를 만들지 않는다. 시작 시 한 번만 꺼낸다.\n        if not (root / \"core\" / \"rfb.js\").is_file():\n            raise HTTPException(404)\n        f = (root / path).resolve()\n        if not f.is_relative_to(root) or not f.is_file():\n            raise HTTPException(404)\n        return FileResponse(f)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "The expensive state is the missing marker, which exists on a fresh install and after any failed extraction; once the marker exists the cost drops to zero, so the attacker has to arrive before the first legitimate desktop use or exploit a broken state, but no credential is needed to do either."
  },
  "impact": {
   "score": "low",
   "reason": "Unauthenticated Docker-daemon work, control-plane threads and data-directory writes, each create holding the whole asset tar in memory, plus 500s and a repeatable path while extraction keeps failing; no data disclosure or privilege gain, and the per-request cost is bounded by one container create plus one asset-tree tar."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "The source trace is complete, every cited line was re-read in the audited tree, and the duplication, the pre-404 create and the repeat-after-failure behaviour were reproduced in the approved sandbox with the Docker client stubbed; the only correction to the candidate is that the concurrent FileExistsError 500s depend on an archive without directory members, while the duplication itself reproduced in both archive shapes."
 }
}
```

# Phase 5 procedure (verbatim)

```text
### Phase 5: Verify the final records with fresh eyes

Launch one fresh `research` verifier per final `confirmed` and `needs_validation` record, in parallel. This verifier checks the structured record, not the hunter write-up, and remains inside source/local boundaries.

In a `quick` run, Phase 3 and Phase 5 merge: the Phase 3 verifier also performs these record checks and returns the final schema-shaped record, so each candidate gets one fresh independent reviewer instead of two. Every other profile keeps the two passes separate. Never skip independent review of a `confirmed` record in any profile.

For `confirmed`, require it to check:

1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.

For `needs_validation`, require it to check:

1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.

Each verifier returns exactly one JSON object: `{"decision":"verified","fingerprint":"..."}` or `{"decision":"replace","reason":"...","record":{...}}`, with no surrounding prose. A replacement record must match its `confirmed`, `needs_validation`, or `rejected` schema branch. Treat a malformed or prose-wrapped Phase 5 result the same way as in Phase 3: discard it without repairing it and re-run with a fresh verifier when the budget permits.

Do not apply a Phase 5 replacement as final when it promotes a record to a stronger verdict, including any promotion to `confirmed`, or materially changes the root cause, trace, execution input or observed result, demonstrated impact, or severity. Give that complete replacement to a new independent verifier that did not hunt, perform Phase 3 validation, or propose the Phase 5 replacement. The new verifier rechecks the current source and independently reproduces any decisive local result under the execution boundary, then returns `verified` or another replacement. Apply a material replacement only after this fresh verification. If another material replacement results, repeat with a fresh verifier. If budget or independence is unavailable, remove the disputed record from `findings.json`, keep its ledger unit as an unresolved candidate, and set `run_status: "incomplete"` with an exact `incomplete_reason`. Non-material wording or repository-line corrections may be applied directly when they do not change meaning or evidence.

After every applied replacement, rerun both validators and update linked ledger decisions. If a final verifier identifies a separate root cause, assign a new fingerprint and send it through independent candidate validation before inclusion. Set `run_status: "complete"` only when every ledger candidate has an independent final disposition and every retained record passes Phase 5.

Do not verify only `confirmed` records. A misleading `needs_validation` handoff wastes owner time and can preserve a false premise.
```

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

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost path, a missing effective bound, and impact on another user, shared service, safety function, or operator-owned spend. Self-limiting work in the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body/message/file caps, concurrency, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before calling a path unbounded.
- Do not run stress, saturation, or production tests. Use asymptotic analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State attacker cost, service work, persistence, scope, and recovery. One bounded input with superlinear or persistent shared effect is materially different from sustained volume.
- Use `confirmed` for source-visible bounds failures demonstrated safely. Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behavior is outside the repository.
```

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance -->
**Pre-authentication work imbalance**
Expensive parsing, key lookup, cryptography, decompression, or external requests happen before authentication and the earliest size/rate gate. Compare minimal requester effort to shared service cost and check upstream limits.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#File descriptor, handle, and temporary-resource leaks -->
**File descriptor, handle, and temporary-resource leaks**
Malformed or canceled work misses cleanup and retains sockets, files, database cursors, timers, subprocesses, temporary files, or object references. Confirm the leak repeats through bounded local iterations and affects a shared pool.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves -->
## Universal moves (apply across the above)

- Build an input-to-resource table: earliest accepted size/cardinality, work before auth, downstream fan-out, persistence, shared pool, limit and cleanup owner, recovery.
- Compare aggregate limits with per-object limits. Ten thousand valid one-byte items may evade a per-message cap while exhausting tenant-wide or process-wide state.
- Validate only in an isolated fixture with strict CPU/memory/time limits and small growth points. Mock external and paid calls and stop once the missing bound or cancellation is observable.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name untrusted input, requester work, service amplification or retained resource, shared blast radius, and recovery. Missing limits without concrete shared impact are hardening.
2. Confirm no source-visible upstream, parser, queue, tenant, or framework bound prevents the path. Unknown deployed controls require `needs_validation`.
3. For superlinear behavior, establish the accepted complexity and bounded local growth. For leaks, show repeatable retention after cleanup should occur. For fatal paths, identify process/supervisor isolation.
4. Prioritize by low requester work, unauthenticated reachability, cross-tenant scope, persistence, and poor recovery; do not validate with availability impact.
5. Return `confirmed` only with safe local proof and meaningful shared effect. Return `needs_validation` with the exact upstream limit, topology, quota, or recovery observation an owner must check.

# Execution boundary and paths

- Agent ID `r07`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r07/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r07 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r07 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/sandbox_desktop.py:extract-novnc-unauthenticated-no-singleflight"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
