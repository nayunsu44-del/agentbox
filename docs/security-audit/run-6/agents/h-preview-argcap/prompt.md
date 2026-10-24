You are hunter `h-preview-argcap` in run-6 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

# architecture.md (verbatim)

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
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per sandbox by `AgentBox._lifecycle`.
- **GUI bursts** (`gui_bursts.py`): `needs_snapshot`, `open` (fail-closed baseline, bound to `container_id`), `covers` (checks `sid in _gui_burst`), `close`/`_finish` (stray kill via `gui_state.gui_strays` from root `ps` + XRes window owners, manifest diff → `gui_changes`), `close_idle` on a dedicated pool, `end`.
- **Desktop**: tickets (60 s, one-time, hashed), sessions (12 h, scoped), leases; takeover/handback (`bursts.close` under `gui_lock`); WS route `api.py:desktop_ws` (cookie session via threadpool, `same_origin` with missing Origin allowed, mode, `may_connect`) → `desktop_ws.relay` (threadpool `vnc_command`/`log_human`, session recheck every 30 s, shielded disconnect log before `drop_conn`).
- **Files**: `read_file`/`write_file`/`delete_file`/`list_dir` (`safe_path`), upload, outbox list/read; `list_dir`, `exists`, `is_dir`, `outbox_list` run `exec_run` with no container-side timeout and full buffering (`_expand`/`_walk` now have 10 s timeout via `_timed`, `_walk` uses `head -z`, `_expand` still buffers all matching names).
- **Rendering**: Jinja autoescape + `finalize=_shown` → `display.escape_controls` (shared with `cli._safe`); `_NoFraming` middleware on HTTP responses.
- **Audit**: hash chain + append-only triggers, `mask_text`, `bound_payload`; `log_human` fails closed with 503; tool results and burst records are best-effort; `retention.prune` exports archives and installs `audit_anchor`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc on this host) |
| Agent → approval gate (exec) | `TOOL_ARG_MAX` + `policy.simple_programs` allowlist + `_relex_changes` + `has_bash_comment` + `>`/`$` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot under `gui_lock` + lease check, `covers()`, fail-closed open, `gui_changes`, XRes stray kill |
| Agent → human authority | token kinds, `human_only`, scope checks, `samefile` source_dir overlap check |
| Agent → control-plane availability | `_BodyLimit` auth check, `TOOL_ARG_MAX`, `PREVIEW_CALLS_MAX`, `_PREVIEW_TIMEOUT`, `tool_pool`, tool concurrency, `_Head`, snapshot quota, pending cap, `disk_low` |
| Container output → control plane | `_parse_ps`, `_parse_manifest`, `_parse_outbox`, preview parsing; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin`, XFO/frame-ancestors |
| Desktop-link session → rest of UI | `scope`, `desktop_human` |
| Network → control plane | `bind_problem`; `_BodyLimit` credential gate; proxy trust `*`; unauthenticated login/novnc routes |

# Assigned coverage units

[
 {
  "coverage_id": "Agent%20tool-argument%20length%20cap%20and%20policy%2Fpreview%2Fapproval%20bounds%20%28PR%20%2324%29%3A%20TOOL_ARG_MAX%20%28service.py%3A49%2C%20322-329%29%2C%20policy._relex_changes%20%28policy.py%3A40-49%2C%2073%29%2C%20preview_command%20PREVIEW_CALLS_MAX%2FNOTES_MAX%20and%20operand%20deduplication%20%28preview.py%3A70-160%29%2C%20sandbox._PREVIEW_TIMEOUT%2F_preview_ok%20%28sandbox.py%3A39%2C%20104-106%2C%20578-594%29%2C%20and%20pending-approval%20bound_payload%28preview%29%20%2B%20pre-create%20disk_low%28%29%20recheck%20%28service.py%3A357-362%29::Agent-to-control-plane%20CPU%2C%20container-exec%20and%20SQLite%20amplification%20across%20tool%20calls%20%28PR%20%2324%20fixes%20for%20run-5%20F1%2C%20F5%2C%20F6%29%3A%20_call_tool%20rejects%20non-content%20args%20over%2016%20KiB%20%28measured%20on%20str%20or%20json.dumps%29%20with%20413%20before%20audit%2Fpolicy%3B%20_words%20skips%20re-lexing%20only%20when%20_relex_changes%20is%20False%3B%20preview_command%20caps%20expand%2Fwalk%20calls%20at%2040%20%2810%20s%20timeout%20each%29%20and%20notes%20at%2050%3B%20pending%20approvals%20bound%20preview%20to%20128%20KiB%20and%20re-check%20disk_low%20before%20creation.%20Invariant%3A%20no%20agent%20tool%20call%20can%20bypass%20TOOL_ARG_MAX%2C%20cause%20superlinear%20or%20multi-second%20policy%20CPU%2C%20trigger%20unbounded%20preview%20execs%2C%20or%20write%20an%20oversized%20pending%20approval%20row%20past%20disk_low%2C%20and%20_relex_changes%20does%20not%20drop%20any%20dangerous%20command%20detection.::agentbox%2Fservice.py%23TOOL_ARG_MAX%2F_call_tool%20%2B%20agentbox%2Fpolicy.py%23_relex_changes%2F_words%20%2B%20agentbox%2Fpreview.py%23PREVIEW_CALLS_MAX%2FNOTES_MAX%2Fpreview_command%20%2B%20agentbox%2Fsandbox.py%23_PREVIEW_TIMEOUT%2F_preview_ok%2F_expand%2F_walk::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Superlinear%20parsing%2C%20matching%2C%20or%20evaluation",
  "surface": "Agent tool-argument length cap and policy/preview/approval bounds (PR #24): TOOL_ARG_MAX (service.py:49, 322-329), policy._relex_changes (policy.py:40-49, 73), preview_command PREVIEW_CALLS_MAX/NOTES_MAX and operand deduplication (preview.py:70-160), sandbox._PREVIEW_TIMEOUT/_preview_ok (sandbox.py:39, 104-106, 578-594), and pending-approval bound_payload(preview) + pre-create disk_low() recheck (service.py:357-362)",
  "boundary": "Agent-to-control-plane CPU, container-exec and SQLite amplification across tool calls (PR #24 fixes for run-5 F1, F5, F6): _call_tool rejects non-content args over 16 KiB (measured on str or json.dumps) with 413 before audit/policy; _words skips re-lexing only when _relex_changes is False; preview_command caps expand/walk calls at 40 (10 s timeout each) and notes at 50; pending approvals bound preview to 128 KiB and re-check disk_low before creation. Invariant: no agent tool call can bypass TOOL_ARG_MAX, cause superlinear or multi-second policy CPU, trigger unbounded preview execs, or write an oversized pending approval row past disk_low, and _relex_changes does not drop any dangerous command detection.",
  "subsystem": "agentbox/service.py#TOOL_ARG_MAX/_call_tool + agentbox/policy.py#_relex_changes/_words + agentbox/preview.py#PREVIEW_CALLS_MAX/NOTES_MAX/preview_command + agentbox/sandbox.py#_PREVIEW_TIMEOUT/_preview_ok/_expand/_walk",
  "attack_class": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
  "starting_paths": [
   "agentbox/service.py",
   "agentbox/policy.py",
   "agentbox/preview.py",
   "agentbox/sandbox.py",
   "agentbox/approvals.py",
   "agentbox/audit.py",
   "tests/test_m5_unit.py"
  ],
  "ordinary_attack_class_block": "ATTACK-CLASSES.md#Injection",
  "selected_companion_blocks": [
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves",
   "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules",
   "ATTACK-CLASSES.md#Injection"
  ],
  "excluded_blocks": [
   {
    "block": "AI-AND-LLM.md#Action-confirmation and approval binding",
    "reason": "Approval card semantic truthfulness is owned by the sibling h-preview-argcap unit."
   }
  ],
  "prior_status": "new"
 },
 {
  "coverage_id": "Approval-preview%20truthfulness%20after%20the%20F4%20change%3A%20preview_command%20%28rm%20operand%20expansion%20via%20_expand%2C%20recursive%20_walk%2C%20curl%20upload%20detection%2C%20_split_segments%20and%20_WRAPPERS%20handling%29%20versus%20what%20the%20approved%20shell%20command%20really%20does::Human%20approval%20binding%3A%20the%20card%20the%20human%20decides%20on%20is%20computed%20by%20a%20separate%20shell-parse%20and%20container%20glob%2Ffind%2C%20not%20by%20the%20executing%20shell.%20The%20run-4%20F4%20fix%20replaced%20newline%20output%20with%20NUL-separated%20records%20and%20head%20-z%2C%20and%20no%20run-5%20unit%20re-checks%20the%20card%20against%20real%20behaviour.%20Cases%20to%20test%3A%20brace%20and%20tilde%20expansion%2C%20dotfile%20globs%2C%20rm%20-f%2F--no-preserve-root%2C%20operands%20after%20%27--%27%2C%20symlinks%2C%20names%20with%20newlines%20or%20leading%20%27-%27%2C%20commands%20the%20preview%20marks%20%27no%20effect%20computed%27%2C%20and%20the%20200-item%20display%20truncation%20hiding%20later%20deletions.::agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fservice.py%23_preview%2Fdecide%20%2B%20agentbox%2Ftemplates%2F_approvals.html::Action-confirmation%20and%20approval%20binding%20%28preview%20does%20not%20match%20execution%29",
  "surface": "Approval-preview truthfulness after the F4 change: preview_command (rm operand expansion via _expand, recursive _walk, curl upload detection, _split_segments and _WRAPPERS handling) versus what the approved shell command really does",
  "boundary": "Human approval binding: the card the human decides on is computed by a separate shell-parse and container glob/find, not by the executing shell. The run-4 F4 fix replaced newline output with NUL-separated records and head -z, and no run-5 unit re-checks the card against real behaviour. Cases to test: brace and tilde expansion, dotfile globs, rm -f/--no-preserve-root, operands after '--', symlinks, names with newlines or leading '-', commands the preview marks 'no effect computed', and the 200-item display truncation hiding later deletions.",
  "subsystem": "agentbox/preview.py#preview_command/_split_segments + agentbox/sandbox.py#_expand/_walk/preview + agentbox/service.py#_preview/decide + agentbox/templates/_approvals.html",
  "attack_class": "Action-confirmation and approval binding (preview does not match execution)",
  "starting_paths": [
   "agentbox/preview.py",
   "agentbox/sandbox.py",
   "agentbox/service.py",
   "agentbox/policy.py",
   "agentbox/templates/_approvals.html",
   "agentbox/default_policy.yaml"
  ],
  "ordinary_attack_class_block": null,
  "selected_companion_blocks": [
   "AI-AND-LLM.md#Action-confirmation and approval binding"
  ],
  "excluded_blocks": [
   {
    "block": "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
    "reason": "Preview call-count, timeout and policy CPU bounds are owned by the sibling h-preview-argcap unit."
   }
  ],
  "prior_status": "prior_deferred"
 }
]

## Prior-run records linked to these units (changed source: revalidate, do not assume)

Since run-5 (audited at 346df29), every run-5 confirmed record and the N1 needs_validation record were fixed in PRs #24 and #25; the source you read is the fixed tree at `530b29e`. Run-4 needs_validation N1 (`same_origin` scheme) and N3 (container output reader caps) were not fixed and are in scope. For each prior confirmed record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can (candidate with the same fingerprint as confirmed, needs_validation, or record in your unit check why it no longer holds). A prior rejected claim may be re-reported only with changed evidence.

- `agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention` — run-5 confirmed medium: One agent exec call writes a pending approval row about 45x its body size, getting past the PR #20 disk guard in a single step
  Root cause (run-5 wording): The disk guard is only a threshold check at call entry (service.py:282). The REQUIRE_APPROVAL branch then calls _preview (service.py:332), and preview_command appends one note per unrecognised segment with no count bound (preview.py:125). The 200-item cap at preview.py:127-128 applies only to 'affected'. approvals.create (approvals.py:56-57) stores json.dumps(args) and json.dumps(preview) unbounded. bound_payload is applied only to the audit copy (AuditLog.append) and to finished rows (_finish, service.py:406-411), never when the pending row is created. The agent request body is capped only by the global 8 MiB AGENTBOX_MAX_BODY, and there is no per-argument size limit before policy and preview.
- `agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap` — run-5 confirmed low: Agent exec command of up to 8 MiB drives minutes of GIL-holding policy parsing per call, slowing the shared control plane
  Root cause (run-5 wording): Policy evaluation has no input-size bound. AgentBox._call_tool passes args['command'] of any length to Policy.decide (service.py:311). The only limit is the 8 MiB HTTP body cap. _words (policy.py:40-62) re-lexes every token that contains whitespace or any character of _SHELL_PUNCT (policy.py:26, 60-61) with a fresh shlex.shlex instance (policy.py:45), even a token that is only ';' or that shlex would return unchanged (for example 'x$'), and the re-lex recurses to depth 4. shlex construction is expensive, so the cost is about 80 us per ';' token, and an 8 MiB command holds about 4M of them.
- `agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound` — run-5 confirmed low: Approval preview runs two untimed docker execs per rm operand, with no count or deadline, on a tool_pool thread before the approval exists
  Root cause (run-5 wording): preview_command loops over every rm operand and every glob match and calls the container callbacks with no call budget, total deadline, or early stop once 'limit' affected entries exist. _expand and _walk use plain c.exec_run without the _timed wrapper used by the manifest and read execs, so a single exec also has no container-side time bound. Neither call_tool nor _call_tool caps the operand count or the command length.
- `agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets` — run-4 confirmed low: Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent)
  Root cause (run-4 wording): The preview path transport is not a lossless representation of a filesystem path. sandbox.py:559 iterates $1 unquoted under the default IFS, so an operand that shlex already unquoted (preview.py:33-44) is re-split into words and each word is expanded again before the existence test; matches are framed with printf "%s/n" and re-split by splitlines() (sandbox.py:562), and _walk's find | head output is split the same way (sandbox.py:565-569). preview.py:90-91 maps an empty expansion to the "does not currently exist" row and preview.py:96-98 maps each returned line to a deletion row, so a split operand both hides the real target and can manufacture paths the command will never touch. The executed command keeps its quoting (sandbox.py:411), so the card and the effect diverge.

## Parent notes

- You own two units: (1) approval-preview truthfulness (`preview.py`, `sandbox.py:_expand/_walk`, `templates/_approvals.html`) and (2) the PR #24 argument/policy/preview/approval caps (`TOOL_ARG_MAX`, `_relex_changes`, `PREVIEW_CALLS_MAX`, `NOTES_MAX`, `_PREVIEW_TIMEOUT`, `bound_payload(preview)`, `disk_low()` recheck). Report both units in your `units` array.
- For approval-preview truthfulness: test `preview_command` and `_expand`/`_walk` (using sandboxed harnesses in `/scratch`) on edge cases where what the approval card shows diverges from what `/bin/bash -c` actually deletes or uploads when approved: brace expansion `{a,b}`, tilde `~`, glob characters inside quotes `rm "*"` vs unquoted `rm *`, `IFS=` in `_expand`'s `for p in $1` when `$1` has spaces or globs, options combined with `-r` (e.g. `-rfv`, `--recursive`, `-R`), operands after `--`, directory symlinks, paths starting with `-`, `rm` inside wrappers (`sh -c`, `env`, `sudo`, subshells, command substitution, pipelines, `find -delete`, `unlink`), and how `PREVIEW_CALLS_MAX=40` / `limit=200` / `bound_payload` affect what the human sees.
- For PR #24 caps: check `TOOL_ARG_MAX` in `service.py:323-329` (non-str values, `content` exemption on tools other than `write_file`? What if an agent passes `content` to `exec` or another tool, or passes a dict/list whose `json.dumps` is under 16 KiB but expands?), check `policy._relex_changes` in `policy.py:40-49` (can any command with `$` or backticks or quotes evade `_words` recursion because `_relex_changes` returns `False`?), and check whether `PREVIEW_CALLS_MAX=40` + `NOTES_MAX=50` + `bound_payload(preview)` + `disk_low()` recheck completely close run-5 F1/F5/F6.
- Contract reminder: each unit's `reviewed_paths` MUST be the exact set union of its `checks[*].reviewed_paths`.

# Selected attack-class blocks (verbatim)

<!-- ATTACK-CLASSES.md#Injection -->
**Injection** (subagent_type: `general`)
Trace untrusted input from entry point to dangerous sink. What counts as a "dangerous sink" depends on the application:
- Web apps: SQL queries, HTML output, shell commands, template engines, file paths, HTTP redirects, deserialization
- Libraries: any function that processes caller-supplied data without validation — buffer operations, parsers, format strings
- CLI tools: shell command construction, file path handling, environment variable interpolation
- Services: query construction, message serialization, log injection, LDAP/XPATH queries
- Client-side (browser/JS): DOM XSS, prototype pollution, `postMessage`/origin trust, and other browser-side classes — covered by the [CLIENT-SIDE.md](CLIENT-SIDE.md) companion blocks when selected

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation -->
**Superlinear parsing, matching, or evaluation**
Small accepted input drives catastrophic regex backtracking, nested parsing, recursive validation, symbolic evaluation, graph traversal, template expansion, or adversarial sort/hash behavior. Derive accepted depth/cardinality and complexity, then demonstrate a bounded growth curve locally.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost path, a missing effective bound, and impact on another user, shared service, safety function, or operator-owned spend. Self-limiting work in the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body/message/file caps, concurrency, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before calling a path unbounded.
- Do not run stress, saturation, or production tests. Use asymptotic analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State attacker cost, service work, persistence, scope, and recovery. One bounded input with superlinear or persistent shared effect is materially different from sustained volume.
- Use `confirmed` for source-visible bounds failures demonstrated safely. Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behavior is outside the repository.
```

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps -->
**Quota-accounting scope and reset gaps**
Accounting uses attacker-influenceable IP, route, tenant, key prefix, task ID, or other dimension, allowing one principal's work to escape its intended budget or consume another principal's allocation. Review integer overflow, distributed races, retries, reconnects, and account switching.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

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

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

# Excluded blocks

- `AI-AND-LLM.md#Action-confirmation and approval binding`: Approval card semantic truthfulness is owned by the sibling h-preview-argcap unit.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation`: Preview call-count, timeout and policy CPU bounds are owned by the sibling h-preview-argcap unit.

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
- `AuditLog._lock%20as%20a%20global%20contention%20point%20reachable%20by%20agent-grown%20table%20size%20and%20by%20unauthenticated%20traffic%3A%20GET%20%2Fui%2Faudit%20%28polled%20every%203%20s%20by%20templates%2Fsandbox.html%29%2C%20GET%20%2Fui%2Fverify%2C%20GET%20%2Faudit%2Fverify%2C%20AuditLog.recent%20%28unindexed%20COUNT%28%2A%29%20WHERE%20sandbox_id%29%2C%20AuditLog.verify%20%28fetchall%20of%20the%20whole%20table%2C%20audit.py%3A336-350%29%2C%20AuditLog.list%2C%20versus%20every%20AuditLog.append%2Finsert_record%20from%20agent%20tool%20calls%20and%20every%20fail-closed%20log_human%3B%20plus%20the%20unauthenticated%20POST%20%2Flogin%20failure%20throttle%20%28web.py%3A93-114%29%20and%20extract_novnc%20single-flight%20%28sandbox_desktop.py%3A174%29::Agent%20and%20unauthenticated%20clients%20to%20human%20availability%20and%20audit%20evidence%3A%20AuditLog.recent%2Fverify%20scan%20the%20agent-grown%20table%20under%20the%20same%20_lock%20append%20needs%20%28fail-closed%20log_human%20returns%20503%20while%20it%20is%20held%29%2C%20verify%20loads%20the%20whole%20table%2C%20the%20F8%20login%20throttle%20shares%20one%20global%20window%2C%20and%20F5%20extract_novnc%20holds%20a%20global%20lock%20across%20docker%20create.%20Invariant%3A%20no%20agent%20or%20unauthenticated%20sequence%20holds%20these%20locks%20long%20enough%20to%20refuse%20human%20actions%2C%20exhaust%20memory%2C%20or%20hide%20credential-guessing%20evidence.::agentbox%2Faudit.py%23recent%2Fverify%2Flist%2Fappend%2Finsert_record%2F_lock%20%2B%20agentbox%2Fweb.py%23note_login_failure%2Faudit%20and%20verify%20routes%20%2B%20agentbox%2Fapi.py%23%2Faudit%2Fverify%20%2B%20agentbox%2Fsandbox_desktop.py%23extract_novnc%2F_NOVNC_LOCK%20%2B%20agentbox%2Ftemplates%2Fsandbox.html%20%283%20s%20poll%29::Resource%20exhaustion%3A%20lock%20contention%20and%20pre-authentication%20work%20imbalance` (owner h-locks-ws)
- `Browser-origin%20checks%20on%20cookie-authenticated%20routes%3A%20api.py%20same_origin%20%28api.py%3A221-223%29%20used%20by%20screen_principal%20%28api.py%3A235%2C%20every%20%2Fui%20and%20screen%20route%29%2C%20the%20login%2Fticket%20handlers%20%28web.py%3A159%2C169%29%20and%20the%20desktop%20WebSocket%20upgrade%20%28api.py%3A442%29%3B%20a%20missing%20Origin%20header%20is%20accepted::Cross-site%20or%20downgraded-scheme%20browser%20request%20to%20human%20authority%3A%20same_origin%20compares%20only%20urlsplit%28origin%29.netloc%20to%20the%20Host%20header%2C%20with%20no%20scheme%20check%2C%20and%20treats%20an%20absent%20Origin%20as%20same-origin.%20Behind%20a%20TLS%20proxy%20with%20forwarded_allow_ips%3D%27%2A%27%20a%20plain-HTTP%20origin%20on%20the%20same%20host%20passes.%20This%20is%20run-4%20N1%20%28needs_validation%2C%20source%20unchanged%29%20and%20no%20run-5%20unit%20owns%20it.%20The%20WS%20and%20body-cap%20units%20excluded%20CLIENT-SIDE.md%23Cross-site%20WebSocket%20request%20use%20by%20pointing%20to%20an%20%27existing%20h-session%20unit%27%20that%20is%20not%20in%20this%20ledger.::agentbox%2Fapi.py%23same_origin%2Fscreen_principal%2Fdesktop_ws%20%2B%20agentbox%2Fweb.py%20login%20and%20ticket%20routes%20%2B%20agentbox%2Fdesktop.py%20cookie%20attributes%20%28SameSite%2C%20Secure%2C%20scope%29%20%2B%20deploy%2FCaddyfile%20Host%2FOrigin%20forwarding::Cross-site%20WebSocket%20and%20cross-origin%20request%20forgery%20against%20cookie%20sessions%20%28scheme%20and%20missing-Origin%20gaps%29` (owner h-origin)
- `Completeness%20of%20the%20PR%20%2319%20control-character%20filter%20at%20its%20sinks%3A%20display.escape_controls%20%28Cc%2FCf%2FZl%2FZp%20via%20unicodedata%29%20applied%20through%20Jinja%20finalize%20web._shown%20and%20cli._safe%2C%20versus%20sinks%20that%20bypass%20finalize%20or%20_safe::Agent-%20or%20container-controlled%20strings%20shown%20to%20the%20human.%20Check%3A%20non-str%20values%20%28Markup%2C%20dict%20or%20list%20reprs%29%2C%20tojson%20or%20attribute%20contexts%20%28hx-confirm%2C%20title%29%2C%20the%20desktop%20page%20D.page%20HTMLResponse%2C%20JSON%20error%20detail%20rendered%20by%20htmx%2C%20and%20CLI%20prints%20without%20_safe%20%28cli.py%3A166%20source_dir%2C%20cli.py%3A187%20sandbox_id%2Fcreated_at%2C%20cli.py%3A315%20verify%20reason%2C%20cli.py%3A337%20snapshot%20reason%29.%20Also%20categories%20left%20unescaped%20%28Co%2C%20Cn%2C%20Cs%2C%20Mn%20combining%20marks%2C%20tag%20characters%29.::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%23_shown%2Fdescribe%2F_short%20%2B%20agentbox%2Fcli.py%23_safe%20and%20print%20sites%20%2B%20agentbox%2Ftemplates%2F%2A.html::Terminal%20and%20display%20injection%20through%20untrusted%20strings%20%28output%20sink%20completeness%29` (owner h-display)
- `Container%20identity%20binding%20of%20the%20F2%20GUI-input%20gate%3A%20GuiBursts.covers%20%28gui_bursts.py%3A68-71%29%20checks%20only%20%27sid%20in%20_gui_burst%27%2C%20called%20from%20_run_tool%20under%20gui_lock%20%28service.py%3A145%29%2C%20versus%20burst%5B%27container_id%27%5D%20set%20in%20open%28%29%20and%20the%20restore%2Fdelete%20path::Agent%20GUI%20input%20to%20the%20burst-based%20change%20recorder%20after%20restore%3A%20a%20burst%20opened%20on%20the%20pre-restore%20container%20can%20satisfy%20covers%28%29%20for%20an%20input%20that%20runs%20on%20the%20restored%20container%2C%20so%20no%20stray%20kill%20or%20gui_changes%20applies%20and%20the%20started%20processes%20join%20the%20next%20baseline.%20h-lifecycle%20recorded%20this%20as%20hardening%2C%20and%20its%20only%20candidate%20was%20rejected%20on%20a%20different%20claim.%20The%20PR%20%2317%20gate%20has%20no%20unit%20that%20reproduces%20or%20refutes%20this%20schedule.::agentbox%2Fgui_bursts.py%23covers%2Fopen%2Fend%2Freset_timers%20%2B%20agentbox%2Fservice.py%23_run_tool%2F_snapshot%2Frestore_sandbox::Race%20and%20check-then-act%20on%20security-control%20state%20%28container%20identity%20across%20restore%29` (owner h-gui-burst)
- `Container%20output%20readers%20that%20fully%20buffer%20attacker-controlled%20bytes%3A%20sandbox.py%20exec_run%20without%20a%20read%20cap%20or%20container-side%20timeout%20%28list_dir%20ls%20-la%20%3A442%2C%20exists%20%3A475%2C%20delete%20%3A497%2C%20outbox_list%20find%20-printf%20%3A548%2C%20is_dir%20%3A537%2C%20plus%20_expand%20glob%20%3A578%20and%20_walk%20find%20-print0%20%3A584%20which%20gained%20_PREVIEW_TIMEOUT%20in%20PR%20%2324%29%20versus%20the%20capped%20_Head%20exec%20path%20%28%3A85%2C%3A427%29::Agent-owned%20container%20filesystem%20output%20to%20control-plane%20memory%20and%20tool_pool%2Frequest%20threads.%20An%20agent%20can%20create%20millions%20of%20names%2C%20deep%20trees%20or%20huge%20glob%20matches%2C%20so%20a%20human-triggered%20or%20preview-triggered%20listing%20buffers%20an%20unbounded%20demux%20result%20in%20the%20single%20control-plane%20process.%20Run-4%20N3%20%28needs_validation%2C%20not%20re-hunted%29.%20The%20h-xres%20and%20h-policy-cpu%20units%20excluded%20Unbounded%20buffering%20and%20cardinality%20citing%20N3%2C%20so%20no%20unit%20owns%20it%2C%20and%20PR%20%2318%20changed%20_expand%2F_walk%20%28NUL-separated%20output%2C%20head%20-z%29%20without%20a%20reader-cap%20review.::agentbox%2Fsandbox.py%23list_dir%2Fexists%2Fdelete_file%2Foutbox_list%2Fis_dir%2F_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fsandbox_common.py%23_timed%20%2B%20agentbox%2Fsandbox_desktop.py%23_x%2Fdesktop_processes%20%2B%20agentbox%2Fpreview.py::Unbounded%20buffering%20and%20cardinality%20of%20container-controlled%20output` (owner h-readers)
- `DesktopControl%20lock%20split%20%28_db_lock%20vs%20_lock%2C%20desktop.py%3A90-305%29%2C%20desktop%20WebSocket%20threadpool%20offload%20and%20shielded%20disconnect%20logging%20%28api.py%3A441%2C%20desktop_ws.py%3A19-24%2C%2076%2C%2093-113%29%2C%20and%20retention.prune%20post-COMMIT%20archive%20preservation%20%28retention.py%3A104-145%29::Event-loop%20responsiveness%2C%20lock%20ordering%20and%20archive%20durability%20%28PR%20%2324%20fixes%20for%20run-5%20F3%20and%20F4%29%3A%20DesktopControl%20separates%20_db_lock%20%28SQLite%29%20from%20_lock%20%28in-memory%20leases%2Fconns%2Fgui_locks%29%20with%20lock%20order%20_db_lock%20-%3E%20_lock%3B%20desktop_ws%20and%20relay%20run%20SQLite%2C%20Docker%20vnc_command%20and%20audit%20logging%20in%20threadpools%20and%20shield%20disconnect%20logging%20before%20drop_conn%3B%20retention.prune%20checks%20audit_anchor%20before%20unlinking%20the%20archive%20on%20exception.%20Invariant%3A%20no%20WebSocket%20or%20desktop%20path%20blocks%20the%20asyncio%20event%20loop%20on%20SQLite%20or%20Docker%2C%20no%20method%20violates%20_db_lock%20-%3E%20_lock%20ordering%20or%20exposes%20inconsistent%20lease%2Fsession%20state%20across%20the%20two%20locks%2C%20and%20no%20failure%20after%20COMMIT%20in%20prune%20deletes%20a%20referenced%20archive.::agentbox%2Fdesktop.py%23DesktopControl%20%2B%20agentbox%2Fdesktop_ws.py%23relay%20%2B%20agentbox%2Fapi.py%23desktop_ws%20%2B%20agentbox%2Fretention.py%23prune::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Worker%2C%20pool%2C%20and%20priority%20starvation` (owner h-locks-ws)
- `Docker%20data-root%20growth%20that%20AgentBox.disk_low%20does%20not%20measure%3A%20container%20writable%20layers%20%28AGENTBOX_DISK%20default%20empty%20so%20no%20storage_opt%29%2C%20docker%20commit%20snapshot%20images%20%28snapshot_quota%2050%20per%20sandbox%2C%20unlimited%20sandboxes%29%2C%20and%20the%20exec%2Fwrite_file%20calls%20that%20an%20admitted%20call%20can%20run%20for%20up%20to%20exec_timeout::Agent%20to%20host%20disk%20outside%20the%20guard%3A%20disk_low%20checks%20shutil.disk_usage%28db_path.parent%29%20only%20%28service.py%3A395%29%2C%20while%20the%20growth%20lands%20in%20the%20Docker%20root.%20When%20DB%20and%20Docker%20root%20are%20on%20different%20filesystems%2C%20or%20one%20admitted%20exec%20fills%20the%20layer%2C%20the%20507%20guard%20never%20trips.%20h-approvals%20recorded%20this%20only%20as%20hardening%20and%20did%20not%20test%20per-sandbox%20or%20aggregate%20snapshot%20disk.::agentbox%2Fservice.py%23disk_low%2Fcall_tool%20%2B%20agentbox%2Fsandbox.py%23_run_container%2Fsnapshot%2Fwrite_file%20%2B%20agentbox%2Fconfig.py%23disk_limit%2Fmin_free_bytes%2Fsnapshot_quota%20%2B%20deploy%2Fdocker-compose.yml%20volume%20layout::Quota-accounting%20scope%20and%20reset%20gaps%20%28disk%20accounting%20measured%20on%20the%20wrong%20filesystem%29` (owner h-readers)
- `GUI%20burst%20opening%20and%20approval%20execution%20against%20human%20takeover%20leases%20%28PR%20%2324%29%3A%20AgentBox._snapshot%20burst%20open%20under%20gui_lock%20with%20_check_control%20and%20reset_timers%20%28service.py%3A265-284%29%2C%20call_tool%20_human_blocked%20handler%20%28service.py%3A396-397%2C%20411-419%29%2C%20and%20decide%20pre-snapshot%20lease%2F_takeover_pending%20gate%20%28service.py%3A498-514%29::Agent%20GUI%20burst%20isolation%20from%20human%20takeover%20sessions%20%28PR%20%2324%20fix%20for%20run-5%20F2%29%3A%20_snapshot%20acquires%20gui_lock%20and%20calls%20_check_control%20before%20mark_snapshot%2Fbursts.open%2C%20resetting%20burst%20timers%20and%20raising%20HumanControl%20after%20recording%20the%20snapshot%20if%20a%20lease%20or%20takeover%20is%20pending%3B%20decide%20refuses%20approved%20GUI_INPUT%20before%20_snapshot%20when%20a%20lease%20is%20active%20or%20takeover%20is%20pending.%20Invariant%3A%20no%20agent%20GUI%20burst%20can%20be%20opened%20or%20remain%20open%20while%20a%20human%20takeover%20lease%20is%20held%20or%20pending%2C%20no%20human-started%20process%20is%20killed%20by%20close_idle%2Fnext_burst%2C%20and%20no%20lock%20ordering%20cycle%20exists%20between%20_snap_locks%2C%20gui_lock%2C%20and%20_lifecycle.::agentbox%2Fservice.py%23_snapshot%2Fcall_tool%2F_call_tool%2F_human_blocked%2Fdecide%2Ftakeover%20%2B%20agentbox%2Fgui_bursts.py%23needs_snapshot%2Fopen%2Fclose%2Freset_timers%2Fcovers::DESKTOP-MOBILE-AND-LOCAL-IPC.md%23Privileged%20helper%20as%20confused%20deputy` (owner h-gui-burst)
- `Pre-read%20credential%20gate%20in%20_BodyLimit%20%28api.py%3A85-96%2C%20authenticated%20at%20api.py%3A185-199%29%2C%20%2Flogin%2064%20KiB%20anonymous%20body%20cap%20%28_ANON_BODY_PATHS%2F_ANON_BODY_MAX%2C%20api.py%3A53-54%29%2C%20Caddy%20per-route%20request_body%20%28%40upload%20vs%20%40other%2C%20deploy%2FCaddyfile%3A8-15%29%2C%20compose%20mem_limit%20%28deploy%2Fdocker-compose.yml%3A20%29%2C%20and%20uvicorn%20limit_concurrency%20%28config.py%3A68%2C%20cli.py%3A126-127%29::Pre-authentication%20body-read%20and%20memory%20amplification%20after%20PR%20%2325%20%28run-5%20N1%20fix%29%3A%20_BodyLimit%20checks%20has_body%20%28Content-Length%20%3E%200%20or%20Transfer-Encoding%20present%29%2C%20caps%20%2Flogin%20at%2064%20KiB%2C%20and%20for%20every%20other%20body-carrying%20request%20runs%20authenticated%28headers%29%20in%20the%20threadpool%20before%20letting%20the%20app%20read%20or%20decode%20any%20bytes%2C%20returning%20401%20when%20neither%20a%20valid%20Bearer%20token%20%28human%20or%20live%20agent%29%20nor%20a%20valid%20session%20cookie%20%28SimpleCookie%20D.COOKIE%20with%20session_scope%29%20is%20present.%20Invariant%3A%20an%20unauthenticated%20client%20cannot%20make%20the%20control%20plane%20read%2C%20buffer%2C%20JSON-parse%20or%20multipart-spool%20more%20than%2064%20KiB%2C%20or%20bypass%20the%20credential%20gate%20via%20HTTP%20framing%2C%20header%20casing%2Fduplication%2C%20path%20variations%20or%20cookie%20parsing.::agentbox%2Fapi.py%23_BodyLimit%2F_ANON_BODY_PATHS%2Fauthenticated%20%2B%20agentbox%2Fconfig.py%23max_connections%20%2B%20agentbox%2Fcli.py%23cmd_serve%20%2B%20deploy%2FCaddyfile%20%2B%20deploy%2Fdocker-compose.yml::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Pre-authentication%20work%20imbalance` (owner h-origin)

# Your paths, sandbox and result contract

- Agent ID: `h-preview-argcap`. Audited source (read-only): `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` (git worktree of main at 530b29e). Read it with read_file or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/h-preview-argcap/scratch/`. Retained artifacts: `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/h-preview-argcap/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" h-preview-argcap <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target). Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest are importable). Write `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/h-preview-argcap/scratch/h.py`, then run `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" h-preview-argcap /usr/bin/sh -c "/usr/bin/python3 /scratch/h.py > /scratch/h.out 2>&1"`. Unit tests (cwd must be /target; pass --capture=sys): `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" h-preview-argcap /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/h-preview-argcap/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
- Contract check: for EVERY unit in `"units"`, `unit["reviewed_paths"]` MUST equal the exact sorted set union of `c["reviewed_paths"]` across all `c` in `unit["checks"]`.
- Time box: aim to finish within roughly 30 tool calls. Stop each line of investigation as soon as the invariant is settled.
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
