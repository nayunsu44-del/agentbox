You are final record verifier `r11` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
 "title": "The shared control-character filter misses U+061C - the only Unicode Bidi_Control code point it omits - plus the Cf/Zl/Zp invisibles, and the approval card renders them raw beside the argv that will execute",
 "description": "Source and a local render confirm a residual gap in the run-3 fix, but not its security outcome. web._shown (web.py:33-37) sends every template output through display.escape_controls with keep_newlines=True (web.py:94), and that class does neutralise the run-3 payloads: rendering the real _approvals.html through web.py's exact Jinja wiring turns U+200E/U+200F/U+202A-E/U+2066-9 into literal \\uXXXX escapes while markupsafe escapes markup. The class is hand-written (display.py:13,15) and covers 11 of the 12 Unicode Bidi_Control characters: U+061C ARABIC LETTER MARK is absent, and so are U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029. Measured in the approved sandbox, all of them survive raw in both the command <pre> and the affected-path cell of the same card, and cli._safe (cli.py:33-35) is byte-identical, so the terminal approval view carries the same gap rather than disagreeing with the web view. What is not established is whether any of them lets the card read as a different command in the operator's browser. U+061C is bidi class AL, a strong right-to-left character, not an isolate: on its own it cannot reverse a run of ASCII letters (they stay strong L), and its bidi effect is limited to the resolved direction of adjacent neutral punctuation sitting between two of them. U+2028/U+2029 are mandatory line breaks that would split one argv into two visual lines inside the same pre block without hiding either line, and the remaining characters are invisible rather than reordering. That leaves a display-integrity question whose answer lives in the renderer, which no surface in this audit can observe.",
 "claimed_root_cause": "display.py:13 and display.py:15 enumerate the control and bidi characters by hand. The set is C0/C1 plus exactly Bidi_Control minus U+061C, so ALM (Bidi_Control=Yes, bidi class AL) together with the Cf invisibles U+200B-200D, U+2060, U+FEFF, U+00AD and the separators U+2028/U+2029 pass through. web._shown applies that class to every str template output (web.py:35-36, 94) and cli._safe applies it to the terminal view (cli.py:35), so both human surfaces share the residual gap; nothing else filters those characters on the path from the stored approval args to the card.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "call_tool (POST /sandboxes/{sid}/tools/{tool}, agent token)",
   "description": "The lowest-trust agent principal posts an exec call whose args.command it chooses; policy.decide routes a non-allowlisted program to approval, and nothing normalises or rejects unusual code points in the string."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 324,
   "scope": "call_tool REQUIRE_APPROVAL branch",
   "description": "The approval is created with the agent's original args dict and the system preview (service.py:318; preview adds no affected paths for a plain echo/python3 command). approvals.py:56 persists the args with json.dumps(ensure_ascii=False), so the code points are stored as bytes the card will show and service.py:398/421 later executes."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 208,
   "scope": "approvals_view",
   "description": "Pending approvals, including the original args and the system-computed preview paths, are listed and rendered into _approvals.html by the same view that serves both GET /ui/approvals and the approve/deny POST handlers."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 94,
   "scope": "tpl.env.finalize = _shown",
   "description": "finalize runs _shown over every output expression, which applies escape_controls(value, keep_newlines=True) to str values only (web.py:33-37); no template uses |safe or Markup, so this hand-written class is the entire filter for the card."
  },
  {
   "kind": "sink",
   "file": "agentbox/templates/_approvals.html",
   "line": 8,
   "scope": "exec command <pre> (and the affected-path cell at line 14)",
   "description": "The command is emitted into <pre> without short(), so only autoescape plus display.py:13/15 apply. Locally rendered with U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029 placed in the command and in an affected path, every one of them reaches the HTML raw in both cells while U+200E/U+200F/U+202A-E/U+2066-9 come out as visible \\uXXXX escapes."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/display.py",
   "line": 13,
   "description": "UNSAFE is [\\x00-\\x1f\\x7f-\\x9f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]. Tested in the sandbox against the 12 code points with Bidi_Control=Yes: it matches 11 of them and does not match U+061C; it also does not match U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 or U+2029."
  },
  {
   "file": "agentbox/display.py",
   "line": 15,
   "description": "_UNSAFE_KEEP_NEWLINES, the variant the web UI actually uses, repeats the same class minus tab/newline, so the U+061C and Cf/Zl/Zp omissions are identical on the web path."
  },
  {
   "file": "agentbox/web.py",
   "line": 35,
   "description": "_shown returns non-str values unchanged and calls escape_controls(value, keep_newlines=True) for str; a direct escape_controls call leaves U+061C, U+200B, U+200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029 unchanged in both keep_newlines modes while escaping U+200E/U+200F/U+202A-E/U+2066-9."
  },
  {
   "file": "agentbox/web.py",
   "line": 94,
   "description": "tpl.env.finalize = _shown is the only string filter registered for the web templates (filters['short'] is added at line 93), so the card's command and path cells depend entirely on the display.py class plus markupsafe autoescape."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 8,
   "description": "The exec command is emitted into <pre> with no short() and no filter; in the local render the markup payload was escaped ('&lt;script&gt;') and the run-3 bidi set became literal escapes, while U+061C/U+200B/U+2028 stayed raw."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 14,
   "description": "Container-derived affected paths are rendered by the same finalize; the local render shows the same nine code points raw inside the path cell, so the second human-facing string on the card is equally unfiltered."
  },
  {
   "file": "agentbox/cli.py",
   "line": 35,
   "description": "cli._safe is escape_controls(str(s), keep_newlines=False); measured on the same command its output is byte-identical to web._shown, so the terminal approver shares the omission and there is no web-only asymmetry left to exploit."
  },
  {
   "file": "agentbox/service.py",
   "line": 126,
   "description": "exec runs str(args.get('command','')) from the approval row loaded at service.py:398 and executed at service.py:421, so the argv keeps the exact code points the card displayed; only the display side is filtered."
  },
  {
   "file": "docs/security-audit/run-3/findings.json",
   "line": 363,
   "description": "Calibration: the run-3 remediation text for the shared class already listed 'Optionally add U+061C to _UNSAFE', so the ALM omission was known and deliberately left optional; this record is that follow-through, not a re-opened run-3 isolate spoof."
  }
 ],
 "blockers": [
  "No browser or terminal renderer is reachable from the approved sandbox (python3 plus the repo and jinja2/fastapi only, no network, no display), so the rendered order of the residual code points cannot be observed. The local run proves the reachability half only: U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029 arrive raw in the card's <pre> and path cell while the argv executed by service.decide (service.py:398,421 -> service.py:126) keeps the same code points.",
  "The decisive fact is whether a residual code point makes the card read as a different command. U+061C is bidi class AL, a strong right-to-left character that cannot reverse ASCII letter runs; U+2028/U+2029 add a mandatory break inside the same pre block but hide nothing; U+200B-200D/U+2060/U+FEFF/U+00AD are invisible and only affect how individual characters join. Which of these, if any, yields a misstatement depends on the browser engine, the resolved base direction and the font stack, none of which the repository pins (base.html:23 sets white-space: pre-wrap and no unicode-bidi isolation).",
  "Which browser engine versions, fonts and terminal emulator the operator actually uses is unknown to this audit, and that choice decides whether ALM and the separator characters produce any visible difference between the approved view and the executed command."
 ],
 "validation_plan": {
  "local": "Already done in this run (artifact v12bidi.out): a per-code-point table (unicodedata.category, unicodedata.bidirectional, UNSAFE/_UNSAFE_KEEP_NEWLINES match) plus a render of the real _approvals.html through web.py's exact wiring (Jinja2Templates over agentbox/templates, env.finalize = web._shown, env.filters['short'] = web._short) with a command and an affected path carrying every candidate code point and an inline script tag. Result: U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028, U+2029 raw in both cells; U+200E/U+200F/U+202A-E/U+2066-9 as literal escapes; markup escaped; cli._safe output byte-identical to web._shown. Next, still offline with dummy data: render the same fragment from a loopback static file in a local browser engine (Playwright Chromium, Firefox, WebKit) and capture the rendered line/baseline order of the pre block for payloads built only from the residual set - (a) echo 'x' + ALM + ';>' + ALM + ' ; python3 /workspace/job.py', (b) the same command with U+2028 placed before the trailing echo, (c) a ZWSP inside one option token - then compare each capture with the argv string and record whether the card states a different command. Regression, worth doing regardless of the browser result: add U+061C to both regexes in display.py plus the Cf/Zl/Zp invisibles (keeping tab/newline in the keep_newlines variant) and add a test asserting escape_controls neutralises U+061C, U+200B and U+2028 in both modes; grep shows no test currently exercises this class.",
  "deployment": "Owner-side and non-destructive: on a dummy sandbox, queue one pending exec approval whose command contains two ALMs around a ';' and a U+2028 between two shell commands, open /ui/approvals in the operator's real browser and the same request in the terminal 'agentbox approve' view, and compare what is rendered with the exact argv returned by GET /approvals/{aid} (or the audit 'tool_execute' args). No probing of live endpoints beyond the owner's own instance."
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

<!-- AI-AND-LLM.md#Insecure output rendering -->
**Insecure output rendering**
Model output reaches an executing HTML, Markdown, template, URL, or command sink without the sink's required encoding and policy. For browser rendering, verify auto-loaded resources and CSP or sanitization in `CLIENT-SIDE.md`; renderer behavior outside the repository makes the candidate `needs_validation`.

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

<!-- CLIENT-SIDE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A client-side candidate needs a controllable source and an executing or disclosing sink. Name both and show attacker-influenced data reaching the sink.
- The impact must reach a victim's session, another origin, or shared persistence. Self-injection and disclosure of the attacker's own data are not findings.
- Framework escaping, browser same-origin policy, CSP, COOP/CORP, service-worker scope, and modern noopener defaults are real controls. Verify them before assigning impact.
- Browser storage and caches are shared by origin and may outlive login state. Identify who writes, who reads, and which account, tenant, or worker lifecycle clears each record.
- Use `confirmed` only for complete source evidence plus bounded local browser tests. Use `needs_validation` when renderer, extension permission, deployed header, or browser-policy behavior is required but unavailable.
```

<!-- CLIENT-SIDE.md#DOM-based XSS -->
**DOM-based XSS**
Trace `location` fields, `document.referrer`, `window.name`, message data, storage, and browser-controlled document state into `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs, executable URLs, jQuery HTML APIs, or framework escape hatches. Interpolation escaped by the framework is not a finding.

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

# Execution boundary and paths

- Agent ID `r11`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r11/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r11 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r11 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
