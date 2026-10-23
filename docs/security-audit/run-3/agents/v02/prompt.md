You are candidate verifier `v02` in a defensive security audit of agentbox (target /home/user/agentbox, read-only, commit 8e4db9e on main; agentbox/ identical to 0e4b958).


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
 "fingerprint": "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines",
 "title": "The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view",
 "description": "The web UI audit fragment and the `agentbox audit` CLI fetch rows with AuditLog.list(limit=5000) and no after_id. AuditLog.list orders by id ascending, so it returns the oldest 5000 rows. The UI shows the last 400 of those (ids 4601-5000); the CLI prints rows 1-5000. Every later event is never shown: tool_request/tool_result, gui_changes, gui_processes_stopped, tool_blocked, human_takeover/handback. UI: per sandbox; default CLI: whole system. The UI footer still says 'most recent 400 of 5000'. A prompt-injected agent can create 5000 rows for its own sandbox with no approval and no Docker work (one approval_forbidden row per POST /approvals/{anything}, or three rows per allowed `exec true`/list_dir), after which its later activity, including gui_changes (the detection record for the ungated GUI path), drops out of the human's timeline. Rows stay in the DB and verify passes, but the views humans use stop updating. Long ordinary sessions hit the same limit.",
 "root_cause": "AuditLog.list implements 'WHERE id > after_id ORDER BY id LIMIT n' (oldest first). web.py audit_frag and cli.py cmd_audit call it with limit=5000 and no after_id, then take the tail of the oldest window (rows[-400:]) or print it whole; total is len(rows), capped at 5000.",
 "intended_behavior": "The UI timeline described as 'recent N' and the CLI timeline show the newest audit events with the real total; agent-created volume must not hide later events from oversight views.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 241,
   "scope": "decide (POST /approvals/{aid})",
   "description": "An agent token calling POST /approvals/{any id} is refused, but each attempt is recorded first. Allowed tool calls also add rows (service.py:297 tool_request + policy_decision + tool_result)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 245,
   "scope": "decide",
   "description": "audit.append(event=\"approval_forbidden\", sandbox_id=p.sandbox_id): one row per request, no rate limit, no tool_pool, no Docker."
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 196,
   "scope": "AuditLog.list",
   "description": "'WHERE id > ? [AND sandbox_id = ?] ORDER BY id LIMIT ?' returns the oldest rows first."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 262,
   "scope": "audit_frag",
   "description": "rows = box.audit.list(sandbox_id=sandbox_id, limit=5000): oldest 5000, no after_id."
  },
  {
   "kind": "sink",
   "file": "agentbox/web.py",
   "line": 263,
   "scope": "audit_frag",
   "description": "render(_audit.html, rows=rows[-400:][::-1], total=len(rows)) shows ids 4601-5000, total 5000; newer events never rendered."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 196,
   "description": "' ORDER BY id LIMIT ?': ascending, so a limit keeps the oldest rows."
  },
  {
   "file": "agentbox/web.py",
   "line": 263,
   "description": "UI takes the tail of the oldest-5000 window and reports total as len(rows)."
  },
  {
   "file": "agentbox/templates/_audit.html",
   "line": 10,
   "description": "Footer '최근 {{ rows|length }}개만 표시 (전체 {{ total }}개)' is false beyond 5000 rows."
  },
  {
   "file": "agentbox/cli.py",
   "line": 258,
   "description": "cmd_audit requests /audit with limit=5000 and no after_id/paging; without --sandbox it is system-wide."
  },
  {
   "file": "agentbox/templates/sandbox.html",
   "line": 19,
   "description": "The sandbox page polls /ui/audit?sandbox_id=… every 3 s: the live oversight view."
  },
  {
   "file": "agentbox/default_policy.yaml",
   "line": 23,
   "description": "read-only-exec allows `true` and `ls`; list_dir is default-allowed."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Attacker holds an agent token for its own sandbox (prompt-injected agent)."
  },
  {
   "kind": "data_state",
   "description": "The sandbox (or system, for the default CLI) has more than 5000 audit rows; agent-causable, and long ordinary sessions reach it."
  },
  {
   "kind": "user_interaction",
   "description": "The human relies on the web UI timeline or `agentbox audit` rather than paging /audit with after_id."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent with its sandbox's agent token wants its later GUI/exec activity and the resulting gui_changes and gui_processes_stopped records to stay out of the human's timeline.",
  "payloads": [
   "5100 x AuditLog.append(actor='agent', event='tool_request', sandbox_id='sb_dummy', tool='exec', payload={'args': {'command': 'ls #i'}}), then one gui_changes row deleting /workspace/important.txt (stands in for agent-driven POST /approvals/x or allowed `exec true` calls)",
   "GET /ui/audit?sandbox_id=sb_dummy against web.register(...) with a stub box whose .audit is the real AuditLog"
  ],
  "instructions": [
   "In sbx (no network, no Docker), create a real agentbox.audit.AuditLog in scratch and append 5100 dummy tool_request rows for 'sb_dummy', then one gui_changes row (id 5101).",
   "Stub fastapi.templating to record the template context (jinja2 absent in sbx); call the real agentbox.web.register on a FastAPI app with a stub box (audit=real log, close_idle_gui_bursts no-op) and stub human principal.",
   "GET /ui/audit?sandbox_id=sb_dummy with TestClient; inspect row ids and total; also call log.list(sandbox_id=None, after_id=0, limit=5000), the CLI query.",
   "Command: sbx h-audit /usr/bin/python3.13 /scratch/h.py (512 MiB, 1 CPU, 64 pids, 120 s, uid 65534, no network)."
  ],
  "observed_result": "status 200, template _audit.html, rows passed: 400, max id 5000, min id 4601, total 5000. Latest id 5101 and the gui_changes event not in UI rows. Footer would read '최근 400개만 표시 (전체 5000개)'. CLI/API default query: ids 1..5000. verify() ok=True over 5101 rows."
 },
 "remediation": {
  "strategy": "Fetch the newest N rows for the UI (ORDER BY id DESC LIMIT N, reversed as needed) and report the real total from COUNT(*). Make the CLI page with after_id until no rows remain, or default to newest. Regression test: append 5100 rows; GET /ui/audit renders id 5100 with total 5100; cmd_audit's fetch includes id 5100.",
  "code_changes": [
   {
    "file_name": "agentbox/audit.py",
    "fixed_code": "    def recent(self, sandbox_id=None, limit=400):\n        where, args = (\" WHERE sandbox_id = ?\", [sandbox_id]) if sandbox_id else (\"\", [])\n        with self._lock:\n            total = self.conn.execute(\"SELECT COUNT(*) FROM audit\" + where, args).fetchone()[0]\n            rows = self.conn.execute(\"SELECT ... FROM audit\" + where + \" ORDER BY id DESC LIMIT ?\", args + [limit]).fetchall()\n        return [...], total"
   },
   {
    "file_name": "agentbox/web.py",
    "fixed_code": "        rows, total = box.audit.recent(sandbox_id=sandbox_id, limit=400)\n        return render(request, \"_audit.html\", rows=rows, total=total, broken=None)"
   },
   {
    "file_name": "agentbox/cli.py",
    "fixed_code": "        rows, after = [], 0\n        while True:\n            page = _check(c.get(\"/audit\", params=params | {\"limit\": 5000, \"after_id\": after}))\n            if not page:\n                break\n            rows += page\n            after = page[-1][\"id\"]"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "No approval needed: ~5000 approval_forbidden requests (pure DB appends) or ~1700 allowed `exec true` calls reach the limit; long ordinary sessions cross it too."
  },
  "impact": {
   "score": "medium",
   "reason": "The live UI timeline and CLI timeline stop showing new events (CLI: system-wide) while claiming to show the most recent, hiding later agent executions and the gui_changes/stray-kill records that are the only detection layer for the ungated GUI path. Rows stay in the DB, /audit with after_id returns them, verify passes, the approval queue is unaffected."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Real AuditLog and real web.py route produced the truncated window in a bounded local run; CLI query shape identical; row-creating paths visible in source."
 }
}
```


# Independent duplicate report of the same root cause by another hunter

[
 {
  "x_duplicate_from": "h-wild",
  "x_duplicate_fingerprint": "agentbox/audit.py:list:ascending-limit-readers-show-oldest-rows-as-recent",
  "x_note": "h-wild proposed confirmed (medium): real build() app, 1701 allowed list_dir calls -> 5103 rows; /ui/audit ids 4601-5000 total 5000; /audit?limit=5000 ids 1-5000; artifact agents/h-wild/artifacts/h_audit.out"
 }
]

# Linked coverage-unit checks

[
 {
  "coverage_id": "agent-controlled%20audit%20content%20%28tool%20args%2C%20file%20names%2C%20process%20args%29::agentbox%2Faudit.py%23hash%20chain%20%2B%20append-only%20triggers%20%2B%20event%20provenance::agentbox%2Faudit.py::ATTACK-CLASSES.md%23Business%20logic",
  "local_checks": [
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/web.py",
     "agentbox/cli.py",
     "agentbox/api.py",
     "agentbox/templates/_audit.html"
    ],
    "invariant": "Human audit timelines (web UI /ui/audit and `agentbox audit` CLI) show the newest events, so an agent cannot push its later actions out of view by creating rows",
    "method": "local",
    "result": "Fails. AuditLog.list orders by id ascending with LIMIT; both readers ask limit=5000 with no after_id. After 5101 rows for one dummy sandbox, the real web.py audit_frag route (Jinja stubbed) passed ids 4601..5000 with total=5000; newest row 5101 (gui_changes) not shown; footer claims 'most recent 400 of 5000'. Default CLI/API query returned ids 1..5000. Agent creates rows without approval: approval_forbidden (api.py:245, 1 row per request, no Docker) or allowed exec true / list_dir (3 rows per call).",
    "artifact": "agents/h-audit/artifacts/h.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/audit.py"
    ],
    "invariant": "Agent-supplied JSON cannot make verify() report a false break",
    "method": "local",
    "result": "Holds. NaN, Infinity, -0.0, 1e308, 2**200, bidi, nested lists, null, bool round-trip; verify ok. Lone surrogate or >4300-digit int make append raise UnicodeEncodeError/ValueError (not AuditWriteError); nothing inserted; tool_request path fails closed before policy. Container output decoded with errors='replace'.",
    "artifact": "agents/h-audit/artifacts/h.out"
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/web.py",
     "agentbox/cli.py",
     "agentbox/templates/_audit.html",
     "agentbox/service.py"
    ],
    "invariant": "Agent-controlled args, file names, process args cannot render as another event/actor/row or crash rendering",
    "method": "source",
    "result": "Holds. Event, actor, tool are system-set (tool must be in TOOLS, service.py:293-294). Agent text only in the detail cell: UI via describe/_short + autoescape, CLI via _safe. payload.session not agent-settable.",
    "artifact": null
   },
   {
    "agent_id": "h-audit",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/api.py"
    ],
    "invariant": "An agent cannot modify, delete or reorder audit rows",
    "method": "source",
    "result": "Holds against the agent: append is the only writer (BEGIN IMMEDIATE + lock), UPDATE/DELETE triggers abort, /audit and /audit/verify human_only. Unkeyed chain only defends against non-DB-holders (hardening).",
    "artifact": null
   }
  ]
 },
 {
  "coverage_id": "whole-repo%23undocumented%2Fedge%20surfaces::whole-repo%23feature%20interactions%20not%20covered%20by%20other%20units::whole-repo::ATTACK-CLASSES.md%23Wildcard",
  "local_checks": [
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/api.py",
     "agentbox/web.py",
     "agentbox/sandbox.py",
     "tests/test_m2_acceptance.py"
    ],
    "invariant": "GUI burst bookkeeping stays consistent across restore and pause/resume.",
    "method": "local",
    "result": "Real AgentBox + fake SandboxManager: control burst kills a mid-burst stray and logs gui_changes. After restore, _gui_input_at/_gui_snap_at kept; first post-restore GUI input opens no burst; gap stray absorbed into the next baseline [1,10,60], never killed; gap change never logged. Pause: idle close pops the burst, desktop_processes fails, stray not killed, no gui_changes; next baseline [1,10,70].",
    "artifact": "agents/h-wild/artifacts/h_burst.out"
   },
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/web.py",
     "agentbox/cli.py",
     "agentbox/api.py",
     "agentbox/templates/_audit.html",
     "agentbox/templates/sandbox.html"
    ],
    "invariant": "Human audit surfaces show the newest events.",
    "method": "local",
    "result": "Real build() app (fake Docker manager/templates): 1701 allowed list_dir calls -> 5103 rows; /ui/audit shows ids 4601-5000, total 5000; GET /audit?limit=5000 returns 1-5000; marker row (id>5000) absent. Same root cause as h-audit's candidate.",
    "artifact": "agents/h-wild/artifacts/h_audit.out"
   },
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "Unauthenticated /static/novnc cannot traverse, extract attacker content or repeatedly create containers.",
    "method": "source",
    "result": "Extracts from the operator image with filter='data', resolve()+is_relative_to; repeated create/remove only if the image lacks noVNC. Hardening.",
    "artifact": null
   },
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/sandbox.py",
     "agentbox/approvals.py"
    ],
    "invariant": "Delete/restore/pause/restart with pending or claimed approvals cannot execute against an unintended container or bypass claim.",
    "method": "source",
    "result": "Atomic claim; deleted/paused sandboxes make the run fail; approvals persist and expire by wall clock. No new defect.",
    "artifact": null
   },
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/sandbox.py",
     "images/desktop/Dockerfile",
     "images/desktop/agentbox-desktop-start"
    ],
    "invariant": "Upload over agent symlinks, exec during a human lease, and the root restore start script give the agent no new authority.",
    "method": "source",
    "result": "uid 1000 operations only; exec not GUI-gated by design; start script touches root-owned sticky-/tmp paths. No defect.",
    "artifact": null
   },
   {
    "agent_id": "h-wild",
    "reviewed_paths": [
     "agentbox/web.py",
     "agentbox/api.py"
    ],
    "invariant": "Unauthenticated requests cannot write attributed audit records.",
    "method": "source",
    "result": "POST /login failures append ui_login_failed actor='human' without rate limit; agent POST /approvals appends approval_forbidden outside tool_concurrency. Hardening; accelerates the audit-reader candidate.",
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
- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it for each read and write path.
- Trace derived copies. Sanitized primary data can become unsafe in search, cache, analytics, export, previews, logs, replicas, and backups with different ACL and retention rules.
- Deletion and revocation are lifecycle contracts. Check current, historical, cached, indexed, exported, restored, and queued copies within the product's stated boundary.
- Privacy or retention preference is not automatically a security vulnerability. Require an explicit data-access boundary or deletion/revocation guarantee and an unauthorized reader or later operation.
- Use `confirmed` for complete source-visible lineage and bounded dummy-tenant tests. Use `needs_validation` when external storage policy, retention, CDN behavior, replica lag, or backup access is unavailable.
```

## Validation rules (apply before reporting ANY finding here)

1. Name attacker or lower-trust principal, protected data/state, affected owner/tenant, alternate copy or operation, and unauthorized disclosure or mutation.
2. Cite both intended source-of-truth policy and the path that omits or disagrees with it. Confirm another layer does not enforce the same tenant/lifecycle condition.
3. Use local dummy tenants and non-sensitive fixtures to prove cross-scope access or stale lifecycle behavior. Stop at the minimum observable record or operation.
4. If external cache, object storage, replicas, analytics, backup, or retention policy is required, classify `needs_validation` and state the owner-observed check.
5. Return `confirmed` only with complete lineage and concrete boundary impact. Return `needs_validation` with the exact unresolved storage, ACL, invalidation, retention, or restore fact.

# Execution boundary and paths

- Agent ID `v02`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/v02/scratch/`. Never edit target files, the ledger, findings, or other agents' directories.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/d3718f34-2d87-5ca6-8bcd-dc70a1cecc79/scratchpad/sbx v02 <cmd...>` (target at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. jinja2 is not importable there; stub templating if needed.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/v02/artifacts/<file>`.
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
