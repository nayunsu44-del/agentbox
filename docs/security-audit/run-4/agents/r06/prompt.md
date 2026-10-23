You are final record verifier `r06` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
 "title": "Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent)",
 "description": "For a gated exec the \"system-computed impact\" table is produced by SandboxManager._expand / _walk and preview_command. _expand hands the already-unquoted rm operand to sh as $1 and iterates over $1 unquoted, so the operand is word-split on IFS and each fragment is pathname-expanded before the [ -e ] existence test; results are newline-framed and re-split in Python, and _walk frames find output the same way. preview_command turns an empty match list into \"삭제 시도 (현재 존재하지 않음)\" and every returned line into a \"삭제\" row. The rm itself later runs through bash -c with the original quoting, so the computed path set and the executed path set differ: an agent whose workspace target contains a space obtains approval for a deletion the card describes as an apparent no-op, or for a card that lists unrelated decoy files, while the real file is deleted. Reproduced with the verbatim scripts: the card for a lone rm of an existing \"final report.docx\" showed exactly one row, \"삭제 시도 (현재 존재하지 않음)\", and no note.",
 "root_cause": "The preview path transport is not a lossless representation of a filesystem path. sandbox.py:559 iterates $1 unquoted under the default IFS, so an operand that shlex already unquoted (preview.py:33-44) is re-split into words and each word is expanded again before the existence test; matches are framed with printf \"%s\\n\" and re-split by splitlines() (sandbox.py:562), and _walk's find | head output is split the same way (sandbox.py:565-569). preview.py:90-91 maps an empty expansion to the \"does not currently exist\" row and preview.py:96-98 maps each returned line to a deletion row, so a split operand both hides the real target and can manufacture paths the command will never touch. The executed command keeps its quoting (sandbox.py:411), so the card and the effect diverge.",
 "intended_behavior": "The affected list shown beside the approval must name exactly the paths the stored command will act on, so approving the card is equivalent to approving the effect: a path that exists must never be reported as nonexistent, and a path must never be listed as deleted unless the command deletes it.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "The agent posts tool=exec with body.args.command under its own sandbox token."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 318,
   "scope": "AgentBox._call_tool",
   "description": "For a REQUIRE_APPROVAL decision (default_policy.yaml:12-16 routes rm to require_approval) the preview is computed while the approval is created, before any human sees it."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 215,
   "scope": "AgentBox._preview",
   "description": "exec previews delegate to SandboxManager.preview with the raw command string."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 573,
   "scope": "SandboxManager.preview",
   "description": "preview_command runs with expand=_expand and walk=_walk bound to the running container."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 89,
   "scope": "preview_command rm branch",
   "description": "Each rm operand (quotes already consumed by _split_segments, preview.py:33-44) is expanded once through the container callback."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 559,
   "scope": "SandboxManager._expand",
   "description": "The operand is passed as $1 and iterated unquoted, so the shell word-splits it on IFS and globs the fragments before [ -e \"$p\" ]; the surviving words are what get tested."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 562,
   "scope": "SandboxManager._expand return",
   "description": "Matches are framed one per line and re-split with splitlines(), so a name containing a newline arrives as two or more fake paths."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 90,
   "scope": "preview_command affected rows",
   "description": "An empty expansion becomes the \"삭제 시도 (현재 존재하지 않음)\" row and each returned line becomes a deletion row; the result is stored with the approval and rendered as the system-computed impact."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 411,
   "scope": "SandboxManager.exec after approval",
   "description": "After the human approves, decide() snapshots (service.py:412) and _run_tool passes the stored command unchanged (service.py:126) to exec, which runs it verbatim through bash -c; the quoting is intact there, so the file the table called nonexistent is actually deleted."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 559,
   "description": "for p in $1 - the operand is expanded without quotes under the default IFS, so a space splits it and each fragment is globbed; reproduced with only the cd target retargeted."
  },
  {
   "file": "agentbox/preview.py",
   "line": 91,
   "description": "An empty match list becomes the \"삭제 시도 (현재 존재하지 않음)\" row - the false no-op statement for an existing but split path, produced with notes=[]."
  },
  {
   "file": "agentbox/preview.py",
   "line": 97,
   "description": "Matched paths become \"삭제\" rows, so split words (decoy names that exist) are presented as the deletion set."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 562,
   "description": "out.splitlines() turns one filename containing a newline into several rows; expand(\"*\") over fixtures \"a\\nb\" and ok.txt returned [a, b, ok.txt]."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 565,
   "description": "_walk frames find output line by line (splitlines at 569), so a recursive rm over \"dir with space/inner\\nname.txt\" reports \"dir with space/inner\" and \"name.txt\" instead of the real path."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 411,
   "description": "The approved command runs as a single bash -c argument, so shell quoting is honoured and the computed set diverges from the executed set."
  },
  {
   "file": "agentbox/service.py",
   "line": 412,
   "description": "decide() snapshots before execution, which bounds the impact to low."
  },
  {
   "file": "agentbox/preview.py",
   "line": 125,
   "description": "The per-segment note added for run-3 v17 shows the module already treats \"the table may be incomplete\" as security-relevant; the split-path case produces no note at all."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 14,
   "description": "The table renders the not-existing row without the deletion highlight (only effect == 삭제 gets class del), so the sole row on the card looks like a failed no-op; the raw command is shown above it at line 8."
  },
  {
   "file": "agentbox/display.py",
   "line": 18,
   "description": "Control characters are escaped for display, so the defect is in the computed path set, not in the rendering."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "A sandbox agent token (or prompt-injected code running as uid 1000 inside that sandbox) submits the rm; the default policy routes rm to require_approval, so the approval card is the only control between it and the deletion."
  },
  {
   "kind": "user_interaction",
   "description": "A human opens the pending approval in the /ui/approvals card or agentbox approve and presses approve, relying on the system-computed impact table rather than re-reading the raw command."
  },
  {
   "kind": "data_state",
   "description": "The rm operand names an existing /workspace path containing whitespace (space or tab) or a newline; the agent can produce that state itself, since creating a new file with write_file needs no approval."
  },
  {
   "kind": "system_configuration",
   "description": "Stock default_policy.yaml, where exec commands containing rm route to require_approval (default_policy.yaml:12-16)."
  }
 ],
 "execution": {
  "attacker_perspective": "The sandbox agent wants to delete /workspace/final report.docx but wants the card not to say so, so it submits exec rm \"final report.docx\". The card describes the target as \"삭제 시도 (현재 존재하지 않음)\" - an apparently already-failed no-op - and with decoy names present it lists files that will not be touched, while the approved command deletes the real file.",
  "payloads": [
   "rm \"final report.docx\"",
   "decoy fixtures final and report.docx in the same directory",
   "rm over a workspace containing a file named \"a\\nb\"",
   "rm -r over \"dir with space\"/\"inner\\nname.txt\"",
   "rm notes.txt; mv important /tmp/important (run-3 v17 revalidation)"
  ],
  "instructions": [
   "Create fixtures in the approved sandbox (tools/sbx.py v06, no network, read-only /target, writes only /scratch): a directory holding one file literally named final report.docx plus notes.txt.",
   "Copy the sandbox.py:559 and sandbox.py:565 scripts verbatim, changing only cd /workspace to the fixture directory (the sandbox has no /workspace and uid 65534 cannot create one), and wrap them exactly as sandbox.py:560-562 / 567-569 do (decode, splitlines) to build the expand and walk callbacks.",
   "Import agentbox.preview from /target (PYTHONPATH) and call preview_command('rm \"final report.docx\"', 200, expand, walk); compare the affected rows and notes with os.path.exists on the real file.",
   "Repeat with decoy files final and report.docx present, and with fixtures named \"a\\nb\" and \"a\\tb.txt\" for the expand path and \"dir with space/inner\\nname.txt\" for the walk path.",
   "Re-run the run-3 v17 case rm notes.txt; mv important /tmp/important and check that its per-segment note still appears.",
   "Show the sink: run sh -c 'rm \"final report.docx\"' in the fixture directory (the quoting sandbox.py:411 hands to bash) and confirm the file the table called nonexistent is gone."
  ],
  "observed_result": "Case B: affected=[{path: \"final report.docx\", effect: \"삭제 시도 (현재 존재하지 않음)\"}], notes=[], real target exists: true. Case C (decoys present): affected=[{path: \"final\", effect: \"삭제\"}, {path: \"report.docx\", effect: \"삭제\"}] while the real target still exists and is never listed. Newline case: expand(\"*\") -> [\"a\", \"b\", \"ok.txt\"] for files \"a\\nb\" and ok.txt, and the old find framing returned [\"dir with space\", \"dir with space/inner\", \"name.txt\"]. Sink: sh -c 'rm \"final report.docx\"' exited 0 and the directory went from [final report.docx, notes.txt] to [notes.txt]. Case A (revalidation): \"rm notes.txt; mv important /tmp/important\" produced the rm row AND the per-segment note, so the run-3 omission defect is fixed. The proposed fix was also executed against the same fixtures: with IFS= and NUL framing expand returned [\"final report.docx\"] and a single \"a\\nb\", and find -print0 | head -z kept \"dir with space/inner\\nname.txt\" whole. Everything ran inside tools/sbx.py v06."
 },
 "remediation": {
  "strategy": "Make both preview transports lossless. In _expand, disable IFS word splitting (IFS=) so the operand is tested as one word while pathname expansion still happens, and frame results with NUL instead of newline; in _walk, use find -print0 with head -z and split on NUL. Then one match is one path: the \"does not currently exist\" row is emitted only when the path really is absent, and no row names a path the command will not touch. Add a regression test that pushes names containing a space, a tab and a newline through both the non-recursive and the recursive branch and asserts the returned list equals the fixture paths.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "def _expand(self, c, pattern: str) -> list[str]:\n    \"\"\"컨테이너 안에서 glob만 펼친다. 명령 치환은 일어나지 않는다.\"\"\"\n    script = ('cd /workspace; IFS=; for p in $1; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then printf \"%s\\\\0\" \"$p\"; fi; done')\n    res = c.exec_run([\"sh\", \"-c\", script, \"_\", pattern], user=AGENT_UID, demux=True)\n    out = (res.output[0] or b\"\").decode(\"utf-8\", errors=\"replace\")\n    return [p for p in out.split(\"\\0\") if p]"
   },
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "def _walk(self, c, path: str, limit: int) -> list[str]:\n    res = c.exec_run([\"sh\", \"-c\", 'cd /workspace; case \"$1\" in -*) set -- \"./$1\" \"$2\";; esac; find \"$1\" -print0 2>/dev/null | head -z -n \"$2\"',\n                      \"_\", path, str(limit)],\n                     user=AGENT_UID, demux=True)\n    out = (res.output[0] or b\"\").decode(\"utf-8\", errors=\"replace\")\n    return [p for p in out.split(\"\\0\") if p]"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "The mechanics are deterministic for any rm operand naming a /workspace path with whitespace or a newline, and the agent can create such a name itself with an ungated write_file before requesting the rm, so the condition is attacker-chosen rather than accidental; exploitation still needs the approver to rely on the table instead of the raw command displayed immediately above it, and only rm and curl reach this preview."
  },
  "impact": {
   "score": "low",
   "reason": "What is lost is informed consent on the card, not a boundary: the effect is a deletion inside the requesting agent's own /workspace, the resource class the rm approval governs, decide() snapshots immediately before execution so the files are recoverable, and the decoy rows are misleading text rather than an additional capability."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Every cited line was re-read in 9805d91, the divergence was reproduced inside the approved sandbox with the verbatim _expand/_walk scripts (only the cd target substituted) and the verbatim preview_command, the sink step confirms the stored command keeps its quoting and really deletes the file, and the proposed fix was executed against the same fixtures."
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

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Pending-action and user-presence confusion -->
**Pending-action and user-presence confusion**
Notification, widget, shortcut, share sheet, biometric prompt, or deferred operation authorizes a different action than displayed, executes after expiry, or uses another profile's pending state. Bind confirmation to normalized action, resource, account, and current foreground state.

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

# Execution boundary and paths

- Agent ID `r06`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r06/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r06 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r06 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
