You are candidate verifier `v-readers` in run-6 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at commit `530b29e` (after fix PRs #24 and #25). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap",
 "title": "Unbounded buffering and missing container-side timeouts in list_dir, outbox_list, and preview glob expand",
 "description": "While exec streams output through _Head (capping memory to 64 KiB) and read_file, outbox_read, and workspace_manifest apply container-side head caps and timeouts, list_dir and outbox_list invoke c.exec_run without container-side _timed timeouts or stream-limiting byte caps, buffering arbitrary output in the control-plane process. Furthermore, preview _expand lacks output cardinality/byte limits, allowing an agent with a populated workspace or outbox to exhaust control-plane RAM or block worker threads indefinitely.",
 "claimed_root_cause": "Container output consumption disciplines were applied inconsistently: exec uses _Head streaming (_OUT_LIMIT=64 KiB) and _timed, read_file/outbox_read use head -c and _timed, workspace_manifest uses head -c and _timed, and preview _walk uses head -z and _timed. However, list_dir (ls -la) and outbox_list (find -printf) lack both container-side timeouts and output byte bounds, while preview _expand has a 10s timeout but no output byte cap or record limit. An agent-populated directory with hundreds of thousands of files causes c.exec_run to buffer all demuxed bytes in memory, parse them into unbounded Python structures, and potentially stall tool_pool and HTTP worker threads.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 293,
   "scope": "AgentBox.call_tool",
   "description": "Agent calls list_dir or triggers approval preview (via exec) on an agent-populated directory, or human views outbox via GET /sandboxes/{sid}/outbox."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 442,
   "scope": "SandboxManager.list_dir",
   "description": "list_dir calls c.exec_run([/"ls/", /"-la/", /"--/", p], demux=True) without _timed and without _Head streaming, waiting for all container output to buffer into control-plane RAM."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 548,
   "scope": "SandboxManager.outbox_list",
   "description": "outbox_list executes find without _timed or head cap, passing raw output to _parse_outbox which instantiates uncurbed Python lists of dicts."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 116,
   "scope": "_parse_outbox",
   "description": "Control plane process buffers unbounded byte arrays and creates thousands of Python objects, risking memory exhaustion in the 2 GB control container or threadpool worker exhaustion."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 424,
   "description": "exec streams output into _Head with _OUT_LIMIT cap and _timed(t, kill_after=5)."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 442,
   "description": "list_dir runs c.exec_run([/"ls/", /"-la/", /"--/", p]) with no _timed timeout and no byte cap."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 548,
   "description": "outbox_list runs c.exec_run with find -printf without _timed or output truncation before _parse_outbox."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 578,
   "description": "_expand runs container glob without head -z or output limit, unlike _walk which uses head -z."
  }
 ],
 "blockers": [
  "Demonstrating full control-plane memory exhaustion or threadpool hang under large-scale container output requires running against a live Docker daemon with a real container, which is excluded from the subagent sandbox environment."
 ],
 "validation_plan": {
  "local": "In a live test with Docker running: (1) create a sandbox container, (2) populate /workspace/outbox with 200,000 files using a fast shell loop, (3) call GET /sandboxes/{sid}/outbox and POST /sandboxes/{sid}/tools/list_dir with path /workspace/outbox, (4) observe control plane memory consumption spike and monitor process RSS; (5) test replacing outbox with a hanging device or slow pipe to observe thread starvation.",
  "deployment": "Review production control-plane logs and metrics under high file counts for OOM kills (mem_limit: 2g) or 504/timeout errors on list_dir and outbox endpoints."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Container%20output%20readers%20that%20fully%20buffer%20attacker-controlled%20bytes%3A%20sandbox.py%20exec_run%20without%20a%20read%20cap%20or%20container-side%20timeout%20%28list_dir%20ls%20-la%20%3A442%2C%20exists%20%3A475%2C%20delete%20%3A497%2C%20outbox_list%20find%20-printf%20%3A548%2C%20is_dir%20%3A537%2C%20plus%20_expand%20glob%20%3A578%20and%20_walk%20find%20-print0%20%3A584%20which%20gained%20_PREVIEW_TIMEOUT%20in%20PR%20%2324%29%20versus%20the%20capped%20_Head%20exec%20path%20%28%3A85%2C%3A427%29::Agent-owned%20container%20filesystem%20output%20to%20control-plane%20memory%20and%20tool_pool%2Frequest%20threads.%20An%20agent%20can%20create%20millions%20of%20names%2C%20deep%20trees%20or%20huge%20glob%20matches%2C%20so%20a%20human-triggered%20or%20preview-triggered%20listing%20buffers%20an%20unbounded%20demux%20result%20in%20the%20single%20control-plane%20process.%20Run-4%20N3%20%28needs_validation%2C%20not%20re-hunted%29.%20The%20h-xres%20and%20h-policy-cpu%20units%20excluded%20Unbounded%20buffering%20and%20cardinality%20citing%20N3%2C%20so%20no%20unit%20owns%20it%2C%20and%20PR%20%2318%20changed%20_expand%2F_walk%20%28NUL-separated%20output%2C%20head%20-z%29%20without%20a%20reader-cap%20review.::agentbox%2Fsandbox.py%23list_dir%2Fexists%2Fdelete_file%2Foutbox_list%2Fis_dir%2F_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fsandbox_common.py%23_timed%20%2B%20agentbox%2Fsandbox_desktop.py%23_x%2Fdesktop_processes%20%2B%20agentbox%2Fpreview.py::Unbounded%20buffering%20and%20cardinality%20of%20container-controlled%20output",
  "surface": "Container output readers that fully buffer attacker-controlled bytes: sandbox.py exec_run without a read cap or container-side timeout (list_dir ls -la :442, exists :475, delete :497, outbox_list find -printf :548, is_dir :537, plus _expand glob :578 and _walk find -print0 :584 which gained _PREVIEW_TIMEOUT in PR #24) versus the capped _Head exec path (:85,:427)",
  "boundary": "Agent-owned container filesystem output to control-plane memory and tool_pool/request threads. An agent can create millions of names, deep trees or huge glob matches, so a human-triggered or preview-triggered listing buffers an unbounded demux result in the single control-plane process. Run-4 N3 (needs_validation, not re-hunted). The h-xres and h-policy-cpu units excluded Unbounded buffering and cardinality citing N3, so no unit owns it, and PR #18 changed _expand/_walk (NUL-separated output, head -z) without a reader-cap review.",
  "local_checks": [
   {
    "agent_id": "h-readers",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/sandbox_common.py"
    ],
    "invariant": "exec uses _Head streaming byte cap and _timed, while list_dir, outbox_list, and exists/is_dir are checked for container-side timeouts and output byte caps",
    "method": "source",
    "result": "Confirmed from source that exec streams through _Head with _OUT_LIMIT (64 KiB) and _timed(t), read_file and outbox_read use head -c and _timed(_READ_TIMEOUT), workspace_manifest uses head -c and _timed(_MANIFEST_TIMEOUT). However, list_dir and outbox_list use c.exec_run without _timed or head byte caps, buffering arbitrary output in control-plane memory.",
    "artifact": null
   },
   {
    "agent_id": "h-readers",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "preview_command glob expansion and recursive directory walking enforce call bounds and output record caps",
    "method": "local",
    "result": "Sandboxed test confirmed that preview_command enforces PREVIEW_CALLS_MAX (40) and truncates affected items to limit (200), and _walk uses head -z; however, _expand has no record or byte cap, allowing wildcards matching thousands of paths to buffer full output before truncation.",
    "artifact": "agents/h-readers/artifacts/h.out"
   },
   {
    "agent_id": "h-readers",
    "reviewed_paths": [
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "desktop_processes and screenshot enforce timeouts and output buffering bounds",
    "method": "source",
    "result": "desktop_processes uses _timed(_X_TIMEOUT) with ps -eo bounded by container pids_limit (1024), and screenshot uses _timed(_X_TIMEOUT) with scrot -o -z, though screenshot cats the entire PNG into memory without streaming byte cap.",
    "artifact": null
   },
   {
    "agent_id": "h-readers",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/service.py",
     "agentbox/web.py"
    ],
    "invariant": "list_dir and outbox_list callers propagate uncurbed container output to control-plane consumers",
    "method": "source",
    "result": "Confirmed that api.py /sandboxes/{sid}/outbox and web.py outbox_frag pass outbox_list output directly to JSON serialization and Jinja template rendering without pagination or cardinality bounds, and service.py _call_tool routes list_dir directly to the container.",
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
 "fingerprint": "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap",
 "title": "list_dir, outbox_list, preview glob expansion and screenshot buffer unbounded container output in the shared control-plane process",
 "description": "On a sandbox that the agent token controls, four control-plane readers take the whole container-produced stream through Docker's non-streaming exec_run, with no byte cap and, for three of them, no container-side timeout: SandboxManager.list_dir (sandbox.py:428) runs `ls -la` on any /workspace or /source path; SandboxManager.outbox_list (sandbox.py:534) runs an unbounded `find -maxdepth 1 -printf`; SandboxManager._expand (sandbox.py:560) globs a preview pattern; DesktopTools.screenshot (sandbox_desktop.py:86-88) `cat`s /home/desktop/.cache/agentbox-shot.png and only then checks the PNG magic. _truncate (sandbox_common.py:24-32) and _parse_outbox (sandbox.py:111-124) run after the whole buffer exists, so they bound the returned value, not the peak. The peak is paid by the one shared FastAPI process, so one sandbox's listing is charged to every sandbox. Measured locally against the real reader functions with a fake exec_run: a 16 MiB stream makes list_dir peak at 16.19 MiB, against 0.32 MiB for exec's _Head reader on the same stream; 5.0 MB of find output becomes 58.6 MiB retained and 72.6 MiB peak after _parse_outbox (12.3x, record count uncapped); 4.2 MB of glob output becomes 209,715 Python strings; an 8 MiB PNG is accepted unchanged and then base64-encoded to 11.2 MB for the agent response (service.py:143). The screenshot path is the one with superlinear amplitude: the shot file sits in the desktop user's writable home (_SHOT, sandbox_desktop.py:32), so uid 1001 can point it at a character device and turn one cheap call into up to 15 s of unthrottled `cat`, bounded only by a wall clock (_X_TIMEOUT, sandbox_desktop.py:26,46-50), whose exit-code check also runs after the read. The host-disk half of the claim is narrower than proposed: service.py:328 writes the captured PNG with no size check, but only after the magic test passes, so a /dev/zero symlink costs memory and no disk; a huge PNG-prefixed file is needed for the disk variant. The list_dir/outbox_list/_expand variants are ~1:1 with container output, and the container's output ceiling is its writable layer, which the repository caps only when the optional AGENTBOX_DISK is set (config.py:42, sandbox.py:263-264).",
 "claimed_root_cause": "The _Head/_OUT_LIMIT discipline for exec and the container-side _timed plus head -c discipline for read_file, outbox_read and workspace_manifest were applied reader by reader; four readers that consume attacker-selected container output were left with a plain exec_run read (sandbox.py:428, 534, 560 and sandbox_desktop.py:86-88), and the screenshot reader's only bound is a timeout that is checked after the full read.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 216,
   "scope": "POST /sandboxes/{sid}/tools/{tool} (Depends(principal))",
   "description": "Agent-token route for the sandbox's own tools. default_policy.yaml:10 is `default: allow`, so list_dir and screenshot reach the readers below with no approval and no snapshot."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 350,
   "scope": "_call_tool ALLOW branch -> self._run_tool",
   "description": "Runs on a tool_pool thread; the reader work and its peak memory happen on that shared pool, outside any per-call size accounting."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 127,
   "scope": "_run_tool list_dir branch",
   "description": "Returns sb.list_dir(sid, path) straight into the tool result with no byte, entry or time check on the way."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 141,
   "scope": "_run_tool screenshot branch (inside gui_lock)",
   "description": "Calls sb.screenshot and then base64-encodes the entire PNG into the tool response at 143, so the response holds a second full copy of container-controlled bytes."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 318,
   "scope": "_call_tool REQUIRE_APPROVAL branch: preview = self._preview(...)",
   "description": "The exec preview is computed before the approval row exists, so sandboxes.preview -> _expand streams glob output even if the human then denies, and once per pending request (up to PENDING_APPROVALS_MAX)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 428,
   "scope": "SandboxManager.list_dir: c.exec_run(['ls','-la','--',p], user=AGENT_UID, demux=True)",
   "description": "The whole ls stream is read into the control plane with no byte cap and no container-side timeout; _truncate at 432 shortens the value only after the peak has been allocated."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 560,
   "scope": "SandboxManager._expand: c.exec_run(['sh','-c', glob loop, '_', pattern])",
   "description": "Shell glob output is buffered whole, then decoded and returned as one string per match; the caller materialises the entire list into preview notes."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 534,
   "scope": "SandboxManager.outbox_list: c.exec_run(['sh','-c', find -printf])",
   "description": "find -printf output is buffered whole and parsed afterwards into one dict per record, then sorted, with no count cap; reached from the human routes api.py:290 and web.py:233, where container-chosen names drive the cost."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox_desktop.py",
   "line": 88,
   "scope": "DesktopTools.screenshot: png = res.output[0] or b''",
   "description": "`cat {_SHOT}` (86) is buffered completely, bounded only by the 15 s timeout, and the PNG magic plus exit-code checks run at 89 only after the full read."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 95,
   "description": "_Head.add keeps only _OUT_LIMIT+1 bytes and merely counts the remainder; only exec's reader (411-416) uses it for container output."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 411,
   "description": "exec streams with api.exec_start(..., stream=True, demux=True), and the comment at 408-409 names the exact hazard (a single cat /dev/zero buffering hundreds of MB). This is the control the four readers skip."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 428,
   "description": "list_dir exec_run with no _timed wrapper and no head -c; the argv captured locally is ['ls','-la','--','/workspace'] with kwargs demux/user/workdir only."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 432,
   "description": "_truncate(out) runs after the whole stream is in memory, so the 64 KiB listing is a display cap, not a memory cap."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 441,
   "description": "read_file does use _timed(_READ_TIMEOUT, ...) plus head -c limit+1, i.e. the sibling that got both guards."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 376,
   "description": "workspace_manifest does use _timed(_MANIFEST_TIMEOUT, ...) plus `| head -c _MANIFEST_CAP` at 378."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 545,
   "description": "outbox_read does use _timed(_READ_TIMEOUT, ...) plus head -c limit+1."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 111,
   "description": "_parse_outbox builds one dict per NUL record, sorts the list and applies no count cap: locally 5.0 MB of records became 58.6 MiB retained."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 561,
   "description": "_expand decodes the whole stream and returns every match line; 4.2 MB of output became 209,715 strings."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 26,
   "description": "_X_TIMEOUT = 15 is the only bound on the screenshot exec; there is no byte cap anywhere on this path."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 32,
   "description": "_SHOT is /home/desktop/.cache/agentbox-shot.png, inside the desktop user's own home, so uid 1001 can replace it with a symlink before the control plane cats it."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 48,
   "description": "_x raises on exit 124/137 only after exec_run returned, i.e. after the full read; the timeout bounds wall clock, not bytes already buffered."
  },
  {
   "file": "agentbox/service.py",
   "line": 143,
   "description": "The screenshot result is base64-encoded into the tool response: +33% bytes and a second simultaneous copy of the PNG."
  },
  {
   "file": "agentbox/service.py",
   "line": 328,
   "description": "In the approval path the same PNG is written to settings.home/captures with no size check; it is only reached when the PNG magic check at sandbox_desktop.py:89 passes."
  },
  {
   "file": "agentbox/service.py",
   "line": 209,
   "description": "_summary drops 'listing' from the audit row for list_dir, so the audit log is not the amplifier on this path (calibration against the unbounded-args finding)."
  },
  {
   "file": "agentbox/api.py",
   "line": 290,
   "description": "outbox_list's own entrypoint is the human screen route (web.py:233 for the UI fragment), not the agent tool route in the trace."
  },
  {
   "file": "agentbox/config.py",
   "line": 42,
   "description": "disk_limit defaults to empty and sandbox.py:263-264 sets storage_opt only when it is non-empty, so by default the container side of the 1:1 readers is bounded only by the host disk."
  }
 ],
 "blockers": [
  "The decisive quantity - how much memory the control plane actually holds while a real container streams - is produced inside the docker SDK's non-streaming exec_start reader. The approved sandbox has no Docker daemon or socket (uid 65534, no /var/run/docker.sock), so no real exec stream can be created or sized; the peaks reported here come from an in-process fake exec_run that hands the real reader functions pre-built bytes, which understates the real peak because the SDK buffers the same bytes as well.",
  "The superlinear variant needs /home/desktop/.cache/agentbox-shot.png replaced by a symlink to /dev/zero (or to a huge PNG-prefixed file) by uid 1001 inside a live agentbox-desktop sandbox; the audit sandbox has neither that image nor an X session, and the control plane's own `scrot -o -z` overwrites the path on the non-symlink case.",
  "Whether the resulting peak is fatal depends on owner-side topology that the repository does not fix: deploy/ sets no memory limit for the agentbox service, the host's memory and any cgroup limit are unknown, AGENTBOX_DISK is unset by default, and the blast radius (control-plane restart drops every sandbox's desktop session and in-flight approvals) is an operational fact."
 ],
 "validation_plan": {
  "local": "Owner-run on a disposable Docker-backed sandbox with AGENTBOX_DISK=2g and no network. (1) Create ~200k empty files in /workspace using unapproved batch `touch` calls (touch is in the read-only allowlist, default_policy.yaml:25-27) or one gated exec. (2) Record VmHWM from /proc/<pid>/status of the control-plane process, call POST /sandboxes/{sid}/tools/list_dir {/"path/":/"/workspace/"} with a dummy agent token, record VmHWM again, and confirm the returned listing stops at 64 KiB while the peak grew by roughly the raw ls size. (3) Control: run the same directory through the capped exec reader (`ls -la /workspace`) and confirm the delta stays near 64 KiB. (4) Put 200k files in /workspace/outbox, call GET /sandboxes/{sid}/outbox, and check for the ~12x parse amplification measured here. (5) Send one `rm /workspace/*` exec so the REQUIRE_APPROVAL branch runs _preview before any human decision, and measure the _expand cost. (6) Desktop variant: in a disposable desktop sandbox, as uid 1001 point the shot path at /dev/zero, call POST /tools/screenshot, and stop the test as soon as VmHWM growth is visible, noting whether the 15 s timeout keeps it under the host limit.",
  "deployment": "Owner-observed on the compose stack: watch the agentbox container's RSS while a dummy agent lists a 200k-entry /workspace, compare it with the same agent running an allowlisted `ls -la` through the capped exec reader, and record whether the service has a cgroup memory limit and what an OOM does to running sandboxes and pending approvals. Then, with captures enabled, watch the same RSS during a burst of gated calls against a desktop sandbox whose shot path was replaced by a device symlink, and confirm that no file appears under settings.home/captures in the /dev/zero case while a huge PNG-prefixed file does produce one."
 }
}
```

# Parent-live evidence

- `agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/readers_live.out` (at `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/readers_live.out`)

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

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation -->
**Worker, pool, and priority starvation**
Low-priority or attacker-controlled jobs hold shared locks, workers, database pools, event-loop turns, or scheduler priority needed by unrelated users. Require a path that bypasses queue/concurrency fairness or retains a slot beyond its deadline.

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

- Agent ID `v-readers`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/v-readers/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-readers <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-readers /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-readers/artifacts/<file>`.
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
