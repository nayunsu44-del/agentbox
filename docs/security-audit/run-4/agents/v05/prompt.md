You are candidate verifier `v05` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
 "title": "GUI burst stray kill spares any uid-1001 process whose pid is named in the client-declared _NET_WM_PID window list",
 "description": "When a GUI burst closes, GuiBursts stops the uid-1001 processes that appeared during the burst so that GUI-launched background work cannot keep changing /workspace outside the policy and outside any gui_changes record. Whether a process counts as a windowed app is decided from window_pids, which desktop_processes fills with the decimal output of xdotool getwindowpid. That is the _NET_WM_PID property, which the X client sets itself; nothing binds the spared pid to a window or to the client that owns it. A uid-1001 process in the desktop session can therefore map a one-pixel titled window and set its _NET_WM_PID to the pid of a second process that has no window at all, and that second process survives every burst close while continuing to write /workspace between bursts, where no manifest diff observes it.",
 "claimed_root_cause": "The stray-kill exemption is derived from container-declared X window metadata instead of a control-plane-verifiable link. sandbox_desktop.desktop_processes (sandbox_desktop.py:59-61) turns every decimal token printed by xdotool getwindowpid into a window pid, gui_state.gui_strays (gui_state.py:85-86) spares a new uid-1001 process when its pid or a new ancestor pid is in that set, and gui_bursts._stop_strays (gui_bursts.py:83-85) then kills only the remaining pids. Because _NET_WM_PID is written by the X client and any desktop-session process can reach the display (images/desktop/agentbox-desktop-start:19-21,30,38), the attacker chooses which of its processes are treated as windowed apps, so the burst-end kill no longer bounds what keeps running.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "The agent (agt_ token, prompt-injectable) sends click/type to a desktop sandbox. GUI input is policy-free by design and executes as uid 1001 in the desktop session (sandbox_desktop.py:45-47, 94-129)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 343,
   "scope": "AgentBox._call_tool",
   "description": "_needs_snapshot is true for GUI input, so _snapshot (250-265) takes the recovery snapshot and opens a burst whose baseline is the workspace manifest plus the current pid set (gui_bursts.py:65-77)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 148,
   "scope": "AgentBox._run_tool (type)",
   "description": "The typed command runs in the desktop session as uid 1001 and starts a background process that never opens a window, staying in the baseline session id."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 120,
   "scope": "GuiBursts._finish",
   "description": "When the burst closes (close_idle, gui_bursts.py:137-155) the strays are collected and killed before the closing manifest is read."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox_desktop.py",
   "line": 59,
   "scope": "DesktopTools.desktop_processes",
   "description": "window_pids is the set of decimal tokens of xdotool getwindowpid for every visible named window, i.e. the client-declared _NET_WM_PID values; any integer is accepted and no window ownership is verified."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_state.py",
   "line": 85,
   "scope": "gui_strays",
   "description": "A new uid-1001 process is spared when its pid is in window_pids, or when a new ancestor pid is, regardless of which process actually owns that window."
  },
  {
   "kind": "sink",
   "file": "agentbox/gui_bursts.py",
   "line": 85,
   "scope": "GuiBursts._stop_strays",
   "description": "kill_processes receives only the unexempted pids, so the attacker's daemon survives the burst and keeps modifying /workspace between bursts, where no burst baseline or diff observes it."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/gui_state.py",
   "line": 85,
   "description": "The windowed test reads only window_pids (client-declared) plus a new-windowed-ancestor heuristic; there is no binding between the spared pid and the window's owning client."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 80,
   "description": "The only other exemptions are baseline pids, pid 1, non-1001 uids and from_exec, so for a same-session process the window test is the sole gate."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 53,
   "description": "The docstring states the window set is the _NET_WM_PID of visible windows, which X clients write themselves."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 59,
   "description": "xdotool getwindowpid output is split and filtered by isdigit only; nothing checks that the pid owns a window or is the declaring client."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 20,
   "description": "Xvfb and the Xfce session are started as the desktop account (uid 1001) via setpriv, so any process in that session can connect to :0 and set window properties."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 38,
   "description": "startxfce4 runs as the desktop account, which is the identity the agent's typed GUI input inherits."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 80,
   "description": "The stated purpose of the kill is to stop work that would otherwise keep changing files outside policy after the burst ends, which this exemption defeats."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 88,
   "description": "Only the selected pids are logged as gui_processes_stopped, so a spared daemon leaves no failure record and the absent pid is the only hint."
  }
 ],
 "blockers": [
  "The decisive platform step - a uid-1001 X client setting _NET_WM_PID to another process's pid and xdotool getwindowpid reporting it - needs a live X server. The approved sandbox has no X server, no Xvfb and no X11 client library, so the property-trust step cannot be observed locally.",
  "Observing the spared daemon after a real idle close needs the Docker-backed desktop container (docker exec for ps, xdotool, kill and the socat/x11vnc relay); the sandbox forbids the Docker daemon."
 ],
 "validation_plan": {
  "local": "In a disposable desktop-image container with network none, start the desktop, then as the desktop account run a helper that maps a 1x1 titled window and sets _NET_WM_PID to the pid of a second 'sleep 300' process started with & (same session id, no window). With the audited tree, call SandboxManager.desktop_processes(sid) and gui_state.gui_strays(procs, wins, baseline=current pids minus the daemon) and assert the daemon pid is absent from the result while the same call with wins=set() contains it; then call kill_processes(sid, result) and assert the daemon is still running.",
  "deployment": "Owner-observed on a disposable desktop sandbox with dummy files: drive the agent's type/click to start 'nohup sh -c \"sleep 300\" &' plus the window helper before AGENTBOX_GUI_SNAPSHOT_IDLE (60 s) elapses, then read GET /audit: the gui_processes_stopped record for that close must omit the daemon pid and an exec ps must still show it running, with no later gui_changes row for its writes. Audit reads only; the process and files are dummy."
 },
 "x_proposed_by": "h-gui-burst"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "container%20output%3A%20ps%2C%20xdotool%20getwindowpid%2C%20find%20-printf%20manifest::agentbox%2Fgui_state.py%23_parse_ps%20%2B%20gui_strays%20%2B%20_parse_manifest%20%2B%20diff_manifest::agentbox%2Fgui_state.py%20%2B%20agentbox%2Fsandbox_desktop.py%23desktop_processes%2Fkill_processes::ATTACK-CLASSES.md%23Business%20logic",
  "surface": "container output: ps, xdotool getwindowpid, find -printf manifest",
  "boundary": "agentbox/gui_state.py#_parse_ps + gui_strays + _parse_manifest + diff_manifest",
  "local_checks": [
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_state.py",
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "_parse_ps must not accept attacker-chosen records: a container process must not be able to add a line with chosen pid/ppid/sid/uid through its argv.",
    "method": "local",
    "result": "Started children whose argv contained a newline, CR, VT, FF, FS, GS, NEL and U+2028 followed by a forged record, then read the real ps -eo pid=,ppid=,sid=,uid=,args= bytes: procps-ng 4.0.4 replaced every control character with ? or space and emitted exactly one line per process, and _parse_ps returned one record per child with its real pid/ppid/sid/uid. The hypothesized ps-text injection (which would have let uid-1001 code forge the ancestor that makes from_exec() true, or forge a uid to redirect the kill) is disproved for this stack, so the line model in gui_state.py:41-49 has no injectable field.",
    "artifact": "agents/h-gui-burst/artifacts/h2.out"
   },
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_state.py",
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "A uid-1001 process must be spared by the stray kill only for a control-plane-verifiable reason.",
    "method": "local",
    "result": "With procs = session leader 100 (uid 1001) -> shell 150 -> daemon 160 and baseline {100,150}: gui_strays(procs, set(), base) returned [160]; gui_strays(procs, {160}, base) returned [] - the daemon is spared solely because its pid is in window_pids although 160 owns no window; when only baseline ancestor 150 is in window_pids the daemon is still killed. desktop_processes (sandbox_desktop.py:59-61) builds window_pids from the decimal tokens of xdotool getwindowpid over xdotool search --onlyvisible --name ., i.e. from the client-set _NET_WM_PID property, with no check that the pid owns a window or that the declaring client is that process. Carried as the needs_validation candidate.",
    "artifact": "agents/h-gui-burst/artifacts/h2.out"
   },
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_state.py",
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "The from_exec exemption (ppid 0) must identify only control-plane docker-exec roots and must not be attacker-reachable.",
    "method": "local",
    "result": "Observed inside the sandbox: the docker-exec'd root appeared as '1 0 1 65534 /usr/bin/timeout -k 5 120 /usr/bin/python3 /scratch/h_ps.py' (ppid 0) exactly as exec_root (gui_state.py:72-76) assumes, and a normally spawned child chain was 9->7->1->0. Orphans are reparented to PID 1 inside the pid namespace, so a uid-1001 process cannot acquire ppid 0 itself; combined with the disproved ps injection the exemption is not forgeable by container code.",
    "artifact": "agents/h-gui-burst/artifacts/h_ps.out"
   },
   {
    "agent_id": "h-gui-burst",
    "reviewed_paths": [
     "agentbox/gui_state.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "The manifest parser must not let container-controlled metadata forge or hide records, and truncation must be visible.",
    "method": "source",
    "result": "_parse_manifest (gui_state.py:17-29) consumes NUL-separated 4-field records; a Linux filename cannot contain NUL, so a path cannot inject or shift fields, the incomplete tail record is dropped (21) and truncated is set at the 8 MiB cap (20). diff_manifest (32-35) compares only (size, mtime, ctime) equality. Residual hardening: workspace_manifest runs find ... | head -c through sh -c (sandbox.py:376-378), so the pipeline status is head's and a find failure returns 0 with a partial manifest and truncated=False; missing entries can only mislabel a change as added/deleted, never as unchanged, so no hiding path was found.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-3 wording)

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
 "title": "gui_strays exempts burst-launched uid-1001 processes from the stray kill based on window ownership, including the client-declared _NET_WM_PID",
 "description": "At GUI-burst close, AgentBox._stop_gui_strays collects uid-1001 processes and the set of window-owning pids and calls gui_strays. A new (non-baseline, non-exec-rooted) uid-1001 process that lives in a session that existed at burst start (base_sids) is spared whenever it is 'windowed': its own pid is in window_pids, or a NON-baseline ancestor's pid is in window_pids. window_pids come from `xdotool getwindowpid`, which returns the _NET_WM_PID property each X client sets for itself. Two routes can therefore spare background work started during the burst. (a) Without any forgery, a newly opened windowed app in the burst-start session (for example a file manager or editor started during the burst) exempts the scripts and children it spawns, because the ancestor clause only requires the windowed ancestor to be non-baseline. (b) A GUI client that declares another process's pid in _NET_WM_PID makes that process, even a headless one, look windowed. Either way the process can survive the close and keep modifying /workspace outside any monitored burst, which weakens the N-1 partial mitigation. Children of a PRE-EXISTING windowed baseline app are still killed, because the ancestor clause excludes baseline ancestors. Processes in a new session (terminal shells, setsid or nohup) are killed regardless of window (line 218). In the image, Xfce is started by the start script (agentbox-desktop-start:30), so apps launched from Xfce probably inherit a burst-start sid. This is not observable from source. The image has no python, xprop or compiler (Dockerfile:17-21), so route (b) needs a hand-written X client.",
 "claimed_root_cause": "Whether a new baseline-session process is spared is decided by window presence, derived from X window properties (including the client-settable _NET_WM_PID via xdotool getwindowpid) and a 'new windowed ancestor' heuristic, rather than by a control-plane-verifiable link such as the docker-exec ancestry already tracked. Target-controlled GUI clients, or any legitimately windowed app launched during the burst, therefore decide which of their descendants are treated as windowed apps or helpers and escape the kill.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 215,
   "scope": "AgentBox._stop_gui_strays",
   "description": "Burst close ingests attacker-influenced container output: calls desktop_processes(sid) to get the process list and window pids, then gui_strays to classify which new uid-1001 processes to kill."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 690,
   "scope": "SandboxManager.desktop_processes",
   "description": "Window pids come from `xdotool search --onlyvisible --name .` then `xdotool getwindowpid $w`, i.e. the client-set _NET_WM_PID property, parsed into the wins set at line 692."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 221,
   "scope": "gui_strays",
   "description": "A new baseline-session process is marked windowed (p.pid in window_pids, or a non-baseline ancestor pid in window_pids) and consequently NOT appended to the kill list at lines 223-224, so it survives the burst close."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 692,
   "description": "wins = {int(x) ...} parsed from container-side xdotool getwindowpid output; the exemption input is controlled by the GUI clients inside the sandbox."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 221,
   "description": "windowed = p.pid in window_pids or any(a.pid in window_pids and a.pid not in baseline for a in ancestors(p)); windowed -> not killed. The ancestor clause spares helpers of any newly created windowed app even with truthful window pids."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 189,
   "description": "Docstring states windowed apps and their helpers (and burst-start processes and docker-exec-launched tools) are intentionally left running, so the only gate for a baseline-session process is window ownership."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 30,
   "description": "startxfce4 is launched from the container start script, so Xfce-launched apps likely share a burst-start session id (base_sids) and are not caught by the new-session kill at sandbox.py:218."
  },
  {
   "file": "agentbox/service.py",
   "line": 235,
   "description": "_close_gui_burst pops the burst (233), runs the stray kill (235) and takes a single final manifest (236-240); nothing monitors /workspace afterwards, so any survivor's later writes are unrecorded."
  }
 ],
 "blockers": [
  "Reachability in agentbox-desktop:0.1: whether, using only GUI input (click/type/key), a prompt-injected agent can get a uid-1001 process into a session that existed at burst start (base_sids) that either owns a visible window reported by `xdotool getwindowpid`, or descends from a newly created windowed process (for example a script run from a file manager or app window opened during the burst), or has its pid forged into another client's _NET_WM_PID. Real session ids (whether launcher, terminal or file-manager spawned processes inherit the Xfce start-script sid or get a new setsid session, which line 218 kills regardless) and real _NET_WM_PID values are not observable from source or from a pure-function harness over gui_strays, and the Docker daemon is unavailable offline. The pure-function harness already confirms the exemption logic itself."
 ],
 "validation_plan": {
  "local": "In a disposable, network-less agentbox-desktop:0.1 sandbox: open a GUI burst with a GUI tool call. Using GUI input only, (a) open a file manager or editor window during the burst and from it run a script that appends a timestamp to a dummy file /workspace/_v15_probe every ~2s; and (b) separately, with a hand-written X client, set _NET_WM_PID of a window to the pid of a headless background writer started from a burst-start-session launcher. Just before close, record `ps -eo pid=,ppid=,sid=,uid=,args=` and `for w in $(xdotool search --onlyvisible --name .); do xdotool getwindowpid $w; done` to capture the real session ids and window-pid set, and feed them through the real gui_strays to predict survivors. Let the burst close on idle; then read the gui_processes_stopped audit entry and check whether /workspace/_v15_probe's mtime keeps advancing after close. Non-destructive: touches only the dummy probe file; kill the probe and discard the sandbox afterward.",
  "deployment": "Owner reproduces the same probe on the live deployed image and config to confirm the image's session-id and _NET_WM_PID semantics and that a spared process (or its child) modifies /workspace after burst close; collect the gui_processes_stopped and gui_changes audit entries and the manifest diff as evidence. Fix check: exempt only burst-start (baseline) processes and control-plane docker-exec-launched components, deriving ownership from a control-plane-verifiable link (for example the exec/ancestry already tracked) rather than window presence or the client-declared _NET_WM_PID. Non-destructive: dummy file only."
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

<!-- ATTACK-CLASSES.md#Business logic -->
**Business logic** (subagent_type: `general`)
Hunt logic errors by hand: standard scanners cannot find them, and they yield high-impact findings. For each major workflow:
- **State machine violations**: Can you skip steps? Go backwards? Reach an invalid state? What happens if you replay a completed flow? What about partial failure — if step 2 of 3 fails, is step 1 rolled back?
- **Race conditions with business impact**: Concurrent operations that produce invalid states (double-spend, double-approve, lost updates). Focus on operations that check-then-act non-atomically.
- **Numeric/quantity manipulation**: Negative values, zero values, overflow, precision loss, type coercion between string and number.
- **Access boundary violations**: Not "does the permission check exist" but "is it the right check for the business rule?" Can input to one operation bypass a restriction enforced on a different operation for the same effect?
- **Implicit trust assumptions**: Data from storage, config, other components, or plugins assumed safe because "we validated it on the way in." What if a different code path wrote it?
- **Time-based logic**: Expiry checks, scheduling, rate windows, clock skew. What happens at exact boundary moments? What about timezone differences between components?
- **Default and fallback behavior**: What is the security posture when config is missing? When a feature flag is off? When a dependency is unavailable? When the system is mid-migration?

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Establish the realistic local or remote-content attacker: another app, another OS user, a sandboxed child, an untrusted document, or a remote origin. Self-harm within the same account and authority is not a boundary violation.
- Paths, process names, bundle/package IDs, and claimed sender fields are not peer authentication. Use OS peer credentials, code identity, capability handles, or protected channel state.
- The native bridge or helper must authorize each operation and final resource after parsing. A trusted UI or broker does not make attacker-influenceable arguments trusted.
- OS sandbox, signing, entitlements, permissions, keychain ACLs, exported-component policy, and prompt behavior are real controls when pinned and visible.
- Use `confirmed` for source evidence plus bounded local/emulator tests. Use `needs_validation` when signing, manifest merge, OS version, device policy, installer ACL, or packaging is required but not observable.
```

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy -->
**Privileged helper as confused deputy**
A low-privilege caller can select a privileged command, file, service, user, or system setting without per-operation authorization. Review sudo/polkit/UAC/XPC helper rules and ensure the helper independently validates normalized arguments.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU -->
**Local file ownership and TOCTOU**
The app checks a file/path then follows replacement, symlink, mount, or case/normalization changes during a privileged read/write. Use descriptor-relative operations and verify final ownership. Focus `MEMORY-SAFETY-AND-BINARY.md` on parsing after the file is opened.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves -->
## Universal moves (apply across the above)

- Enumerate every process, app component, local endpoint, URI scheme, file association, webview origin, and helper. Record OS identity, runtime privilege, caller, and callable operation.
- Read final packaging inputs: merged manifest, entitlements, installer rules, native-messaging registration, protocol handlers, and ACL creation. Source declarations can be overwritten downstream.
- Validate with dummy profiles and non-sensitive local fixtures on an isolated machine/emulator. Do not interact with other users' apps, credentials, or production services.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the attacker starting capability, OS/app principal crossed, entry channel, accepted argument or state, and unauthorized operation or disclosure.
2. Confirm OS sandbox, peer credential, signing, entitlement, permission, user-consent, and installer controls that apply. Unknown packaging/runtime facts require `needs_validation`.
3. For webview bridges, cite both navigation/origin control and privileged native sink. For IPC, cite peer authentication and per-resource authorization. For helpers, verify final normalized destination.
4. Keep local tests bounded and use dummy content/accounts. Stop after proving the boundary result; do not extend proof into persistence or broader system modification.
5. Return `confirmed` only with a complete source and local evidence chain. Return `needs_validation` with the exact OS, manifest, signing, ACL, or device-lifecycle fact required.

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

- Agent ID `v05`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v05/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v05 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v05 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
