You are final record verifier `r05` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
 "title": "GUI burst stray kill spares a uid-1001 process in a burst-start session whose pid the client-declared _NET_WM_PID window list names",
 "description": "Verified in the audited tree (9805d91): at GUI-burst close GuiBursts._finish (gui_bursts.py:120) calls _stop_strays, which reads desktop_processes (gui_bursts.py:83) and kills gui_strays(procs, wins, burst['pids']) (gui_bursts.py:84-85). For a new uid-1001 process the only remaining exemption is the window test: p['pid'] in window_pids or a non-baseline ancestor pid in window_pids (gui_state.py:85-86); baseline pids, pid 1, other uids and docker-exec roots are exempted earlier (gui_state.py:80). window_pids are the decimal tokens of `xdotool getwindowpid` over `xdotool search --onlyvisible --name .` (sandbox_desktop.py:59-61), i.e. the _NET_WM_PID property the X client writes for itself; the parser filters with isdigit only, never checks that the pid owns a window or is the declaring client, and xdotool is run as the desktop account on the desktop-owned display (sandbox_desktop.py:46-47, images/desktop/agentbox-desktop-start:20,30,38). I re-ran the real gui_state.gui_strays and the real GuiBursts._stop_strays in the sandbox (agents/v05/artifacts/v05_probe.out): a headless uid-1001 daemon 300 in the burst-start session sid 1, parented by the baseline Thunar 85, is killed when window_pids is empty (line 2) and is spared when the window list merely names 300 (line 3); naming an unrelated pid 301 does not spare it (line 4), and a windowed but baseline ancestor 85 does not spare it (line 5). With the real _stop_strays the forged case killed nothing and emitted no gui_processes_stopped record at all, while the control case killed [300] and logged it (lines 20-22). Two preconditions bound the claim, and both are runtime facts of the image rather than source facts. (1) The window test is reached only when p['sid'] is in base_sids, the sessions of the uid-1001 baseline pids (gui_state.py:63,82-84); a new session is killed regardless of window, which my run confirms for a daemon in sid 777 (line 8). tests/test_unit.py:330-334 encodes exactly that for a terminal opened during a burst: the terminal window 150 is spared but its shell 152 and the shell's job 160 are killed as a new session, so a daemon typed into a terminal opened during the burst is not in this candidate's class. (2) The attacker needs an X client that can set _NET_WM_PID to another process's pid and then have xdotool report it; the image recipe installs xdotool, socat and x11-xserver-utils but not x11-utils (xprop), python or a compiler (images/desktop/Dockerfile:17-23), so whether such a client exists in the running image is unobserved. Impact is bounded and detective-control shaped: GUI input is approval-free by design (N-1) and the burst's snapshot and gui_changes are its documented record. A spared daemon keeps writing /workspace after the close, where the only manifest read (gui_bursts.py:122) has already happened, and its writes produce no gui_changes and no gui_processes_stopped row; because it is then present at the next burst open (gui_bursts.py:70,76), gui_state.py:80 treats it as baseline forever, which is the candidate's 'survives every burst close'. Calibration, not dismissal: the by-design ancestor clause already spares a helper of any windowed app opened during the burst (tests/test_unit.py:335-336; my line 9), so the forgery route adds capability mainly for a process with no new windowed ancestor, for example one started from a baseline windowed app such as the pre-existing file manager (tests/test_unit.py:337 keeps such a script in the kill list).",
 "claimed_root_cause": "The stray-kill exemption is decided from container-declared X window metadata instead of a control-plane-verifiable link. sandbox_desktop.desktop_processes (sandbox_desktop.py:59-61) turns every decimal token printed by xdotool getwindowpid into a window pid, gui_state.gui_strays (gui_state.py:85-86) spares a new uid-1001 process in a burst-start session when its pid, or a new ancestor pid, is in that set, and gui_bursts._stop_strays (gui_bursts.py:83-85) kills only the remaining pids. Because _NET_WM_PID is written by the X client and every process in the desktop session can reach display :0 (images/desktop/agentbox-desktop-start:20,30,38), the attacker chooses which of its base-session processes look windowed, so the burst-end kill no longer bounds what keeps running.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "Agent token (lowest-trust network principal, prompt-injectable) posts a GUI input tool. GUI tools are in the allowed set with no approval (service.py:135-139), and GUI input executes as uid 1001 in the desktop session (sandbox_desktop.py:94-129)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 343,
   "scope": "AgentBox._call_tool -> _needs_snapshot",
   "description": "For GUI input _needs_snapshot is true, so _snapshot (250-265) takes the recovery snapshot and opens the burst, whose baseline is the workspace manifest plus the current pid set (gui_bursts.py:65-77)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 148,
   "scope": "AgentBox._run_tool (type)",
   "description": "The typed command is delivered into the desktop session as uid 1001. Whether the resulting shell or daemon ends up in a session that existed at burst open is a runtime fact of the image's terminal/launcher behaviour (tests/test_unit.py:330-334 models a terminal shell as a new session that is killed), not a source fact."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_bursts.py",
   "line": 120,
   "scope": "GuiBursts._finish",
   "description": "When the burst closes (close_idle, gui_bursts.py:137-155) the strays are collected and killed (120) before the closing manifest is read (122)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox_desktop.py",
   "line": 59,
   "scope": "DesktopTools.desktop_processes",
   "description": "window_pids is the isdigit-filtered set of xdotool getwindowpid values for every visible window with a non-empty name, i.e. client-declared _NET_WM_PID integers; no window ownership or declaring-client identity is checked (59-61)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/gui_state.py",
   "line": 85,
   "scope": "gui_strays",
   "description": "A new uid-1001 process in a burst-start session is spared when its pid is in window_pids, or when a non-baseline ancestor pid is, regardless of which process actually owns that window."
  },
  {
   "kind": "sink",
   "file": "agentbox/gui_bursts.py",
   "line": 85,
   "scope": "GuiBursts._stop_strays",
   "description": "kill_processes receives only the unexempted pids (kill -KILL -- <pids> as the desktop account, sandbox_desktop.py:64-67), so a forged-window daemon is not signalled and keeps modifying /workspace after the close."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/gui_state.py",
   "line": 85,
   "description": "The windowed test reads only window_pids (client-declared) plus a new-windowed-ancestor heuristic; nothing binds the spared pid to the window's owning client."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 80,
   "description": "The other exemptions are baseline pids, pid 1, non-1001 uids and from_exec (docker-exec roots), so for a base-session process the window test is the sole gate."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 63,
   "description": "base_sids is built only from the sessions of uid-1001 baseline pids, which is why the candidate's class is base-session processes."
  },
  {
   "file": "agentbox/gui_state.py",
   "line": 82,
   "description": "A process in a session that did not exist at burst open is killed regardless of any window, bounding the attack to base sessions."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 53,
   "description": "The docstring states the window set is the _NET_WM_PID of visible windows, a property the X client writes."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 59,
   "description": "The xdotool search --onlyvisible --name . / getwindowpid pipeline is run as the desktop account, so any uid-1001 client's windows are in scope."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 61,
   "description": "Output is split and filtered by isdigit only; nothing checks that the pid exists, owns a window, or is the declaring client, and the set is not intersected with procs."
  },
  {
   "file": "agentbox/sandbox_desktop.py",
   "line": 66,
   "description": "kill_processes signals only the pids it is given, as the desktop account; there is no cgroup or session-wide sweep elsewhere (kill_processes has no other caller)."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 80,
   "description": "The stated purpose of the kill is to stop GUI-launched background work that would otherwise keep changing files outside policy after the burst ends."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 88,
   "description": "Only the selected pids are logged as gui_processes_stopped, so a spared daemon leaves no failure record; my run shows the forged case logs nothing and the control logs the kill."
  },
  {
   "file": "agentbox/gui_bursts.py",
   "line": 122,
   "description": "The closing manifest is read after the kill, and nothing reads /workspace again between bursts, so a survivor's later writes are never diffed."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 20,
   "description": "Xvfb, the Xfce session and every GUI tool run as the desktop account via setpriv (19-23, 30, 38), so the display is reachable by uid-1001 code in that session."
  },
  {
   "file": "images/desktop/agentbox-desktop-start",
   "line": 38,
   "description": "startxfce4 runs as the desktop account, the identity the agent's typed GUI input inherits."
  },
  {
   "file": "images/desktop/Dockerfile",
   "line": 18,
   "description": "Installed packages are xvfb, xauth, x11vnc, socat, xdotool, scrot, x11-xserver-utils, Xfce, thunar, xfce4-terminal, mousepad, procps and base tools; there is no x11-utils (xprop), no python and no compiler, so whether the image can set an arbitrary _NET_WM_PID at all is a runtime fact."
  },
  {
   "file": "tests/test_unit.py",
   "line": 332,
   "description": "The intended-behaviour test models the shell and job inside a burst-opened terminal as a new session (152) and keeps them in the kill list, which is the precondition this candidate needs to overcome."
  },
  {
   "file": "agents/v05/artifacts/v05_probe.out",
   "line": 3,
   "description": "My local run of the real gui_strays: with window_pids={300} the headless base-session daemon 300 is absent from the kill list; with the list naming 301 (line 4) or only the baseline ancestor 85 (line 5) it is killed."
  }
 ],
 "blockers": [
  "The decisive platform step is not observable here: this sandbox has no X server and no X client. Reproduced in the run (agents/v05/artifacts/v05_probe.out:25-33): DISPLAY unset, /tmp/.X11-unix absent, xdotool/xprop/Xvfb absent, python Xlib absent. So neither 'a uid-1001 client sets _NET_WM_PID to another process's pid' nor 'xdotool getwindowpid reports that value for its window' can be observed.",
  "Related image fact: the recipe (images/desktop/Dockerfile:17-23) provides xdotool and socat but no xprop/x11-utils, no python and no compiler, and xdotool has no generic property setter. Whether the running image contains any program able to write an arbitrary _NET_WM_PID (base-layer or Xfce component, or a hand-written X11-protocol client over the unix socket via socat) must be read from the live image; if none exists the forgery route is refuted for this image and only the by-design ancestor route remains.",
  "Reachability needs the daemon's sid to be one that existed at burst open (gui_state.py:63,82-84): a typed command's shell normally gets a new session (tests/test_unit.py:330-334, my line 8). Whether GUI-only input can place a headless daemon in the startxfce4 session is a runtime property of the image's terminal/launcher behaviour.",
  "Observing survival after a real idle close needs the Docker-backed desktop container (docker exec for ps, xdotool, kill and the audit read); the Docker daemon is forbidden in this verifier sandbox, so the end-to-end kill/no-kill result and the missing gui_processes_stopped row are shown only against the real pure function and the real _stop_strays with a fake container."
 ],
 "validation_plan": {
  "local": "Disposable agentbox-desktop:0.1 container, network none, built from the audited tree, dummy files only. (1) Record `command -v xprop python3 gcc cc socat xdotool` and `dpkg -l x11-utils` as the property-setter inventory. (2) Start the desktop; as the desktop account via docker exec -u desktop, first start the helper in a burst-start session (launched from the panel/Thunar or from a pre-existing windowed app) and confirm with `ps -eo pid=,ppid=,sid=,uid=,args=` that its sid equals a session that predates the burst; then start the headless writer `sh -c 'while :; do date +%s >> /workspace/_v05_probe; sleep 2; done' &` in that same session. (3) With the inventory from step 1, map a 1x1 titled visible window in that session and set its _NET_WM_PID to the writer's pid (a second window may carry the helper's own pid). If no tool can set the property, stop: the forgery route is refuted for this image. (4) Call the real SandboxManager.desktop_processes(sid) and feed procs/wins into the real gui_state.gui_strays with baseline = the pids taken immediately before step 2; record the wins set and the returned kill list. Expected if the finding holds: the writer pid is absent from the list, while the same call with wins=set() returns it. (5) Call kill_processes(sid, returned list), then confirm by ps that the writer still runs and that /workspace/_v05_probe's mtime advances past AGENTBOX_GUI_SNAPSHOT_IDLE. Non-destructive: dummy probe file only, writer killed and container discarded at the end.",
  "deployment": "Owner-observed on a disposable desktop sandbox with dummy tokens and dummy files: during a real burst drive the agent's click/type to open a terminal from the panel and start `nohup sh -c \"while :; do date +%s >> /workspace/_v05_probe; sleep 2; done\" &`, plus the property helper if the image has one. Just before close record `ps -eo pid=,ppid=,sid=,uid=,args=` and `for w in $(xdotool search --onlyvisible --name .); do xdotool getwindowpid $w; done`, let the burst close on AGENTBOX_GUI_SNAPSHOT_IDLE, then read GET /audit as the human: the gui_processes_stopped record for that close must omit the writer pid, an exec ps must still show it running, and no later gui_changes row may exist for its writes. Refuted if the writer is killed, or if its session is new so the sid rule kills it, or if the image has no property setter. Fix check: exempt only baseline pids/sessions and control-plane docker-exec ancestry, or bind any spared pid to a control-plane-verified owner (for example the X socket owner in /proc/<pid>/fd) instead of trusting _NET_WM_PID. Audit reads and dummy files only."
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

# Execution boundary and paths

- Agent ID `r05`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r05/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r05 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r05 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
