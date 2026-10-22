# agentbox 보안 감사 run-3 — 검증이 더 필요한 후보 (NEEDS VALIDATION)

[`findings.json`](findings.json)의 `needs_validation` 레코드에서 그대로 만든 문서다(`tools/gen6.py`). 레코드 원문(영어)을 그대로 옮겼다. **확정 취약점이 아니며 심각도를 매기지 않는다.** 각 항목은 소스에서 경로가 확인됐지만, 결론을 가를 사실 하나가 소스와 로컬 sandbox 밖에 있다. 해소 계획은 일회용 로컬 환경이나 운영자가 자기 설정을 보는 방법만 적었고, 배포된 서비스에 감사 트래픽을 보내는 방법은 적지 않았다.

순서는 에이전트(가장 낮은 신뢰 주체)가 혼자 닿을 수 있는지, 막힌 사실이 얼마나 좁은지 기준의 우선순위다.

검증되지 않은 후보 1건(`agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion`)은 여기 들어가지 않는다. 독립 검증을 거치지 않았기 때문이다. [`REPORT.md`](REPORT.md) 1절을 본다.

## 1. v10 — Human screen takeover (safety override) blocks behind an untimed agent GUI exec holding gui_lock while the in-container X server is unresponsive

- fingerprint: `agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover`
- 판정: needs_validation (심각도 없음, 확정 취약점 아님)

### 설명

Agent GUI tools (screenshot/click/type/key) run through AgentBox._run_tool, which acquires desktop.gui_lock(sid) and calls SandboxManager._x -> docker exec_run (scrot/xdotool) with no container-side timeout wrapper, unlike exec (timeout -k 5), read_file and outbox_read (timeout -k 2 30). takeover and handback acquire the same plain threading.Lock via `with`, with no acquisition deadline. If the X server stops answering while an agent GUI exec is outstanding, that exec blocks inside the held lock, so the human takeover (the safety override for a misbehaving screen) and handback queue behind it. Source chain verified at the cited lines; gui_lock is a plain threading.Lock (desktop.py:155-158). Parent-live evidence (the parent's, not the verifier's; no Docker here): l1_takeover.py SIGSTOPs Xvfb (uid desktop=1001) in a real desktop sandbox, issues an agent screenshot that hangs holding gui_lock, then starts a takeover: it does not return within 20 s. l10_bound.py (after Phase 3) ran the same setup for 150 s: after 151 s both the screenshot and the takeover were still blocked, and both returned only after SIGCONT (screenshot 153 s, takeover 151 s). So the hang is not capped by the docker SDK client timeout and the lock is not released by a ReadTimeout, which settles the bound: the lockout lasts as long as X stays unresponsive. Not yet established: that a prompt-injected agent, using only its own agent-token capabilities, can itself make X unresponsive. The parent's SIGSTOP was a docker exec as uid 1001, standing in for a GUI terminal step (N-1). Source makes it plausible: the type/key tools can drive xfce4-terminal (Dockerfile:19), which runs as the same uid as Xvfb, and a process may signal another process of its own uid.

### 주장된 근본 원인

gui_lock is held across SandboxManager._x exec_run with no container-side timeout wrapper (unlike exec/read_file/outbox_read, which use `timeout -k`), and takeover/handback acquire the same plain threading.Lock unconditionally with no acquisition deadline, so a hung GUI exec serializes the human safety override behind it for as long as the in-container X server is unresponsive.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:205` `call_tool` — Lowest-trust agent token POSTs a GUI tool (screenshot/click/type/key) to /sandboxes/{sid}/tools/{tool}, dispatched on tool_pool.
2. **propagation** `agentbox/service.py:106` `AgentBox._run_tool` — For GUI tools, acquires `with self.desktop.gui_lock(sid):` and runs the GUI method while holding it.
3. **propagation** `agentbox/sandbox.py:684` `SandboxManager._x` — Runs c.exec_run(argv, user=desktop, ...) for scrot/xdotool with no container-side `timeout -k` wrapper, so the exec blocks for as long as X is unresponsive.
4. **sink** `agentbox/service.py:464` `AgentBox.takeover` — Human takeover (safety override) acquires the same gui_lock via a plain `with` (no deadline) and cannot return until the hung GUI exec releases it.

### 확인된 근거

- `agentbox/service.py:106` — `with self.desktop.gui_lock(sid):` wraps the entire GUI tool execution in _run_tool.
- `agentbox/sandbox.py:684` — _x returns c.exec_run(argv, user=DESKTOP_USER, environment=DESKTOP_ENV, demux=True) with no `timeout -k` wrapper.
- `agentbox/sandbox.py:531` — By contrast, exec wraps argv in a container-side `timeout -k 5 <t>`; read_file (561) and outbox_read (665) use `timeout -k 2 30`; _x has no equivalent bound.
- `agentbox/sandbox.py:286` — self.client = docker.from_env() with no explicit timeout; parent-live l10 shows the exec still blocked at 151 s, so this client default does not bound the hang.
- `agentbox/service.py:475` — handback also acquires gui_lock via a plain `with`, unconditionally and with no acquisition deadline.
- `agentbox/service.py:464` — takeover acquires gui_lock with the inline comment that it waits until the running GUI tool finishes; no timeout/409 path.
- `agentbox/desktop.py:155` — gui_lock(sid) returns self._gui.setdefault(sid, threading.Lock()), a plain threading.Lock acquired only via `with` (no timeout) everywhere it is used.
- `images/desktop/agentbox-desktop-start:22` — `as_desktop Xvfb :0 ...` runs the X server as uid 1001 (desktop), the same account as GUI-launched programs.
- `images/desktop/Dockerfile:19` — The desktop image ships xfce4-terminal, so the agent's key/type tools (sandbox.py:740, 749) can reach a shell running as uid 1001, the same uid as Xvfb.
- `agents/parent-live/artifacts/l10_bound.out:1` — Parent-live: with Xvfb stopped, after 151 s the agent screenshot and the human takeover were both still blocked; they returned only after SIGCONT (153 s / 151 s). Stand-in: the stop was done by docker exec as uid 1001, not by the agent.

### 막혀 있는 사실 (blockers)

- Whether a prompt-injected agent, using only its own agent-token calls (key/type/click to open a GUI terminal as uid 1001 and run e.g. `kill -STOP $(pgrep -x Xvfb)`), can itself make the in-container X server unresponsive so that a following agent GUI call hangs holding gui_lock. The parent-live runs (l1_takeover.py, l10_bound.py) induced the stall with a docker-exec SIGSTOP as uid 1001 as a stand-in for that GUI step. It decides between an agent-triggerable lockout of the human override and an owner-induced X freeze, and needs the live Docker daemon and agentbox-desktop:0.1.

### 해소 계획

**로컬 (범위 제한 fixture):**

Disposable desktop sandbox on a real Docker daemon with agentbox-desktop:0.1 (loopback only, dummy tokens), driven only through box.call_tool / POST /sandboxes/{sid}/tools/{tool} with the agent token (no docker exec after create): (1) call key `ctrl+alt+t` (or click the panel terminal launcher), then type `kill -STOP $(pgrep -x Xvfb)` followed by key `Return`; (2) issue one agent screenshot and record whether it hangs; (3) start a takeover from a UI session and record whether it returns within 60 s. Then SIGCONT Xvfb with docker exec as cleanup and record the elapsed times. If the keybinding fails, use an equivalent agent-reachable step (panel launcher click). A pass reproduces the l10 result with no owner-side signal and promotes the record to confirmed. Fix check: wrap _x argv in a container-side `timeout -k 2 N` as exec/read_file/outbox_read do, and have takeover/handback use gui_lock.acquire(timeout=...) returning 409/503 on contention so the human override is never serialized unboundedly behind an agent GUI exec.


---

## 2. v09 — GUI burst open treats failed container-side collection as success (empty baseline or no burst) with no audit record

- fingerprint: `agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit`
- 판정: needs_validation (심각도 없음, 확정 취약점 아님)

### 설명

When the first agent GUI input of a burst arrives, AgentBox._snapshot takes a docker-commit snapshot and then calls _open_gui_burst. That method collects the /workspace manifest and the desktop process baseline. Two silent fail-open paths exist. (a) Exit status unchecked (observed live): SandboxManager.workspace_manifest runs the root `find ... | head -c` exec and returns `_parse_manifest(res.output[0] or b"")` without checking res.exit_code. If the in-container command cannot run, it returns ({}, False) with no exception, and _open_gui_burst records the burst against an empty baseline. desktop_processes and kill_processes ignore exec status in the same way. At close, the diff reports every pre-existing file as added. The audit event carries counts and truncated=True plus only the first 100 sorted paths, so the real GUI-made change can fall outside the listed paths, and nothing records that the baseline collection failed. Parent-live l7 measured this on agentbox-desktop:0.1 with the pids cgroup at 1022-1024/1024, using pressure created by direct docker exec as uid 1001: the manifest had 0 entries, the burst was recorded, the audit showed only tool_request/policy_decision/snapshot/tool_result, and a close after the pressure ended gave gui_changes added=301, truncated=True, with the real change zz_changed_by_gui.txt absent from the listed 100. (b) Exception swallowed: if either collector raises, the bare `except Exception: return` at service.py:210 records no burst. Later GUI inputs inside the idle/interval window open no new burst, so there is no stray kill and no gui_changes for that window. The same pattern at :221 and :238 skips the kill or the diff at close. A mock reproduces this, but no agent-reachable raising trigger is known. Agent reachability (parent-live l9): an approval-free exec under the default read-only-exec rule (uid 1000) filled the pids cgroup to 1024/1024 within about 1 s, and a concurrent agent GUI input (key shift) still returned 200 and recorded a burst with 0 manifest entries and no audit marker. The pressure did not release itself: the exec ended with exit 254, about 1000 uid-1000 processes survived, pids stayed at 1022/1024 even after a root `pkill -x tail` by the parent, and a close under that pressure logged no gui_changes at all. A sandbox wedged this way can start no new processes, which limits what the agent can do while the condition holds. Not yet shown: an agent-only sequence that ends with a misleading or absent gui_changes record while a real GUI-made change exists. Bounds: the burst snapshot is still taken and logged, so the restore point survives. gui_changes is a detective, partial control, and the GUI is approval-free by design (N-1). Provenance: the l7/l9 scripts imported the working branch /home/user/agentbox rather than the audited tree. The burst, collector and policy code they exercise is byte-identical between the two, so the results apply to the audited source. The decisive live runs are the parent's.

### 주장된 근본 원인

Burst bookkeeping treats a failed container-side collection as a successful one. workspace_manifest (sandbox.py:495-501), desktop_processes (sandbox.py:689-692) and kill_processes (sandbox.py:697) never check exec exit status, and _open_gui_burst/_stop_gui_strays/_close_gui_burst (service.py:210, 221, 238) swallow every exception. In both cases there is no audit event and no fail-closed fallback, such as refusing further GUI input or marking the burst baseline invalid.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:205` `POST /sandboxes/{sid}/tools/{tool} (call_tool)` — Agent token (lowest-trust principal, own sandbox) sends a GUI input tool (key/click/type). Policy default is allow, with no approval.
2. **propagation** `agentbox/service.py:339` `AgentBox._call_tool` — On an allowed GUI input that starts a burst (_gui_needs_snapshot true), it calls _snapshot.
3. **propagation** `agentbox/service.py:264` `AgentBox._snapshot` — After docker commit, it opens the GUI burst with the new snapshot id.
4. **propagation** `agentbox/sandbox.py:501` `SandboxManager.workspace_manifest` — Root find exec result is parsed without checking exit_code. A failed exec returns ({}, False) instead of raising.
5. **sink** `agentbox/service.py:212` `AgentBox._open_gui_burst` — Burst is recorded with the empty manifest as its baseline, with no audit event marking the collection as failed. A later gui_changes diff reports all existing files as added and can leave the real change out of the 100 listed paths.

### 확인된 근거

- `agentbox/service.py:210` — except Exception: return in _open_gui_burst. A raising collector leaves no burst and no audit record.
- `agentbox/service.py:221` — except Exception: return in _stop_gui_strays. A failed ps/xdotool/kill skips the stray kill silently.
- `agentbox/service.py:238` — except Exception: return in _close_gui_burst. A failed close-time manifest skips gui_changes silently.
- `agentbox/service.py:246` — gui_changes lists only v[:100] of each sorted diff list plus counts and a truncated flag, so an empty baseline buries the real change.
- `agentbox/sandbox.py:689` — desktop_processes ignores the ps exit status. A failed exec yields an empty process list.
- `agentbox/sandbox.py:697` — kill_processes ignores the kill exec's exit status.
- `agentbox/default_policy.yaml:22` — read-only-exec allow rule includes tail, so the l9 pressure exec is approval-free.
- `agents/parent-live/artifacts/l7_burst_open.out:8` — Live: under pid pressure, workspace_manifest returned 0 entries with no exception.
- `agents/parent-live/artifacts/l7_burst_open.out:11` — Live: first GUI input still 200, burst recorded with baseline manifest entries 0.
- `agents/parent-live/artifacts/l7_burst_open.out:13` — Live: after pressure ends, the next GUI input opens no new burst, so the degraded burst persists.
- `agents/parent-live/artifacts/l7_burst_open.out:15` — Live: close gives gui_changes added=301, truncated=True, and the real change is not in the listed 100 paths. Control at line 3 shows added=1 with the change listed.
- `agents/parent-live/artifacts/l9_agent_pressure.out:4` — Live: the agent's approval-free exec drove pids to 1024/1024 within about 1 s, before the GUI input.
- `agents/parent-live/artifacts/l9_agent_pressure.out:5` — Live: the agent's GUI input under that pressure returned 200 and recorded a burst with 0 manifest entries.
- `agents/parent-live/artifacts/l9_agent_pressure.out:6` — Live: the audit shows only tool_request, policy_decision, snapshot and tool_result, with no event marking the failed collection.
- `agents/parent-live/artifacts/l9_agent_pressure.out:7` — Live: the agent exec ended with exit 254 while pids stayed at 1022/1024, so the pressure is not self-releasing.
- `agents/parent-live/artifacts/l9_agent_pressure.out:10` — Live: with the pressure persisting, the close logged no gui_changes record, so the end-to-end misleading-diff result via the agent-only path is not shown.
- `agents/parent-live/artifacts/l9_probe.out:2` — Live: after the exec returned, about 1002 uid-1000 processes remained in state S.
- `agents/parent-live/artifacts/l9_agent_pressure.py:10` — The script imports the working branch, but the burst/collector/policy code it exercises is byte-identical to the audited tree.
- `agents/v09/artifacts/v09_burst.out:2` — Mock: a raising workspace_manifest at open leaves no burst, with no new burst on the next input, no kill and no gui_changes (lines 3-5).
- `agents/v09/artifacts/v09_burst.out:8` — Real SandboxManager collectors with a fake container whose exec exits 126 return empty results without raising.
- `agents/v09/artifacts/v09_burst.out:13` — Real _close_gui_burst with an empty baseline: added=301, truncated=True, real change not listed. The control on line 15 lists it.
- `agents/v09/artifacts/v09_policy.out:2` — Default policy decides allow (read-only-exec) for the pressure command.

### 막혀 있는 사실 (blockers)

- Not observed on the live image: an agent-only sequence that ends with a misleading or absent gui_changes record while a real GUI-made change exists. l9 shows only the first half (agent exec pressure, then agent GUI input, then an empty-baseline burst with no audit marker). The pressure did not release (exit 254, pids stayed at 1022/1024, even after the parent's pkill), so the change step and close ran under full pids and the close logged nothing. Decisive missing facts: (a) whether the pressure can be released, or left with enough headroom for the open to fail while later steps still work; (b) whether a GUI-made change that needs no new process is recorded or silently missed at close. This needs a parent-live Docker observation; the verifiers have no Docker access.
- No agent-reachable trigger is identified for the exception path at service.py:210/221/238 (a Docker API error, a container not running, or the docker client's read timeout during collection). This path stays mock-only.

### 해소 계획

**로컬 (범위 제한 fixture):**

Parent-live, Docker-backed, disposable desktop sandbox, dummy tokens, scratch AGENTBOX_HOME, loopback only, importing the audited tree. Create 300 workspace files, then reproduce the l9 empty-baseline burst. Restore headroom (record whether an agent-reachable means sufficed or the host had to release it), make a GUI-only change to /workspace/zz_changed_by_gui.txt, wait past gui_snapshot_idle, and read GET /audit as the human. The finding holds if the burst has 0 manifest entries, no event marks the collection failure, and gui_changes shows added about 301, truncated=True, with the change unlisted. The control without pressure must show added=1 with the file listed. Also check the persistent-pressure case: a change made with a shell builtin in an already-open terminal, and whether the close leaves any record. The finding is refuted if the GUI input fails with 503 or the manifest is complete. Fix check: the collectors raise SandboxError on a nonzero exit, and the burst methods log a gui_burst_error audit event and mark the baseline invalid.

**운영자 관찰 (배포 대상에 감사 트래픽을 보내지 않음):**

Owner-observed on a non-production desktop sandbox with the deployment's pids, exec timeout and GUI idle settings: confirm whether the human-facing timeline shows any sign that the burst baseline was lost, whether the pressure persists after the exec returns, and whether the GUI-made change is visible without restoring the burst snapshot.


---

## 3. v15 — gui_strays exempts burst-launched uid-1001 processes from the stray kill based on window ownership, including the client-declared _NET_WM_PID

- fingerprint: `agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process`
- 판정: needs_validation (심각도 없음, 확정 취약점 아님)

### 설명

At GUI-burst close, AgentBox._stop_gui_strays collects uid-1001 processes and the set of window-owning pids and calls gui_strays. A new (non-baseline, non-exec-rooted) uid-1001 process that lives in a session that existed at burst start (base_sids) is spared whenever it is 'windowed': its own pid is in window_pids, or a NON-baseline ancestor's pid is in window_pids. window_pids come from `xdotool getwindowpid`, which returns the _NET_WM_PID property each X client sets for itself. Two routes can therefore spare background work started during the burst. (a) Without any forgery, a newly opened windowed app in the burst-start session (for example a file manager or editor started during the burst) exempts the scripts and children it spawns, because the ancestor clause only requires the windowed ancestor to be non-baseline. (b) A GUI client that declares another process's pid in _NET_WM_PID makes that process, even a headless one, look windowed. Either way the process can survive the close and keep modifying /workspace outside any monitored burst, which weakens the N-1 partial mitigation. Children of a PRE-EXISTING windowed baseline app are still killed, because the ancestor clause excludes baseline ancestors. Processes in a new session (terminal shells, setsid or nohup) are killed regardless of window (line 218). In the image, Xfce is started by the start script (agentbox-desktop-start:30), so apps launched from Xfce probably inherit a burst-start sid. This is not observable from source. The image has no python, xprop or compiler (Dockerfile:17-21), so route (b) needs a hand-written X client.

### 주장된 근본 원인

Whether a new baseline-session process is spared is decided by window presence, derived from X window properties (including the client-settable _NET_WM_PID via xdotool getwindowpid) and a 'new windowed ancestor' heuristic, rather than by a control-plane-verifiable link such as the docker-exec ancestry already tracked. Target-controlled GUI clients, or any legitimately windowed app launched during the burst, therefore decide which of their descendants are treated as windowed apps or helpers and escape the kill.

### 경로 (trace)

1. **entrypoint** `agentbox/service.py:215` `AgentBox._stop_gui_strays` — Burst close ingests attacker-influenced container output: calls desktop_processes(sid) to get the process list and window pids, then gui_strays to classify which new uid-1001 processes to kill.
2. **propagation** `agentbox/sandbox.py:690` `SandboxManager.desktop_processes` — Window pids come from `xdotool search --onlyvisible --name .` then `xdotool getwindowpid $w`, i.e. the client-set _NET_WM_PID property, parsed into the wins set at line 692.
3. **sink** `agentbox/sandbox.py:221` `gui_strays` — A new baseline-session process is marked windowed (p.pid in window_pids, or a non-baseline ancestor pid in window_pids) and consequently NOT appended to the kill list at lines 223-224, so it survives the burst close.

### 확인된 근거

- `agentbox/sandbox.py:692` — wins = {int(x) ...} parsed from container-side xdotool getwindowpid output; the exemption input is controlled by the GUI clients inside the sandbox.
- `agentbox/sandbox.py:221` — windowed = p.pid in window_pids or any(a.pid in window_pids and a.pid not in baseline for a in ancestors(p)); windowed -> not killed. The ancestor clause spares helpers of any newly created windowed app even with truthful window pids.
- `agentbox/sandbox.py:189` — Docstring states windowed apps and their helpers (and burst-start processes and docker-exec-launched tools) are intentionally left running, so the only gate for a baseline-session process is window ownership.
- `images/desktop/agentbox-desktop-start:30` — startxfce4 is launched from the container start script, so Xfce-launched apps likely share a burst-start session id (base_sids) and are not caught by the new-session kill at sandbox.py:218.
- `agentbox/service.py:235` — _close_gui_burst pops the burst (233), runs the stray kill (235) and takes a single final manifest (236-240); nothing monitors /workspace afterwards, so any survivor's later writes are unrecorded.

### 막혀 있는 사실 (blockers)

- Reachability in agentbox-desktop:0.1: whether, using only GUI input (click/type/key), a prompt-injected agent can get a uid-1001 process into a session that existed at burst start (base_sids) that either owns a visible window reported by `xdotool getwindowpid`, or descends from a newly created windowed process (for example a script run from a file manager or app window opened during the burst), or has its pid forged into another client's _NET_WM_PID. Real session ids (whether launcher, terminal or file-manager spawned processes inherit the Xfce start-script sid or get a new setsid session, which line 218 kills regardless) and real _NET_WM_PID values are not observable from source or from a pure-function harness over gui_strays, and the Docker daemon is unavailable offline. The pure-function harness already confirms the exemption logic itself.

### 해소 계획

**로컬 (범위 제한 fixture):**

In a disposable, network-less agentbox-desktop:0.1 sandbox: open a GUI burst with a GUI tool call. Using GUI input only, (a) open a file manager or editor window during the burst and from it run a script that appends a timestamp to a dummy file /workspace/_v15_probe every ~2s; and (b) separately, with a hand-written X client, set _NET_WM_PID of a window to the pid of a headless background writer started from a burst-start-session launcher. Just before close, record `ps -eo pid=,ppid=,sid=,uid=,args=` and `for w in $(xdotool search --onlyvisible --name .); do xdotool getwindowpid $w; done` to capture the real session ids and window-pid set, and feed them through the real gui_strays to predict survivors. Let the burst close on idle; then read the gui_processes_stopped audit entry and check whether /workspace/_v15_probe's mtime keeps advancing after close. Non-destructive: touches only the dummy probe file; kill the probe and discard the sandbox afterward.

**운영자 관찰 (배포 대상에 감사 트래픽을 보내지 않음):**

Owner reproduces the same probe on the live deployed image and config to confirm the image's session-id and _NET_WM_PID semantics and that a spared process (or its child) modifies /workspace after burst close; collect the gui_processes_stopped and gui_changes audit entries and the manifest diff as evidence. Fix check: exempt only burst-start (baseline) processes and control-plane docker-exec-launched components, deriving ownership from a control-plane-verifiable link (for example the exec/ancestry already tracked) rather than window presence or the client-declared _NET_WM_PID. Non-destructive: dummy file only.


---

## 4. v14 — Cookie-authenticated web UI and desktop page set no frame-ancestors/X-Frame-Options, so a same-site origin can frame /ui/sandboxes/{sid} (or the desktop page) and a single disguised click approves a pending agent action or takes over the desktop

- fingerprint: `agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve`
- 판정: needs_validation (심각도 없음, 확정 취약점 아님)

### 설명

No agentbox HTML response sets CSP frame-ancestors or X-Frame-Options, api.build installs no middleware, and Caddy is a bare reverse_proxy, so every cookie-authenticated page is frameable. The session cookie is HttpOnly, SameSite=Strict, host-only and Path=/ (not port-scoped). A pure cross-site framer is blocked by SameSite=Strict (confirmed: the parent-live control framed from http://localhost:9999 and the frame fell back to /login). But a same-site origin -- another port on the same loopback host in local mode, or a sibling subdomain under the same registrable domain in proxy mode -- is same-site, so the browser sends the full-scope session cookie into a transparent iframe of /ui/sandboxes/{sid}#approvals. The approve/deny/snapshot buttons and the desktop takeover button are single-click (no hx-confirm; only restore/delete use hx-confirm). Because the click originates inside the framed agentbox document, the htmx/fetch POST carries Origin == Host, so same_origin() passes (it also allows a missing Origin), and box.decide(...actor='human') runs the agent's originally-gated args as a human-approved action. A prompt-injected agent controls its pending card text and can learn its sandbox id, aiding a same-site decoy in positioning the button. Parent-live Chromium confirmed the mechanics end-to-end; what remains unverified is whether a real deployment exposes a same-site origin an attacker can influence.

### 주장된 근본 원인

Cookie-authenticated HTML (render() in web.py sets only Cache-Control/X-AB-Version; desktop_page sets only Cache-Control; Caddyfile adds no headers; no middleware in api.build) carries no framing policy, and the state-changing UI actions rely only on SameSite=Strict plus same_origin() -- neither of which stops a same-site framer or a click induced inside the framed agentbox document. SameSite=Strict blocks only genuinely cross-site framers; it does not scope by port or subdomain, so a same-site origin defeats it.

### 경로 (trace)

1. **entrypoint** `agentbox/web.py:181` `sandbox_page GET /ui/sandboxes/{sid}` — Full authenticated UI page served (render()) with only Cache-Control/X-AB-Version; no frame-ancestors/X-Frame-Options, so it can be embedded in a cross-origin iframe.
2. **propagation** `agentbox/desktop.py:53` `set_cookie` — Session cookie is HttpOnly, SameSite=Strict, host-only, default Path=/, not port-scoped; sent on same-site cross-port / sibling-subdomain iframe loads (SameSite blocks only cross-site).
3. **propagation** `agentbox/templates/sandbox.html:25` `#approvals polling div` — Approvals fragment auto-loaded into the framed page (hx-get every 2s), rendering the pending approval card with its action buttons.
4. **propagation** `agentbox/templates/_approvals.html:19` `approve button` — Single-click hx-post /ui/approvals/{aid}/approve with hx-disabled-elt but no hx-confirm; one framed click suffices.
5. **propagation** `agentbox/api.py:110` `same_origin` — An in-frame POST from the framed agentbox document has Origin == Host (and a missing Origin is also allowed), so same_origin() returns True.
6. **propagation** `agentbox/web.py:209` `decide POST /ui/approvals/{aid}/{decision}` — Browser-session route (browser_human) calls box.decide(aid, approve=True, actor='human', session=p.session).
7. **sink** `agentbox/service.py:415` `AgentBox.decide` — _run_tool(sid, tool, args) runs the agent's originally gated args as a human-approved action.

### 확인된 근거

- `agentbox/web.py:88` — render() TemplateResponse sets only Cache-Control: no-store (plus X-AB-Version at line 92); no framing header. Grep over agentbox/ and deploy/ finds no X-Frame-Options/CSP/frame-ancestors and no add_middleware.
- `agentbox/api.py:313` — desktop_page returns HTMLResponse(D.page(...)) with only Cache-Control: no-store; the takeover/handback controls live in this frameable page.
- `deploy/Caddyfile:5` — Proxy mode is a bare reverse_proxy agentbox:8765 adding no response headers, so proxy deployments also lack framing headers.
- `agentbox/templates/sandbox.html:11` — agentbox frames its own desktop page (iframe src=/sandboxes/{sid}/desktop), so a correct fix must be frame-ancestors 'self' / X-Frame-Options SAMEORIGIN, not DENY.
- `agentbox/templates/_approvals.html:20` — Deny is also single-click; only restore/delete carry hx-confirm (sandbox.html:5, _snapshots.html), so approve/deny/snapshot/takeover are inducible with one blind click.
- `agentbox/desktop.py:332` — Desktop takeover button posts /takeover with no confirmation; combined with the frameable desktop page this clickjacks screen control.
- `agentbox/api.py:122` — screen_principal enforces only same_origin after the cookie lookup; a framed agentbox document satisfies it, so same_origin + SameSite=Strict are the only barriers and neither stops a same-site framer.

### 막혀 있는 사실 (blockers)

- Decisive deployment fact, outside source/local observation: whether a given deployment exposes an attacker-influenceable same-site origin -- another port on the same loopback host in local mode, or a sibling subdomain under the same registrable domain in proxy mode. SameSite=Strict blocks every pure cross-site framer (parent-live control: framing from http://localhost:9999 produced a frame that fell back to /login), and the assumed local attacker (a prompt-injected agent in a network_mode=none container) cannot itself bind a host port to create such an origin, so exploitation depends on an independent same-site foothold that source cannot establish.
- Cross-engine browser-policy behavior: the parent's real Chromium (agents/parent-live/artifacts/l3) is the decisive reproduction, not mine (jinja2/no browser in my sbx) -- it observed Chromium sending the SameSite=Strict host-only cookie into a same-site cross-port iframe and the in-frame htmx POST completing (apr_0fb8e904e830 -> executed, decided_by human). Firefox/WebKit same-site-cross-port iframe cookie behavior remains unobserved.

### 해소 계획

**로컬 (범위 제한 fixture):**

Already executed by the parent on loopback and reproducible: start the app with the fake-Docker shim via uvicorn on 127.0.0.1:8765 with a dummy human token; in Playwright Chromium (and additionally Firefox/WebKit) log in, create a pending exec approval for a dummy sandbox; serve evil.html from http://127.0.0.1:9999 with a decoy over an opacity-reduced iframe of /ui/sandboxes/{sid}#approvals; assert the frame URL stays on /ui/sandboxes/{sid} (not /login) and that clicking the decoy over the approve button yields approval status=executed, decided_by=human (parent-live l3.out shows exactly this for Chromium). Repeat for the desktop page takeover button. Control (must fail): serve from http://localhost:9999 (cross-site) -> frame redirects to /login (parent-live confirmed). Regression: add middleware setting X-Frame-Options SAMEORIGIN + CSP frame-ancestors 'self' and confirm the external frame is blocked while the in-app /sandboxes/{sid}/desktop iframe still loads.

**운영자 관찰 (배포 대상에 감사 트래픽을 보내지 않음):**

Owner runs curl -sI against deployed /ui, /login, /ui/sandboxes/{sid} and /sandboxes/{sid}/desktop to confirm no X-Frame-Options/CSP frame-ancestors are present (local, direct-TLS, and Caddy proxy modes), and enumerates same-host loopback ports and sibling subdomains under the same registrable domain that serve attacker-influenceable or XSS-prone content; the finding is exploitable only if at least one such same-site origin exists.


---

## 5. v01 — same_origin ignores the scheme, so a plaintext http:// page on the same host passes the CSRF origin check of a TLS deployment

- fingerprint: `agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare`
- 판정: needs_validation (심각도 없음, 확정 취약점 아님)

### 설명

Every cookie-authenticated UI mutation ultimately relies on same_origin() (api.py:108-110), which compares only urlsplit(Origin).netloc with the Host header and never the scheme. Verified in-sandbox: http://H, http://H:8765, and http://agentbox.example.com are all accepted against the matching Host, while sibling same-site, wrong port, and null are rejected. In a TLS deployment a page served as plaintext http://H (forgeable by an active network attacker; no Strict-Transport-Security is set anywhere in agentbox/, deploy/ or images/, and Caddy's reverse_proxy adds none) has a different web origin from https://H but passes this check. On a browser WITHOUT schemeful same-site, http://H and https://H count as same-site, so a SameSite=Strict Secure cookie (desktop.py:53) would be attached to the auto-submitted cross-scheme POST and agentbox would accept it. Id-free actions: POST /logout (ends the server session and hands desktop takeover back to the agent) and POST /ui/sandboxes (creates a sandbox with an attacker-supplied source_dir). Approve/deny additionally needs the 48-bit apr_ approval id (approvals.py:51, token_hex(6)), so a blind attacker is limited to the id-free actions. DECISIVE CAVEAT from parent-live evidence (agents/parent-live/artifacts/l3/l4.out, script l4.cjs): on Chromium 141 the cross-scheme POST had same_origin accept its Origin but the Secure SameSite=Strict cookie was NOT attached (schemeful same-site), so the session-ending and create attacks fail there; the only effect was the unconditional r.delete_cookie on the logout response clearing the browser cookie client-side (forced browser logout) WITHOUT ending the server session. Firefox and WebKit were not tested. The finding therefore stands only on browsers without schemeful same-site; the exploitable browser population and the HSTS/active-network-attacker deployment facts remain open.

### 주장된 근본 원인

api.py:108-110: same_origin() accepts when urlsplit(origin).netloc == headers['host'] with no scheme comparison, so the cross-origin defence degrades to the browser treating http/https of one host as cross-site; nothing in source emits Strict-Transport-Security (deploy/Caddyfile, agentbox/ and images/ set none), so an active network attacker can serve http://H.

### 경로 (trace)

1. **entrypoint** `agentbox/web.py:203` `decide (POST /ui/approvals/{aid}/{decision}); also create web.py:160, logout web.py:128` — Cookie-authenticated, form-encodable POST routes reachable by a cross-origin auto-submitted form; verified these are the state-changing UI mutations gated only by the cookie session plus same_origin.
2. **propagation** `agentbox/api.py:119` `screen_principal` — Resolves the cookie session via box.desktop.session_scope(cookie) (api.py:119), then same_origin(request.headers) at api.py:122 is the only origin binding for the cookie principal.
3. **propagation** `agentbox/api.py:110` `same_origin` — Returns True when urlsplit(origin).netloc equals Host; independently confirmed http://H matches Host H and missing Origin is allowed, so scheme is never compared.
4. **sink** `agentbox/web.py:209` `decide` — box.decide(aid, approve, actor='human', session=p.session) executes with the victim's session; peer id-free sinks are create_sandbox at web.py:164 and end_ui_session at web.py:132.

### 확인된 근거

- `agentbox/api.py:110` — Netloc-only comparison with no scheme check. Reproduced in-sandbox (agents/v01/artifacts/v01_same_origin.out): accepts http://H vs Host H, http://H:8765 vs H:8765, http://agentbox.example.com vs that host, and missing Origin; rejects sibling same-site, wrong port, and null.
- `agentbox/desktop.py:53` — set_cookie issues the session cookie HttpOnly, samesite='strict', secure=secure; under non-schemeful same-site http://H and https://H are same-site, so the Strict cookie is not separated by scheme.
- `agentbox/cli.py:106` — s.secure_cookie = s.secure_cookie or tls or behind: the Secure attribute is set for direct-TLS and behind-TLS-proxy deployments, which is the deployment class this finding targets.
- `deploy/Caddyfile:4` — reverse_proxy site block emits no Strict-Transport-Security; grep over agentbox/, deploy/ and images/ found no HSTS anywhere, so the browser is not forced to upgrade http://H to https.
- `agentbox/web.py:130` — logout's only guard is the scheme-blind same_origin (web.py:130); end_ui_session (web.py:132) ends the server session and hands takeover leases back to the agent when the cookie is present.
- `docs/security-audit/run-3/agents/parent-live/artifacts/l3/l4.out:4` — Parent-live (not a verifier reproduction) real Chromium 141, script l4.cjs: cross-scheme POST http://127.0.0.1 -> https://127.0.0.1/logout had same_origin accept the http Origin (netloc==Host) but the Secure SameSite=Strict cookie was NOT attached (schemeful same-site); server session not ended, only the delete_cookie forced a client-side logout. Resolves the Chromium 141 case as non-exploitable; Firefox/WebKit untested.

### 막혀 있는 사실 (blockers)

- Browser behaviour (decisive): whether any operator browser lacks schemeful same-site and so attaches a SameSite=Strict Secure cookie to a cross-scheme form POST from http://H to https://H. Only Chromium 141 was tested (cookie NOT attached, l4.out); Firefox and WebKit current behaviour and the legacy-version cut-offs are untested and cannot be determined from source.
- Deployment: whether the production host sends HSTS or is preloaded (none in source), and whether an active on-path network attacker who can serve plaintext http://H is in scope.

### 해소 계획

**로컬 (범위 제한 fixture):**

Isolated loopback browser lab: map H to 127.0.0.1, run a dummy agentbox with --tls-cert (self-signed, lab-trusted) on 443 and a plaintext http://H listener on 80 auto-submitting forms to https://H/logout and /ui/sandboxes. The parent already ran this on Chromium 141 and the Secure SameSite=Strict cookie was not attached (agents/parent-live/artifacts/l3/l4.out). Remaining local steps: repeat with current Firefox and WebKit, and with any browser/version or policy that disables schemeful same-site: log in to https://H, open http://H, and check whether agentbox_session is sent and the POST is accepted (303) rather than 403, and whether the server session is actually ended. Regression check on the fix: same_origin({'origin':'http://h','host':'h'}) must return False once the full scheme+netloc origin is compared.

**운영자 관찰 (배포 대상에 감사 트래픽을 보내지 않음):**

Owner confirms whether the production hostname sends HSTS (or is on the preload list) and which browser engines and versions operators actually use; if all are schemeful-same-site browsers and/or HSTS is present, the finding is not reachable. No live probing of deployed endpoints.

