# agentbox 보안 감사 run-3 — 확정 결과 상세 (medium 이상)

[`findings.json`](findings.json)의 최종 레코드에서 그대로 만든 문서다(`tools/gen6.py`). 레코드 원문은 영어이고 그대로 옮겼다. 판정·심각도·근거는 JSON과 같으며 이 문서가 바꾸지 않는다. low 5건(v03, v06, v17, v18, v19)은 [`REPORT.md`](REPORT.md)에 요약했다.

줄 번호는 감사 대상 소스 `0e4b958`(= `main`의 `8e4db9e`) 기준이다. 이 브랜치에는 이후 수정이 들어가 있어 줄이 다를 수 있다. `parent-live`라고 적힌 재현은 부모가 이 클라우드 컨테이너의 일회용 Docker에서 가짜 토큰으로 돌린 것이고, 산출물은 `agents/parent-live/artifacts/`에 있다.

## [high] v11 — Idle GUI burst close runs another sandbox's untimed docker execs inline on unrelated tool threads and human approval/audit threads

- fingerprint: `agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency`
- 심각도: likelihood medium · impact high · overall **high**; confidence high
- 수정 상태: 이 브랜치에 `c1f88da`로 수정됨. 회귀 테스트: `tests/test_m2_unit.py::test_idle_burst_close_does_not_run_on_caller_thread`, `tests/test_m2_unit.py::test_gui_execs_have_a_container_side_deadline`, `tests/test_m2_acceptance.py::test_frozen_display_does_not_hold_tools_or_takeover`

### 설명

close_idle_gui_bursts() iterates every sandbox's open GUI burst and is called before the per-sandbox tool_concurrency check at the start of every call_tool (service.py:273), from expire_stale (service.py:373, reached by GET /approvals, GET /approvals/{aid}, and POST /approvals/{aid} via decide->expire_stale at 385), and from GET /audit (api.py:258). Closing sandbox B's burst runs desktop_processes (ps + an xdotool search via _x) and workspace_manifest (find) and kill_processes against B's container with docker exec_run and no deadline. So B's maintenance runs on sandbox A's tool_pool thread or on a human request (Starlette threadpool) thread, outside B's tool_concurrency budget. If B's container/X server is unresponsive, the exec never returns and the unrelated caller blocks indefinitely. The burst is popped before closing (service.py:232), so one idle stuck burst permanently steals one caller thread; aggregating across many desktop sandboxes can exhaust the shared pools. The parent reproduced the cross-sandbox block against the real Docker-backed control plane: with B's Xvfb stopped and B's burst idle, A's list_dir did not return within 20s and returned 0.3s after B's Xvfb resumed.

### 근본 원인

close_idle_gui_bursts() runs cross-sandbox maintenance (burst close) inline on whatever thread calls it - a tool_pool thread of an unrelated sandbox (service.py:273, before the tool_concurrency check at 275-278) or a human request thread (expire_stale service.py:373 from GET/POST approvals and decide; GET /audit api.py:258) - and the docker execs it performs (desktop_processes xdotool via _x sandbox.py:684/690-691, workspace_manifest find 499, kill_processes 697) use exec_run with no deadline, unlike exec/read_file/outbox_read which wrap the command in 'timeout'. An unresponsive owning container therefore blocks the unrelated caller indefinitely, with the work charged to no sandbox's budget.

### 지켜야 할 불변식

Work done for sandbox B should be charged to B's tool_concurrency budget and never run inline on another sandbox's tool thread or a human request thread, and every docker exec (as exec/read_file/outbox_read already do) should carry a deadline so an unresponsive container cannot stall unrelated sandboxes or the human approval/audit path.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:206` `POST /sandboxes/{sid}/tools/{tool} (call_tool route)` — Agent of sandbox A posts any tool; it runs on the shared 32-thread tool_pool via run_in_executor (api.py:81,209-210). The same close_idle_gui_bursts maintenance is also reached from GET /audit (api.py:258) and, via expire_stale, from GET /approvals (217), GET /approvals/{aid} (222) and POST /approvals/{aid} decide (240-252) - all def routes on the Starlette threadpool.
2. **propagation** `agentbox/service.py:273` `AgentBox.call_tool` — close_idle_gui_bursts() runs before the per-sandbox _busy/tool_concurrency check at 275-278, so the burst-close work is charged to no sandbox's budget.
3. **propagation** `agentbox/service.py:254` `AgentBox.close_idle_gui_bursts` — Iterates list(self._gui_burst) - every sandbox's open burst - and closes any whose last GUI input is older than gui_snapshot_idle (default 60s) on the calling thread (loop 254-256), so sandbox B is closed on sandbox A's or a human's thread.
4. **propagation** `agentbox/service.py:235` `AgentBox._close_gui_burst` — Pops burst B (232) then calls _stop_gui_strays(B) (235) before workspace_manifest (237).
5. **propagation** `agentbox/service.py:218` `AgentBox._stop_gui_strays` — Calls self.sandboxes.desktop_processes(B) (218) against sandbox B's container.
6. **sink** `agentbox/sandbox.py:690` `SandboxManager.desktop_processes via _x` — docker exec_run of the xdotool search command (via _x at sandbox.py:684, user=desktop) with no 'timeout' wrapper, run against sandbox B's container. The calling thread (sandbox A's tool_pool thread or a human request thread) blocks in exec_start until B's X server replies; a stopped/unresponsive Xvfb never replies and exec_run has no deadline. workspace_manifest find (499) and kill_processes (697) on the same path are likewise untimed.

### 근거 (evidence)

- `agentbox/service.py:273` — close_idle_gui_bursts() is invoked before the tool_concurrency check at 275-278, so burst-close work is never counted against any sandbox's per-sandbox budget.
- `agentbox/service.py:256` — The loop closes the burst of any sid in self._gui_burst, not just the calling sandbox's (254-256); _close_gui_burst pops the burst at 232 so each stuck burst costs one caller rather than all callers.
- `agentbox/sandbox.py:684` — _x issues c.exec_run(argv, user=DESKTOP_USER, ...) with no 'timeout' wrapper; the docker SDK exec_run/exec_start exposes no deadline. Used by desktop_processes xdotool (690-691).
- `agentbox/sandbox.py:531` — Contrast: exec wraps the command in 'timeout -k 5 <exec_timeout>' (default 60); read_file (561) and outbox_read (665) use 'timeout -k 2 30'. The burst-close execs (499 find, 684/690-691 xdotool, 697 kill) have no such bound.
- `agentbox/service.py:373` — expire_stale() calls close_idle_gui_bursts(); decide() calls expire_stale() first (385), so a human approve/deny decision for any approval runs another sandbox's burst-close inline on the request thread.
- `agentbox/api.py:258` — GET /audit calls box.close_idle_gui_bursts() on the human request (Starlette threadpool) thread before listing.
- `agents/parent-live/artifacts/l2_cross.out:2` — Parent Docker-backed run (l2_cross.py): with sandbox B's Xvfb stopped and B's GUI burst idle, sandbox A's list_dir did NOT return within 20s, and returned 0.3s after B's Xvfb got SIGCONT - demonstrating A's unrelated tool call blocked indefinitely on B's untimed GUI exec.

### 공격 주체와 조건

A prompt-injected agent on its own desktop sandbox B. Victims are other sandboxes' agents and the human operator (approval decisions and audit reads), who share the same control plane thread pools.

- *authorization_role*: Lowest-trust network principal: a prompt-injected agent holding an agt_ token for a desktop-template sandbox. GUI tools have no approval gate by design (architecture: Agent -> GUI approval gate = none).
- *system_configuration*: Desktop mode (Xvfb/Xfce) enabled for at least one sandbox so GUI bursts exist. Defaults: gui_snapshot_idle=60s, tool_concurrency=4, tool_pool max_workers=32 (api.py:81).
- *environmental_dependency*: The owning container's X server (or the docker exec) must be unresponsive so the untimed exec_run does not return; docker exec_run/exec_start provides no deadline parameter. The parent induced this by SIGSTOP of Xvfb as the desktop user.
- *timing_dependency*: The victim's GUI burst must be idle (> gui_snapshot_idle) at the moment another sandbox's call_tool, a GET /audit, or an approval decision triggers close_idle_gui_bursts.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `POST /sandboxes/{B}/tools/click  {"x":5,"y":5}   (opens a GUI burst for sandbox B)`
- `inside B, as the desktop user (reachable via the ungated GUI tools / desktop shell): kill -STOP $(pgrep -x Xvfb)   (renders B's X server unresponsive)`
- `stop issuing GUI input for > gui_snapshot_idle seconds so B's burst becomes idle`

절차:

1. Create or use a desktop-template sandbox B and issue one GUI input tool so a GUI burst opens for B (service.py:_open_gui_burst via _snapshot).
2. From within B, make B's X server unresponsive (e.g. SIGSTOP Xvfb as the desktop user, or hold an XGrabServer); let GUI input go quiet so B's burst is idle past gui_snapshot_idle.
3. From an unrelated principal, trigger close_idle_gui_bursts: another sandbox A's POST /sandboxes/{A}/tools/list_dir (service.py:273), or a human GET /audit (api.py:258), or a human POST /approvals/{aid} decide (service.py:385->373).
4. Observe that the triggering request blocks until B's container becomes responsive again, while B's _busy/tool_concurrency counter stays unchanged.

관찰 결과:

Decisive reproduction is the parent's (l2_cross.py/.out, real Docker-backed control plane + agentbox-desktop image; I could not run Docker in the sandbox). With B's Xvfb stopped and B's burst idle, sandbox A's list_dir did not return within 20s and returned only 0.3s after B's Xvfb was resumed, confirming A's unrelated tool call blocked on B's untimed GUI exec run on A's tool_pool thread. The h-pool stub run (agents/h-pool/artifacts/h.out) independently showed that B's close runs on A's thread and on the human (expire_stale) thread while B's _busy counter stays 0, confirming the work is charged to no sandbox. Because decide() and GET /audit enter the identical close_idle_gui_bursts path on the Starlette threadpool, a human approval decision or audit read blocks the same way and the blocked thread is leaked for the burst's lifetime (burst popped at service.py:232).

### 영향과 우선순위 근거

- likelihood (medium): Requires a desktop sandbox and the agent to render its own X server/exec unresponsive; the GUI boundary is ungated by design and prompt injection is in the threat model, but weaponizing X unresponsiveness from the lowest-trust principal carries a desktop-image dependency (terminal/launcher reachability, X auth) that the parent demonstrated via a desktop-user action rather than a confirmed uid-1000-only path. The defect also triggers on benign causes (a slow or overloaded desktop container, a slow Docker exec), so exposure is not solely attacker-gated.
- impact (high): A single unresponsive desktop container indefinitely blocks an unrelated sandbox's tool call (demonstrated: 20s, bounded only by the test's external SIGCONT) and, by the identical close_idle_gui_bursts path, a human approval decision (POST /approvals/{aid}) or GET /audit, degrading the human-oversight safety function; the blocked shared control-plane thread (tool_pool of 32 or the Starlette threadpool) is leaked for the burst's lifetime. Single-principal effect is one leaked thread plus one indefinitely blocked cross-tenant request per compromised desktop sandbox (burst popped before close); aggregated across many desktop sandboxes it can exhaust both pools. Cross-tenant, persistent, poor recovery (operator must intervene).
- confidence (high): The entire source path was verified by reading: service.py:273 (before busy check 275-278), 254-256 (iterates all sandboxes), 232/235, 218 -> sandbox.py:684/690-691 untimed _x exec, with the timeout contrast at 531/561/665 and human entrypoints at api.py:258 and decide->expire_stale (385->373). The decisive runtime behaviour - the untimed exec blocks the caller indefinitely and blocks an unrelated sandbox - was reproduced by the parent against the real Docker-backed control plane and desktop image (agents/parent-live/artifacts/l2_cross.py/.out); I re-read that script and confirmed it exercises exactly this path, and I could not run it myself because the verification sandbox has no Docker. Source contains no deadline or per-sandbox accounting bound that refutes the trace.

### 수정 방향

Put a hard deadline on every docker exec reached from the burst-close and GUI paths (wrap the container command in 'timeout -k' as exec/read_file/outbox_read do, and/or use a client call with a socket timeout), and stop running cross-sandbox maintenance inline on an unrelated caller's thread: close idle bursts in a dedicated background worker, or charge each close to the owning sandbox's tool_concurrency budget and never to another sandbox's tool thread or a human request thread. Guard close_idle_gui_bursts/_close_gui_burst so one unresponsive container is skipped-and-logged after a bounded wait instead of stalling the loop for other sandboxes.

`agentbox/sandbox.py`:

```python
# Give the maintenance/GUI execs the same deadline exec() uses, so an
# unresponsive container cannot block the control plane indefinitely.
@staticmethod
def _x(c, argv: list[str]):
    return c.exec_run(["timeout", "-k", "2", "15", *argv], user=DESKTOP_USER,
                      environment=DESKTOP_ENV, demux=True)

def workspace_manifest(self, sid):
    c = self._container(sid)
    res = c.exec_run(["timeout", "-k", "2", "15", "sh", "-c",
        f"find {WORKSPACE} -xdev ! -type d -printf '%P\\0%s\\0%T@\\0%C@\\0' | head -c {_MANIFEST_CAP}"],
        user="0:0", demux=True)
    return _parse_manifest(res.output[0] or b"")

def kill_processes(self, sid, pids):
    if pids:
        self._desktop(sid).exec_run(["timeout", "-k", "2", "10", "kill", "-KILL", "--", *map(str, pids)],
                                    user=DESKTOP_USER)
```

`agentbox/service.py`:

```python
# Do not run another sandbox's burst-close inline on the caller's thread.
# Hand idle-burst closing to a single background worker so a stuck container
# never blocks an unrelated call_tool, a human approval decision, or GET /audit.
def close_idle_gui_bursts(self) -> None:
    idle = self.sandboxes.settings.gui_snapshot_idle
    now = time.monotonic()
    for sid in list(self._gui_burst):
        if now - self._gui_input_at.get(sid, 0.0) > idle:
            self._gui_closer.submit(self._close_gui_burst, sid, "idle")  # bounded background pool
```


---

## [medium] v02 — The UI and CLI audit timelines stop at the 5000th row, so an agent can push its later actions out of the human's view

- fingerprint: `agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines`
- 심각도: likelihood medium · impact medium · overall **medium**; confidence high
- 수정 상태: 이 브랜치에 `3587c9c`로 수정됨. 회귀 테스트: `tests/test_unit.py::test_audit_recent_is_newest_with_real_total`, `tests/test_unit.py::test_cli_audit_pages_past_5000`

### 설명

The sandbox page's audit fragment (GET /ui/audit, re-polled every 3 s) and `agentbox audit` both fetch rows with AuditLog.list(limit=5000) and no after_id. AuditLog.list is `WHERE id > ? [AND sandbox_id = ?] ORDER BY id LIMIT ?`, so it returns the OLDEST 5000 matching rows, and nothing is ever pruned. Once a sandbox (sandbox page, `agentbox audit --sandbox`) or the whole system (default `agentbox audit`) holds more than 5000 rows, the UI shows the last 400 of the oldest window (ids 4601-5000, total capped at 5000) and the CLI prints rows 1-5000. Every later row (tool_request/tool_result, snapshot, human_takeover/handback, gui_processes_stopped, gui_changes) is never shown, while the UI footer keeps saying it shows the most recent 400 of 5000. The UI window is per sandbox; the default CLI view is system-wide, so one sandbox's volume also hides other sandboxes' later events from it. A prompt-injected agent that holds only its own sandbox's agent token can reach the threshold without any approval: one approval_forbidden row per refused POST /approvals/{any id} (no Docker, no rate limit; needs raw API access with the token), or three rows per allowed tool call such as list_dir or exec of an allowlisted read-only command (about 1,670 calls through the ordinary MCP tools). Correction to the hunter's example: `exec true` is not an approval-free path, because default_policy.yaml lists true/false unquoted (line 27) and PyYAML parses them as booleans, so that call returns 202 and needs approval; `exec ls`, `exec echo` and list_dir are allowed. Long-lived ordinary sandboxes reach the same threshold without any attacker. The rows stay in the database, GET /audit?after_id=... returns them, verify passes and the approval queue is unaffected; only the two views humans actually use stop updating.

### 근본 원인

AuditLog.list (audit.py:190-197) can only return the oldest `limit` rows after `after_id` (ORDER BY id ascending). Both human-facing consumers call it with limit=5000 and no after_id and then treat the result as the newest window: web.py audit_frag takes rows[-400:] and total=len(rows), and cli.py cmd_audit prints the whole list. Beyond 5000 rows the 'tail' is the tail of the oldest 5000, never the newest rows, and total is capped at 5000. Neither the UI nor the CLI has a paging control and the audit table is never pruned, so the freeze is permanent for that sandbox or system.

### 지켜야 할 불변식

The sandbox page timeline (footer: only the most recent N shown, total M) and `agentbox audit` show the newest audit events with the real total, or page through all rows. The volume of rows an agent can create must not hide its later events from the human's oversight views, in particular the gui_changes and gui_processes_stopped records that the README (line 198) names as the way the human sees changes made through the ungated GUI path.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:241` `decide (POST /approvals/{aid})` — An agent token (lowest-trust principal) calling POST /approvals/{any id} with a valid {"decision": ...} body is authenticated by principal() and refused with 403, but the refusal path records an audit row first. Ordinary allowed tool calls (POST /sandboxes/{sid}/tools/{tool}: list_dir, read_file, exec of an allowlisted command, GUI tools) also add rows, three each via service.py:297, 305 and 359.
2. **propagation** `agentbox/api.py:245` `decide` — audit.append(actor='agent', event='approval_forbidden', sandbox_id=p.sandbox_id): one row per request, tagged with the agent's own sandbox id. No request-rate limit (none in the app or in deploy/), no tool_pool slot, no Docker call and no row cap; tool_concurrency only bounds simultaneous tool calls.
3. **propagation** `agentbox/audit.py:196` `AuditLog.list` — 'WHERE id > ? [AND sandbox_id = ?] ORDER BY id LIMIT ?' returns the oldest rows first. Rows are never deleted (UPDATE/DELETE triggers), so once the limit is exceeded newer rows are only reachable by paging with after_id.
4. **propagation** `agentbox/web.py:262` `audit_frag (GET /ui/audit)` — rows = box.audit.list(sandbox_id=sandbox_id, limit=5000): the oldest 5000 rows of that sandbox, no after_id. This is the fragment sandbox.html:19 re-requests every 3 s.
5. **sink** `agentbox/web.py:263` `audit_frag (GET /ui/audit)` — render(_audit.html, rows=rows[-400:][::-1], total=len(rows)) passes ids 4601-5000 and total 5000 (reproduced); newer rows, including gui_processes_stopped and gui_changes, are never rendered, and _audit.html:10 then prints the footer '최근 400개만 표시 (전체 5000개)'.

### 근거 (evidence)

- `agentbox/audit.py:196` — ' ORDER BY id LIMIT ?' is ascending, so any limit keeps the oldest rows; the same query serves the unpaged UI/CLI callers and the after_id paging API.
- `agentbox/web.py:263` — The UI takes the tail of the oldest-5000 window and reports total as len(rows), which cannot exceed 5000.
- `agentbox/templates/_audit.html:10` — Footer '최근 {{ rows|length }}개만 표시 (전체 {{ total }}개)' (most recent N shown, total M) is false beyond 5000 rows; the harness printed '최근 400개만 표시 (전체 5000개)' with 5012 rows in the database.
- `agentbox/cli.py:258` — cmd_audit requests /audit with limit=5000 and no after_id and prints everything it gets; there is no paging flag, and without --sandbox the query is system-wide. Real cmd_audit printed ids 1..5000 only.
- `agentbox/api.py:259` — GET /audit returns list(..., after_id=after_id, limit=min(limit, 5000)) with a default limit of 500: an unpaged call returns the oldest 500 rows (measured: newest id 500 of 5012); only after_id paging reaches newer rows, and neither the UI nor the CLI pages.
- `agentbox/templates/sandbox.html:19` — The sandbox page polls /ui/audit?sandbox_id=... on load, every 3 s and on audit-changed: this is the live oversight view, and its only other audit-related control is the verify button.
- `agentbox/service.py:297` — Every tool call appends tool_request here, policy_decision at line 305 and (when allowed and executed) tool_result at line 359: measured exactly 3 rows each for exec ls and list_dir.
- `agentbox/default_policy.yaml:10` — default: allow, so list_dir, read_file, write_file and the GUI tools have no rule and need no approval; the read-only-exec allowlist (lines 25-27) allows ls, echo, cat and similar.
- `agentbox/default_policy.yaml:27` — true and false are unquoted, so yaml.safe_load yields booleans and the allowlist holds 'True'/'False', not 'true'/'false'; measured: exec true returns 202 (approval requested), so the hunter's `exec true` example is wrong (the root cause is unaffected).
- `agentbox/service.py:243` — gui_changes (and gui_processes_stopped at line 225) are written only to the audit log and rendered only by web.py describe (line 62) and cli.py (line 280), so the two timelines are the only human-facing surface for them.
- `README.md:198` — Documents the timeline as where the human sees the 'deleted: ...' list and the snapshot id for GUI-path changes; the README's known limitations do not mention a 5000-row cap.
- `tests/test_m2_acceptance.py:242` — The suite asserts that the /ui/audit page shows '삭제됨: old-report.md', confirming the timeline is the designed surface for gui_changes; no test brings a sandbox anywhere near the 5000-row limit.

### 공격 주체와 조건

A prompt-injected agent holding its sandbox's agent token wants its later exec and GUI activity, and the gui_processes_stopped and gui_changes records the system writes about it, to stay out of the human's timeline; it first pads the audit table with cheap approval-free rows until the oldest-first window is full.

- *authentication_level*: Holder of the victim sandbox's agent token (prompt-injected agent). Rows can be created through the ordinary tool endpoints and MCP tools (list_dir, read_file, exec of an allowlisted command: 3 rows per call) or, with raw API access, by refused POST /approvals/{id} (1 row per call).
- *data_state*: More than 5000 audit rows for the sandbox (sandbox page, `agentbox audit --sandbox`) or for the whole system (default `agentbox audit`). Agent-causable within minutes; long-lived ordinary sandboxes reach it too.
- *user_interaction*: The human relies on the sandbox page timeline or `agentbox audit` output rather than paging GET /audit with after_id; the UI and CLI have no paging control.
- *system_configuration*: Default policy (default: allow plus the read-only-exec allowlist) so list_dir, read_file, ls and echo need no approval. The refused-POST path does not depend on the policy.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `POST /approvals/apr_<n>  Authorization: Bearer <agent token of sb_v02>  body {"decision":"approve"}, repeated 4,991 times: each returns 403 and appends one approval_forbidden row tagged sb_v02; together with 9 rows from three probe tool calls the table holds exactly 5000 rows (ids 1..5000)`
- `POST /sandboxes/sb_v02/tools/exec {"args":{"command":"echo AFTER_FLOOD_MARKER"}}; POST /sandboxes/sb_v02/tools/click {"args":{"x":10,"y":10}} (opens a GUI burst; the fake container then deletes /workspace/important.txt and leaves a background process, and the burst is aged 61 s); POST /sandboxes/sb_other/tools/exec {"args":{"command":"echo OTHER_SANDBOX_MARKER"}}: ids 5001-5012, including gui_processes_stopped 5008 and gui_changes 5009`
- `Human side: GET /ui/audit?sandbox_id=sb_v02 with a browser-session cookie; the real cli.cmd_audit with sandbox=None, 'sb_v02' and 'sb_other'; GET /audit?after_id=5000&limit=5000 and GET /audit/verify with the human token`

절차:

1. In sbx (no network, no Docker) run: sbx v02 /usr/bin/python3.13 -I -B /scratch/v02.py 5000 /scratch/v02.out (artifacts agents/v02/artifacts/v02.py and agents/v02/artifacts/v02.out; 512 MiB, 1 CPU, 64 pids, 120 s, uid 65534; about 17 s). It builds the real agentbox.api.build() app under a scratch AGENTBOX_HOME and replaces only SandboxManager (needs Docker) and fastapi.templating (jinja2 is not importable in sbx); the template stub records the context web.py passes and takes the footer text from the real _audit.html source line.
2. Step 0-1: with the sandbox's agent token send POST /approvals/apr_probe (403) and three probe tool calls (exec ls and list_dir are allowed and add 3 rows each; exec true returns 202 and needs approval), then 4,990 more refused POST /approvals/apr_N so the table holds exactly 5000 rows for sb_v02. Step 2: GET /ui/audit?sandbox_id=sb_v02 with a session cookie from box.desktop.new_session(): boundary control, the newest row (5000) is shown.
3. Step 3-4: as the agent run exec echo AFTER_FLOOD_MARKER and a GUI click (opens a GUI burst), alter the fake container (delete important.txt, leave a stray uid-1001 process), age the burst by 61 s, run an exec in an unrelated sandbox; poll /ui/audit again, which closes the burst so the real service code appends gui_processes_stopped and gui_changes. Inspect the template context and the unrelated sandbox's page.
4. Step 5-7: call the real cli.cmd_audit (default, --sandbox sb_v02, --sandbox sb_other) through a shim that injects the human token; GET /audit (default and after_id=5000) and /audit/verify; exercise the proposed remediation (newest-N plus COUNT(*) query, CLI after_id paging loop) on the same database.

관찰 결과:

With exactly 5000 rows the sandbox page showed ids 4601..5000 and the newest shown id equalled the newest in the database (boundary control). After 12 more rows (ids 5001-5012: exec and click tool_request/policy_decision/tool_result, snapshot 5006, gui_processes_stopped 5008, gui_changes 5009 for sb_v02; 5010-5012 for sb_other) the poll for sb_v02 returned status 200, template _audit.html, 400 rows, ids 4601..5000 (all approval_forbidden), total 5000, footer '최근 400개만 표시 (전체 5000개)', with no id above 5000, no gui_changes, no gui_processes_stopped and no AFTER_FLOOD_MARKER; the unrelated sb_other page still showed its own rows 5010-5012. Real cmd_audit printed 5000 lines, ids 1..5000, and none of the markers for both the default and --sandbox sb_v02; --sandbox sb_other printed ids 5010-5012. An unpaged GET /audit returned the oldest 500 rows (newest id 500). GET /audit?after_id=5000 returned ids 5001-5012 and /audit/verify returned ok=True over 5012 rows, so nothing is lost, only not shown. Proposed fix on the same database: the newest-400 plus COUNT(*) query returned ids 4610..5009 with total 5009 including gui_changes, and the CLI paging loop returned all 5012 rows. A second run gave identical numbers. Not executed: real Jinja2 rendering (unavailable in sbx), Docker-backed SandboxManager.

### 영향과 우선순위 근거

- likelihood (medium): No approval and no Docker work are needed: the rows come from the agent's own requests. In the harness 4,991 refused POST /approvals/{id} calls (one row each; needs raw API access with the agent token) took about 15 s in-process, and each allowed list_dir/read_file/exec of an allowlisted command adds exactly 3 rows (about 1,670 calls through the ordinary MCP tools, no raw API access needed). tool_concurrency (4 simultaneous) only slows this; there is no request-rate limit or row cap. Long-lived ordinary sandboxes cross 5000 rows without any attacker. It needs a human who relies on the timeline rather than paging /audit, and the frozen window stays visible (400 rows, constant total), so an attentive operator could notice that it stopped advancing.
- impact (medium): Both human timelines (the sandbox page polled every 3 s, and `agentbox audit`) stop advancing while the UI footer claims to show the most recent rows, so later tool_request/tool_result, snapshot, takeover/handback, gui_processes_stopped and gui_changes rows are not shown. The README names the timeline as the way the human sees gui_changes, the compensating control for the ungated GUI path, so the lowest-trust principal can silence that control for itself at will. The default CLI is system-wide, so one sandbox's volume also hides other sandboxes' later events from `agentbox audit` without --sandbox; the per-sandbox UI window of an unrelated sandbox was not affected (checked). Bounded: no row is lost or altered (GET /audit?after_id= returns them, verify passes), the approval queue, snapshots, stray-process kill and tool gating are unaffected, and there is no disclosure or privilege gain.
- confidence (high): Reproduced twice with identical numbers through the real api.build() app: agent-token HTTP requests created the rows, the real service.py code wrote gui_processes_stopped and gui_changes, and the real web.py audit_frag route and real cli.cmd_audit ran. Only Docker (SandboxManager) and Jinja2 rendering were stubbed, and the footer text came from the real _audit.html line. The boundary control (exactly 5000 rows shows the newest row), the unrelated-sandbox control and the paging/verify checks support the causal reading, and the ordering, the limit, the missing paging and the absence of any documented cap are direct from source. The hunters' artifacts (h-audit, h-wild) agree.

### 수정 방향

Make the human views read the newest rows and report the real total. Add AuditLog.recent(sandbox_id, limit) = SELECT COUNT(*) plus 'ORDER BY id DESC LIMIT ?' under the same lock, use it in web.audit_frag (newest first, matching the existing template), and make `agentbox audit` page /audit with after_id until an empty page (optionally add a --tail N flag or a newest-first /audit option so large logs are not transferred in full). Replace the same oldest-first pattern in web.verify_frag (web.py:270, limit=100000) with a point lookup of the broken id. Optionally add an index on audit(sandbox_id, id) for the filtered COUNT and reverse scans (CREATE INDEX does not conflict with the append-only triggers). Regression tests: append 5100 rows for one sandbox, assert GET /ui/audit renders id 5100 with total 5100 and that cmd_audit's fetch includes id 5100; assert the same for a sandbox filter when another sandbox holds most of the rows.

`agentbox/audit.py`:

```python
    def recent(self, sandbox_id: str | None = None, limit: int = 400) -> tuple[list[dict[str, Any]], int]:
        """Newest `limit` rows (newest first) and the real row count for the same filter."""
        where, args = (" WHERE sandbox_id = ?", [sandbox_id]) if sandbox_id else ("", [])
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM audit" + where, args).fetchone()[0]
            rows = self.conn.execute(
                "SELECT id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash FROM audit" + where
                + " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()
        return [
            {"id": r[0], "ts": r[1], "sandbox_id": r[2], "actor": r[3], "event": r[4], "tool": r[5],
             "payload": json.loads(r[6]), "prev_hash": r[7], "hash": r[8]}
            for r in rows
        ], total
```

`agentbox/web.py`:

```python
    @app.get("/ui/audit", include_in_schema=False)
    def audit_frag(request: Request, sandbox_id: str | None = None, p=Depends(browser_human)):
        box.close_idle_gui_bursts()
        rows, total = box.audit.recent(sandbox_id=sandbox_id, limit=400)   # newest first, real total
        return render(request, "_audit.html", rows=rows, total=total, broken=None)
```

`agentbox/cli.py`:

```python
def cmd_audit(a: argparse.Namespace) -> None:
    with _client() as c:
        params = {"sandbox_id": a.sandbox} if a.sandbox else {}
        rows, after = [], 0
        while True:   # /audit is oldest-first: page with after_id so the newest rows are included
            page = _check(c.get("/audit", params=params | {"limit": 5000, "after_id": after}))
            if not page:
                break
            rows += page
            after = page[-1]["id"]
```


---

## [medium] v05 — Rotating the human token does not revoke existing full-admin browser sessions (no revoke-all; sessions persist 12 h across restart)

- fingerprint: `agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions`
- 심각도: likelihood low · impact high · overall **medium**; confidence high
- 수정 상태: 이 브랜치에 `3587c9c`로 수정됨. 회귀 테스트: `tests/test_m4_acceptance.py::test_human_token_rotation_logs_out_browsers`, `tests/test_m4_unit.py::test_human_token_rotation_drops_sessions_and_tickets`, `tests/test_m4_unit.py::test_session_db_without_token_column_is_migrated`, `tests/test_m4_unit.py::test_token_gen_is_stable_and_distinct`

### 설명

Web UI cookie sessions (scope '*') are rows in ui_sessions: sha256(cookie), a public hs_ id, created, expires = creation + 12 h, scope. Nothing ties a row to the human token that authorised it. When the owner rotates the shared admin secret (a new AGENTBOX_HUMAN_TOKEN, or deleting/regenerating data/human_token) and restarts, the old token stops working (Bearer 401; /login issues no cookie), but every '*' cookie minted under it keeps working until its fixed 12 h expiry, because DesktopControl.__init__ deletes only expired rows and session_scope checks only the cookie hash and expiry. There is no bulk revocation: no route, method or CLI command does it; logout and login/ticket redemption act only on the presented/new cookie and never end a replaced one; no API accepts the hs_ id that the audit log records. A holder of an earlier-minted agentbox_session cookie therefore keeps the full browser-UI authority after the owner has withdrawn the only credential: the same Depends(browser_human) gate admits approve/deny of agent actions, sandbox delete/restore/snapshot, file upload, outbox download, sandbox creation with an arbitrary host source_dir (only data-folder overlap is refused) and desktop takeover, and the desktop WebSocket gate accepts the cookie too. README.md documents the 12 h life and persistence across restart as a known limit but is silent on rotation and revocation.

### 근본 원인

Session validity is independent of the credential that created it: the ui_sessions schema (desktop.py:35-37) has no token-generation or lineage column, DesktopControl.__init__ (desktop.py:91-93) prunes only expired rows, session_scope (desktop.py:133-145) checks hash and expiry only, and no code path deletes more than one session at a time (end_session, desktop.py:127-131), so only the session's own logout or its 12 h expiry ends it. The human token is read once at start-up (config.py:88, api.py:66) and used only for comparisons, so rotating it changes nothing stored in agentbox.db.

### 지켜야 할 불변식

A browser session is valid only while the human credential that authorised it is still current: rotating the human token (new AGENTBOX_HUMAN_TOKEN or regenerated data/human_token) invalidates every browser session and unredeemed ticket minted under the old one, while a restart with an unchanged token keeps logins (tests/test_m4_acceptance.py::test_login_survives_restart); the owner has an explicit revoke-all that needs no rotation; and a login that replaces a cookie ends the replaced server-side session. The README documents none of the rotation/revocation guarantees, so this is the security expectation for a shared-admin-secret model, not a documented promise.

### 경로 (trace)

1. **entrypoint** `agentbox/web.py:117` `login` — POST /login (unauthenticated network client holding the then-current token) compares the form token with human_token (compare_digest, web.py:120) and calls start_session (web.py:95-101), which calls DesktopControl.new_session() with the default scope '*'. GET /login?ticket= (web.py:109-113) and the per-sandbox ticket route (api.py:298-308) mint sessions the same way.
2. **propagation** `agentbox/desktop.py:116` `DesktopControl.new_session` — Inserts (sha256(cookie), public hs_ id, created, expires = now + 12 h, scope) at lines 123-124; nothing records which human token authorised the session (schema lines 35-37).
3. **propagation** `agentbox/config.py:88` `Settings.human_token` — Rotation = new AGENTBOX_HUMAN_TOKEN or a deleted/regenerated data/human_token, read once at start-up (api.py:66) and used only for compare_digest checks (api.py:96, web.py:120) and log masking; nothing in agentbox.db changes.
4. **propagation** `agentbox/desktop.py:93` `DesktopControl.__init__` — On restart only rows with expires < now are deleted (lines 92-93); the table is dropped only for the legacy no-scope schema (lines 86-89).
5. **propagation** `agentbox/api.py:115` `screen_principal` — With no Authorization header the cookie goes to box.desktop.session_scope (line 119); same_origin (line 122) passes when Origin is absent; returns Principal('human', session, scope) (line 124).
6. **propagation** `agentbox/desktop.py:133` `DesktopControl.session_scope` — The only verification: SELECT by sha256(cookie) and reject if expires < now (lines 138-145). No token generation, lineage or revocation check; a cookie minted under the rotated-out token returns (public id, '*').
7. **sink** `agentbox/web.py:204` `decide (/ui/approvals/{aid}/{decision})` — p=Depends(browser_human) = api.screen_human (api.py:126-132) admits the scope-'*' stale session; box.decide(...) runs with the stale session id (web.py:209). The same gate fronts every other /ui admin route, sandbox create (source_dir), delete, restore, snapshot, upload, outbox and takeover.

### 근거 (evidence)

- `agentbox/desktop.py:35` — ui_sessions columns are hash, public, created, expires, scope only (PRAGMA output in agents/v05/artifacts/v05_rotation.out line 4): no token generation.
- `agentbox/desktop.py:93` — Start-up prunes only expired sessions. The only other deletions are single-hash logout (130), per-lookup expiry (143), expiry cleanup in new_session (122) and the legacy scope-less table drop (89); nothing deletes sessions in bulk and nothing extends expires (grep of agentbox/).
- `agentbox/desktop.py:138` — session_scope: SELECT by hash, reject only if expires < now.
- `agentbox/desktop.py:127` — end_session deletes exactly one hash.
- `agentbox/web.py:129` — Logout ends only the presented cookie (via service.end_ui_session, service.py:517-527).
- `agentbox/web.py:95` — start_session (POST /login and GET /login?ticket=) mints a new session without reading or ending a cookie already presented; api.py:306 does the same for per-sandbox tickets (the hunter's api.py:306 evidence covers only that route). Harness: v05_rotation.out lines 38, 41, 43, 47.
- `agentbox/api.py:66` — human_token is read once in build(); rotation therefore needs a restart and touches nothing in agentbox.db.
- `README.md:370` — Known limitations: login sessions last 12 h and survive a restart; nothing about rotation or revocation (README.md:193 covers only expiry/deletion of one session).
- `tests/test_m4_acceptance.py:49` — test_login_survives_restart pins persistence across a restart with an unchanged token as intended; no test or code considers rotation.
- `agents/v05/artifacts/v05_rotation.out:21` — Independent reproduction after rotation + restart on the same agentbox.db: old token 401 (line 12) and no cookie from /login (14); cookie minted under it gets /ui 200 (20), /ui/approvals 200 (21), /ui/sandboxes 200 (22); an approval decision is accepted and audit-logged under the stale session id (25-29); WS gate passed (30); 43199 s left (33); forged/no cookie controls 401 (16-18); regenerated data/human_token gives the same result (51-54).
- `agents/v05/artifacts/v05_rotation.out:36` — Route inventory of the real app: the cookie principal reaches POST /ui/approvals/{aid}/{decision}, POST /ui/sandboxes, POST /ui/sandboxes/{sid}/delete, restore, snapshots, POST /sandboxes/{sid}/files, outbox, capture.png and desktop takeover/handback/state; only /logout matches session/revoke/logout (line 34) and no revoke/logout-all attribute exists (35).
- `agents/v05/artifacts/v05_fix_check.out:1` — Patch validation: a token-generation binding drops sessions and tickets on rotation (lines 2-3), keeps them across a restart under the same token (1, 4-5), adds revoke_all (6-7), migrates legacy databases (8-10); the repo's session/ticket/lease unit tests pass against the patched class (11).

### 공격 주체와 조건

A former operator (or other holder of an earlier-minted '*' browser session cookie) who is meant to be cut off when the owner rotates the shared human token and restarts the control plane; the attacker sends ordinary browser requests with the old agentbox_session cookie, no Authorization header and no Origin header.

- *authentication_level*: Attacker holds a '*' agentbox_session cookie minted before the rotation (former operator, shared browser profile, or a login made with the since-rotated token). The old token alone is not enough after rotation (Bearer 401; /login issues no cookie).
- *system_configuration*: Owner rotates the human token (new AGENTBOX_HUMAN_TOKEN, or deletes/regenerates data/human_token) and restarts against the same agentbox.db (the default; AGENTBOX_HOME/AGENTBOX_DB unchanged).
- *timing_dependency*: Use within the cookie's original 12 h life: the expiry is fixed at creation and no code path extends it, so a session minted just before the rotation gives the longest window.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `POST /login  form token=hum_V05_old_dummy_token_aaaaaaaaaaaaaaaa -> 303, Set-Cookie agentbox_session=<cookie_old>; HttpOnly; Max-Age=43200; SameSite=strict`
- `restart: api.build() with AGENTBOX_HUMAN_TOKEN=hum_V05_new_dummy_token_bbbbbbbbbbbbbbbb on the same AGENTBOX_HOME/agentbox.db (variant: delete data/human_token and restart)`
- `GET /sandboxes with Authorization: Bearer <old token> -> 401; POST /login with the old token -> no cookie`
- `GET /ui, /ui/approvals, /ui/sandboxes, /ui/audit, /ui/notify with Cookie: agentbox_session=<cookie_old> (no Authorization, no Origin) -> 200`
- `POST /ui/approvals/<pending dummy approval id>/deny with the same cookie -> 200; approval becomes denied; audit approval_decision records session=<hs_ id of cookie_old>`
- `WS /sandboxes/sb_v05dummy/desktop/ws?mode=view with Origin http://testserver and the old cookie -> closed 1011 (past the 4401/4403 gates); no or forged cookie -> 4401`

절차:

1. Ran agents/v05/artifacts/v05_rotation.py as 'sbx v05 /usr/bin/python3.13 -I -B /scratch/v05_rotation.py' (no network, no Docker socket, read-only target and /usr, scratch-only writes, uid 65534, empty allow-listed environment, 512 MiB, 1 CPU, 64 pids, 120 s).
2. Docker is replaced by a dummy client (info() -> runc) and Jinja2 (not installed in the sandbox) by a stub registered as fastapi.templating. Authorization runs in route dependencies before any render, so the stub cannot change an auth decision: forged or absent cookie -> 401 on the same routes where the stale cookie gets 200.
3. Part A: api.build() with AGENTBOX_HUMAN_TOKEN=OLD, POST /login, keep cookie_old, close; api.build() again on the same AGENTBOX_HOME with AGENTBOX_HUMAN_TOKEN=NEW (the restart). Probe with Bearer OLD, form login OLD, forged and no cookie (controls) and cookie_old; create a pending dummy approval for dummy sandbox sb_v05dummy and deny it with cookie_old; open the desktop WebSocket gate for the dummy sandbox id; read ui_sessions and enumerate the routes whose auth dependency accepts the cookie principal.
4. Part B repeats the rotation by deleting data/human_token and restarting (regenerated token). Part C posts /login, redeems a '*' ticket and a per-sandbox ticket, and logs out, each while presenting an existing cookie, then checks which sessions remain valid. Part D moves the stale row's expiry into the past to show that only the TTL ends it.
5. Part E (and v05_fix_check.py with desktop_fixed.py, a scratch copy of desktop.py plus the patch below; target files untouched) applies the proposed generation binding in memory and repeats the rotation; the repo's own session/ticket/lease unit tests pass against the patched class.

관찰 결과:

After rotation + restart on the same database: Bearer OLD -> 401 and POST /login with OLD -> no cookie; forged or absent cookie -> 401 (GET /ui -> 303 /login). The cookie minted under OLD gets GET /ui 200, /ui/approvals 200, /ui/sandboxes 200, /ui/audit 200, /ui/notify 200; POST /ui/approvals/<dummy>/deny -> 200 and the dummy approval became denied, with an approval_decision audit entry carrying the stale session's hs_ id; the WebSocket gate accepted the stale cookie (close 1011 on the non-existent dummy sandbox) while no or forged cookie got 4401; the row had 43199 s left. Deleting/regenerating data/human_token gave the same result (token1 Bearer 401, cookie1 -> 200 on /ui/approvals and /ui/sandboxes). The session table and DesktopControl expose no revoke/logout-all, and the only session route is /logout. Logging in, redeeming a '*' ticket or a per-sandbox ticket while presenting a cookie left the presented session valid, and logout ended only its own cookie. Only expiry (moved into the past) ended the stale session (401). With the generation-binding prototype: old cookie -> 401 after rotation, new-token login 200, restart with an unchanged token keeps the login (200). Not exercised (no Docker): approve, delete, restore, upload, source_dir sandbox creation; they share the same authorization gate.

### 영향과 우선순위 근거

- likelihood (low): Needs a '*' cookie minted before the rotation (a former operator, a shared browser profile, or a login made with the since-rotated token) and an owner who rotates while that session is alive; the old token alone is useless after rotation (Bearer 401, /login issues no cookie). HttpOnly + SameSite=Strict (+ Secure behind TLS) make remote theft of the cookie hard, and use is capped at the cookie's 12 h life, which is fixed at creation.
- impact (high): The stale session passes the same gate as every admin UI route (demonstrated: UI pages 200 and an approval decision on a dummy approval executed and audit-logged under the stale session id; the route inventory shows approve/deny, delete/restore, upload, outbox, host source_dir sandbox creation and takeover behind that gate, not exercised without Docker). It grants no privilege beyond what the holder already had, the JSON management API stays closed to cookies and exposure ends at expiry, but the owner cannot cut the holder off sooner than 12 h, with rotation or otherwise.
- confidence (high): Independently reproduced in the OS sandbox with the real api.build() factory, real DesktopControl/SQLite persistence and the real auth dependencies (only Docker and Jinja2 stubbed), with positive and negative controls (forged/no cookie 401, Bearer OLD 401, expiry 401), both rotation methods, and a source trace checked line by line; corrections to the hunter's wording: start-up prune is lines 92-93, the old token alone gives nothing after rotation, api.py:306 covers only per-sandbox tickets ('*' tickets go through web.py:95), and session_scope (desktop.py:133) was missing from the trace. The architecture summary names no comparable baseline to calibrate against.

### 수정 방향

Bind sessions and tickets to the human token that minted them and give the owner a way to revoke: store a domain-separated hash of the human token (token_gen) in a gen column of ui_sessions and ui_tickets, delete rows whose gen differs at start-up (a rotation then drops all old sessions and unredeemed tickets, while a restart with an unchanged token still keeps logins) and require gen in session_scope; add a human-only revoke-all (DesktopControl.revoke_all, a bearer-authenticated route and an 'agentbox logout-all' command) that deletes all sessions and tickets and cuts live screen connections (the 30 s session_watch re-check in api.py already hands back leases once the rows are gone); end the replaced server-side session when a login or ticket redemption arrives with a cookie. Use a high-entropy token (the default is) because the stored fingerprint is derived from it. Add a regression test: token A login, rebuild with token B, old cookie -> 401 on /ui/approvals and WS 4401. The DesktopControl part of this patch was validated in a scratch copy (rotation drops, same-token restart keeps, revoke_all, legacy-DB migration, repo session tests pass); the api.py route and web.py glue are sketches.

`agentbox/desktop.py`:

```python
--- a/agentbox/desktop.py
+++ b/agentbox/desktop.py
@@ SCHEMA
 CREATE TABLE IF NOT EXISTS ui_tickets (
-  hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL);
+  hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL, gen TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS ui_sessions (
   hash TEXT PRIMARY KEY, public TEXT NOT NULL, created TEXT NOT NULL, expires REAL NOT NULL,
-  scope TEXT NOT NULL DEFAULT '*');
+  scope TEXT NOT NULL DEFAULT '*', gen TEXT NOT NULL DEFAULT '');
@@ class DesktopControl.__init__
-                 db_path: str | Path | None = None):
+                 db_path: str | Path | None = None, token_gen: str = ""):
+        self.gen = token_gen   # fingerprint of the human token these sessions are minted under
@@ (after self._db.executescript(SCHEMA))
+        for table in ("ui_tickets", "ui_sessions"):   # databases from before the token binding
+            if "gen" not in [r[1] for r in self._db.execute(f"PRAGMA table_info({table})")]:
+                self._db.execute(f"ALTER TABLE {table} ADD COLUMN gen TEXT NOT NULL DEFAULT ''")
         now = time.time()
-        self._db.execute("DELETE FROM ui_tickets WHERE expires < ?", (now,))
-        self._db.execute("DELETE FROM ui_sessions WHERE expires < ?", (now,))
+        # expired rows go, and so does everything minted under a different (rotated-out) human token
+        self._db.execute("DELETE FROM ui_tickets WHERE expires < ? OR gen != ?", (now, token_gen))
+        self._db.execute("DELETE FROM ui_sessions WHERE expires < ? OR gen != ?", (now, token_gen))
@@ issue_ticket
-            self._db.execute("INSERT INTO ui_tickets VALUES (?, ?, ?)", (_h(t), sid, time.time() + self.ticket_ttl))
+            self._db.execute("INSERT INTO ui_tickets (hash, scope, expires, gen) VALUES (?, ?, ?, ?)",
+                             (_h(t), sid, time.time() + self.ticket_ttl, self.gen))
@@ new_session
-            self._db.execute("INSERT INTO ui_sessions (hash, public, created, expires, scope) VALUES (?, ?, ?, ?, ?)",
-                             (_h(cookie), public, _now_iso(), now + self.session_ttl, scope))
+            self._db.execute("INSERT INTO ui_sessions (hash, public, created, expires, scope, gen)"
+                             " VALUES (?, ?, ?, ?, ?, ?)",
+                             (_h(cookie), public, _now_iso(), now + self.session_ttl, scope, self.gen))
@@ session_scope
-            row = self._db.execute("SELECT public, expires, scope FROM ui_sessions WHERE hash = ?",
-                                   (_h(cookie),)).fetchone()
+            row = self._db.execute("SELECT public, expires, scope FROM ui_sessions WHERE hash = ? AND gen = ?",
+                                   (_h(cookie), self.gen)).fetchone()
@@ new method (owner's "log out everywhere")
+    def revoke_all(self) -> int:
+        with self._lock:
+            n = self._db.execute("SELECT COUNT(*) FROM ui_sessions").fetchone()[0]
+            self._db.execute("DELETE FROM ui_sessions")
+            self._db.execute("DELETE FROM ui_tickets")
+            conns = list(self._conns.values())
+        for c in conns:
+            c.close()
+        return n

```

`agentbox/api.py`:

```python
# agentbox/api.py  (add: import hashlib)
    human_token = settings.human_token()
    audit.register_secret(human_token)
    # sessions/tickets are minted under this fingerprint; a rotated token drops them all at start-up
    token_gen = hashlib.sha256(b"agentbox-ui-session\0" + human_token.encode()).hexdigest()[:32]
    box = AgentBox(
        ...
        desktop=D.DesktopControl(idle=settings.takeover_idle, db_path=settings.db_path, token_gen=token_gen),
        ...
    )

    # owner-only 'log out everywhere' without rotating (sketch; also add `agentbox logout-all` calling it)
    @app.post("/ui/sessions/revoke", include_in_schema=False)
    def revoke_sessions(p: Principal = Depends(human_only)):
        n = box.desktop.revoke_all()
        box.log_human("ui_sessions_revoked", None, {"count": n})
        return {"revoked": n}

```

`agentbox/web.py`:

```python
# agentbox/web.py  start_session(): a login that replaces a cookie ends the replaced server-side session
    def start_session(request: Request, target: str, how: str) -> RedirectResponse:
        stale = request.cookies.get(D.COOKIE)
        if stale:
            box.end_ui_session(stale)
        cookie, session = box.desktop.new_session()
        ...
# agentbox/api.py desktop_page(): same call before box.desktop.redeem(...) mints the per-sandbox cookie

```

`tests/test_m4_unit.py`:

```python
# tests/test_m4_unit.py
def test_rotation_drops_sessions_but_restart_keeps_them(tmp_path):
    db = tmp_path / "a.db"
    a = DesktopControl(db_path=db, token_gen="A")
    cookie, public = a.new_session()
    t = a.issue_ticket("*")
    a.close()
    assert DesktopControl(db_path=db, token_gen="A").session(cookie) == public      # same token: login survives
    assert DesktopControl(db_path=db, token_gen="B").session(cookie) is None        # rotated token: dropped
    assert DesktopControl(db_path=db, token_gen="B").redeem(t, "*") is None         # and its unredeemed tickets
# acceptance (needs the app, no Docker): login with token A, api.build() again with token B on the same
# AGENTBOX_HOME -> old cookie gets 401 on /ui/approvals and WS close 4401; POST /ui/sessions/revoke empties ui_sessions.

```


---

## [medium] v08 — Prompt-injected agent writes unbounded, undeletable rows into the shared audit log via uncapped tool-call args

- fingerprint: `agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap`
- 심각도: likelihood high · impact medium · overall **medium**; confidence high
- 수정 상태: 이 브랜치에 `e63922c`로 수정됨. 회귀 테스트: `tests/test_m2_unit.py::test_large_tool_args_are_capped_in_audit`

### 설명

The agent token (lowest-trust principal, assumed prompt-injected) controls the free-form args dict of every tool call. service._call_tool writes an event=tool_request audit row with payload {"args": _logged_args(tool, args)} as its very first action, before policy.decide, so even denied or approval-requiring calls still persist the row. _logged_args only special-cases write_file content (replacing it with size+sha256); for every other tool and every other key the args pass through verbatim. No size cap exists at any layer: FastAPI/Starlette/uvicorn impose no default request-body limit, ToolCall.args is an unconstrained dict[str, Any], Settings has read/write/upload caps but no args/body cap, the shipped Caddy reverse_proxy has no request_body max_size, and audit.append serializes and INSERTs the payload with no size check. One request therefore persists an arbitrarily large row into the shared, append-only control-plane SQLite audit DB (a single DB for all sandboxes, on host disk). UPDATE/DELETE are blocked by triggers, so the operator cannot prune oversized rows without rebuilding the DB and destroying the hash chain. audit.verify() loads every row and rehashes each full payload, and /ui/verify calls audit.list(limit=100000), so one agent can permanently bloat the shared audit store and make the operator's own audit/verify tooling slow and memory-heavy for the life of the DB.

### 근본 원인

_logged_args (service.py:131-137) returns agent args unchanged except write_file content, and _call_tool (service.py:297-298) persists them via audit.append before any policy decision; neither the HTTP layer (api.py:50-51,206-211), configuration (config.py:54-57), shipped proxy (deploy/Caddyfile:5) nor audit.append (audit.py:143-187) bounds the serialized payload; the append-only triggers (audit.py:35-38) make the oversized rows unrecoverable.

### 지켜야 할 불변식

Agent-supplied tool arguments recorded for audit are bounded in serialized size (as write_file content already is), so one lowest-trust request cannot persist an arbitrarily large, undeletable row into the shared audit DB or amplify the operator's verify/list path.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:206` `call_tool(sid, tool, body: ToolCall)` — Agent POSTs /sandboxes/{sid}/tools/{tool}; body.args is an unconstrained dict[str, Any] (api.py:50-51) passed straight to box.call_tool with actor=p.kind; no request-body or args size limit.
2. **propagation** `agentbox/service.py:297` `AgentBox._call_tool` — First action in the tool path: audit.append(event='tool_request', payload={'args': _logged_args(tool, args)}), executed before policy.decide (line 299), so the row persists even for calls that are later denied or sent to approval.
3. **propagation** `agentbox/service.py:131` `AgentBox._logged_args` — Static method returns the args dict unchanged for every tool except write_file; only write_file 'content' is replaced with content_bytes+content_sha256. All other keys/tools (e.g. a 3 MiB 'junk' value on read_file) pass through verbatim.
4. **propagation** `agentbox/audit.py:153` `AuditLog.append` — payload = self._mask(payload or {}); _mask recurses over the dict and json.dumps serializes it with no size check before the INSERT.
5. **sink** `agentbox/audit.py:176` `AuditLog.append INSERT` — The full json.dumps(payload) is persisted into the append-only audit table; verify() (audit.py:208-233) and list(limit=100000) (web.py:270) later re-load and rehash every full row.

### 근거 (evidence)

- `agentbox/service.py:133` — Only the write_file 'content' key is special-cased; every other tool/key is returned unchanged.
- `agentbox/service.py:297` — tool_request row appended as the first action, before policy.decide at line 299.
- `agentbox/audit.py:176` — INSERT persists json.dumps(payload) with no size cap.
- `agentbox/audit.py:36` — audit_no_update / audit_no_delete triggers (RAISE ABORT 'audit log is append-only') make oversized rows unprunable.
- `agentbox/audit.py:210` — verify() selects all rows ORDER BY id and rehashes each full payload.
- `agentbox/web.py:270` — /ui/verify calls box.audit.list(sandbox_id=..., limit=100000), re-loading up to 100k full payloads.
- `agentbox/config.py:54` — Settings defines max_read_bytes/max_write_bytes/max_upload_bytes but no args/request-body cap.
- `deploy/Caddyfile:5` — Shipped behind-proxy deployment uses a bare 'reverse_proxy agentbox:8765' with no request_body max_size.
- `agentbox/api.py:50` — ToolCall.args: dict[str, Any] = {} is unconstrained; passed to box.call_tool (api.py:210) with no body limit.

### 공격 주체와 조건

A prompt-injected agent adds a large junk field to tool args it already controls; the control plane records the full args into the shared append-only audit DB permanently and re-reads them on every operator verify/list.

- *authentication_level*: Valid agent token for its own sandbox (lowest-trust network principal; threat model assumes a prompt-injected agent).
- *data_state*: Each request appends one unprunable row sized to the body; recovery requires rebuilding the DB and losing the hash chain, since UPDATE/DELETE are trigger-blocked.
- *system_configuration*: Both the default local serve and the shipped behind-proxy Caddy deployment lack a body cap; an operator-added body cap would reduce per-row magnitude but not cross-request accumulation.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `POST /sandboxes/{sid}/tools/read_file  body {"args": {"path": "/workspace/x", "junk": "<3 MiB of 'A'>"}}`
- `Repeat with list_dir, exec, key, type, etc. (any non-write_file tool, or any non-'content' key).`

절차:

1. In the OS-enforced sandbox (sbx v08: /usr/bin/python3.13, /target read-only on sys.path, /scratch writable, no network, no Docker, uid 65534, 512 MiB, 1 CPU), reproduce service._logged_args verbatim and confirm a non-write_file args dict with a 3 MiB junk value is returned unchanged while write_file content is stripped.
2. Open agentbox.audit.AuditLog on a scratch DB and append actor='agent', event='tool_request', tool='read_file', payload={'args': logged_args(...)} with the 3 MiB junk; measure length(payload) of the stored row.
3. Append 3 more rows with junk; sum length(payload).
4. Attempt DELETE and UPDATE on a row; observe the append-only triggers.
5. Call verify() and list(limit=100000).

관찰 결과:

logged_args kept the 3,145,728-byte junk key unchanged (write_file content was stripped); the stored row's payload was 3,145,774 bytes; 4 rows totalled 12,583,024 bytes; both DELETE and UPDATE raised sqlite3.IntegrityError 'audit log is append-only'; verify() returned ok=True after re-checking all 4 rows; list(limit=100000) returned all 4 rows with the full 3 MiB payload intact. Independently reproduced in sbx v08 (/scratch DB); see agents/v08/artifacts/repro_v08.out (consistent with the hunter's agents/h-buffer/artifacts/audit_cap.out).

### 영향과 우선순위 근거

- likelihood (high): The agent controls the args dict in normal operation; adding a large field is trivial with its own token and requires no special conditions.
- impact (medium): Persistent, unprunable growth of the shared append-only audit DB (single DB for all sandboxes, on host disk) plus memory/CPU amplification on every operator verify()/ui-verify list(100000); recovery requires rebuilding the DB and losing the hash chain. Not RCE or a guaranteed crash.
- confidence (high): Every layer read from source: uncapped pass-through in _logged_args, pre-decision persistence, absence of any HTTP/config/proxy/audit body or row cap, append-only triggers, and full re-read in verify/list all confirmed. Uncapped persistence, trigger-blocked DELETE/UPDATE, and full re-read independently reproduced in the sandbox (repro_v08.out).

### 수정 방향

Bound the serialized size of the agent-supplied args that reach the audit log, after the existing write_file content strip and for every tool, so the cap cannot be sidestepped by combining write_file content with an extra large key. When the json-serialized args exceed a fixed limit, store a byte count, sha256 and a truncated head. Keep content_bytes and content_sha256 in the truncated form, since the approval preview uses them. The same _logged_args also feeds the approval payload (service.py:167 and :408), so the fix covers those rows too. Add a request-body/args size limit on the tool endpoint (and a request_body max_size in the shipped Caddyfile) as defense in depth.

`agentbox/service.py`:

```python
# add `import json` at the top of the module
LOGGED_ARGS_MAX = 64 * 1024    # args kept verbatim in the audit log (JSON bytes)
LOGGED_ARGS_HEAD = 16 * 1024   # head kept when exceeded

@staticmethod
def _logged_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    if tool == "write_file" and "content" in args:
        data = str(args.get("content", "")).encode("utf-8")
        args = {k: v for k, v in args.items() if k != "content"} | {
            "content_bytes": len(data), "content_sha256": hashlib.sha256(data).hexdigest()}
    # the size cap applies to the result of the write_file strip too, so write_file + small content + huge extra key is also bounded
    blob = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    if len(blob) <= LOGGED_ARGS_MAX:
        return args
    kept = {k: args[k] for k in ("content_bytes", "content_sha256") if k in args}
    return kept | {"args_truncated": True, "args_bytes": len(blob),
                   "args_sha256": hashlib.sha256(blob).hexdigest(),
                   "args_head": blob[:LOGGED_ARGS_HEAD].decode("utf-8", errors="replace")}
```


---

## [medium] v12 — GUI burst stray-kill and gui_changes logging are lost across sandbox restore and pause

- fingerprint: `agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause`
- 심각도: likelihood medium · impact medium · overall **medium**; confidence high
- 수정 상태: 이 브랜치에 `c1f88da`로 수정됨. 회귀 테스트: `tests/test_m2_acceptance.py::test_gui_burst_restarts_after_pause_and_restore`, `tests/test_m2_unit.py::test_lifecycle_change_resets_gui_burst_timers`, `tests/test_m2_unit.py::test_burst_from_replaced_container_kills_nothing`, `tests/test_m2_unit.py::test_failed_burst_close_is_logged_not_dropped_silently`

### 설명

GUI input bypasses the approval gate by design (N-1). The partial mitigation for that is a per-burst snapshot, a gui_changes audit record and killing the uid-1001 processes started during the burst (service.py:206-256). None of the GUI burst state (_gui_burst, _gui_input_at, _gui_snap_at) is reconciled with container lifecycle transitions. (1) Restore: api.py:192 and web.py:243 call end_desktop, which closes the old burst (service.py:531). It clears _gui_input_at only through handback when a human lease exists (service.py:494), and it never clears _gui_snap_at. After the restore, an agent GUI input that comes within gui_snapshot_idle (60 s) of its previous input and within gui_snapshot_interval (600 s) of the last GUI snapshot gets False from _gui_needs_snapshot (service.py:196). It therefore runs with no snapshot and no burst. A uid-1001 background process the agent starts in that gap is recorded in the next burst's baseline pid set (service.py:213), so gui_strays skips it (sandbox.py:216) and it is never killed. Workspace changes made in the gap are in the next burst's baseline manifest, so they never appear in gui_changes. (2) Pause: the pause route (api.py:166-170) does no burst handling. Once the burst's idle time passes while the sandbox is paused, the next caller of close_idle_gui_bursts closes it: the sandbox page polls /ui/audit every 3 s (templates/sandbox.html:19, web.py:261), and GET /audit, expire_stale and any call_tool also call it. _close_gui_burst pops the burst first (service.py:232). desktop_processes then raises through _desktop/_require_running for a paused sandbox (sandbox.py:688, 468-469) and the error is swallowed (service.py:221-222). The manifest exec against the paused container also fails and is swallowed (238-239). The strays are not killed and the changes are not logged. After resume they keep running and become part of the next burst's baseline. The same unreconciled state also causes an availability effect, reproduced only in the fake harness. Restore pops the burst in end_desktop before the container is replaced, and nothing invalidates a burst opened after that point. If an agent GUI input opens a burst between end_desktop and the container swap (a race window), the baseline holds the old container's pids. When that burst idles out, gui_strays treats every uid-1001 process of the new desktop session as a stray and kills it. Windowed processes are included, because base_sids is empty when the old pids are absent from the new container. This happens only when the new container's pids differ from the old ones. With identical pids nothing is killed.

### 근본 원인

GUI burst bookkeeping in AgentBox is in-memory state keyed only by sandbox id. It has no tie to the container instance or its run state. end_desktop (service.py:529-537), which the restore routes call, closes the burst but leaves _gui_input_at (cleared only by handback at 494) and _gui_snap_at (set at 263, never cleared) in place. _gui_needs_snapshot (195-197) therefore suppresses a fresh burst after restore, and a burst opened after end_desktop survives the container swap. The pause and resume routes (api.py:166-176) do not touch burst state at all. _close_gui_burst (232) also discards the burst before its enforcement steps, and those steps return silently on failure (221-222, 238-239). An idle close while the sandbox is paused therefore drops the burst without killing strays or logging changes.

### 지켜야 할 불변식

Every container lifecycle change (restore, pause, resume, delete) resets the GUI burst timers, so the first GUI input afterwards takes a snapshot and opens a burst whose baseline belongs to the current container. A burst is discarded only after its strays have been stopped and its changes diffed and logged. A paused sandbox keeps its burst until it is running again, or the burst is closed before pausing. A burst whose container id no longer matches is closed without killing anything.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:205` `POST /sandboxes/{sid}/tools/{tool}` — Agent token (lowest-trust principal, own sandbox) calls GUI input tools click/type/key, which the default policy allows (no matching rule), through box.call_tool on tool_pool.
2. **propagation** `agentbox/service.py:109` `AgentBox._run_tool` — Every GUI input sets _gui_input_at[sid] before the click runs, even if the click then fails, for example while the container is being replaced.
3. **propagation** `agentbox/api.py:192` `restore route` — Human restore calls box.end_desktop(sid, 'sandbox_restored') and then sandboxes.restore, which replaces the container (web.py:243-244 does the same). Nothing else touches GUI burst state.
4. **propagation** `agentbox/service.py:531` `AgentBox.end_desktop` — Closes the open burst before the swap. _gui_input_at is popped only via handback when a lease exists (494). _gui_snap_at is never cleared.
5. **propagation** `agentbox/service.py:196` `AgentBox._gui_needs_snapshot` — Recent last_input (<=60 s) and last_snap (<=600 s) give False, so _call_tool (339) runs the first post-restore GUI inputs with no snapshot and no open burst.
6. **propagation** `agentbox/api.py:169` `pause route` — Pause variant: the route only logs and calls sandboxes.pause; the open burst stays in _gui_burst.
7. **propagation** `agentbox/service.py:232` `AgentBox._close_gui_burst` — An idle close during the pause (close_idle_gui_bursts at 254-256, called by the /ui/audit 3 s poll at web.py:261) pops the burst first. desktop_processes then raises through sandbox.py:688 -> _require_running 468-469 and the error is swallowed at 221-222. The manifest failure is swallowed at 238-239.
8. **propagation** `agentbox/service.py:213` `AgentBox._open_gui_burst` — The next burst (after the idle or interval timer expires, or after resume) records all current pids as its baseline, including the gap or paused-burst stray, and records the current manifest, including the gap changes.
9. **sink** `agentbox/sandbox.py:216` `gui_strays` — Baseline pids are skipped, so the stray uid-1001 process is never selected by _stop_gui_strays and keeps running. Its changes never appear in gui_changes.

### 근거 (evidence)

- `agentbox/service.py:494` — _gui_input_at is reset only on handback, which end_desktop calls only when a lease exists (532-536).
- `agentbox/service.py:263` — _gui_snap_at is set on every GUI snapshot and has no pop anywhere in the package (grep).
- `agentbox/api.py:175` — Resume route only logs and unpauses; no burst or timer handling.
- `agentbox/service.py:255` — close_idle_gui_bursts closes idle bursts regardless of sandbox status.
- `agentbox/web.py:261` — UI audit fragment calls close_idle_gui_bursts. sandbox.html:19 polls it every 3 s; api.py:258 GET /audit and expire_stale/call_tool also call it.
- `agentbox/sandbox.py:468` — _require_running raises SandboxError for a paused sandbox. desktop_processes reaches it via _desktop (680, 688).
- `agentbox/sandbox.py:498` — workspace_manifest uses _container, not _require_running. For a paused sandbox the docker exec fails, so the post-burst diff is skipped at service.py:238-239.
- `agentbox/sandbox.py:518` — restore sets the new container_id and status running before _wait_display. A burst opened after end_desktop is not invalidated by the swap (stale-baseline consequence).
- `docs/security-audit/run-3/agents/v12/artifacts/v12_burst.out:46` — Harness output. A_control kills stray 50 and logs gui_processes_stopped and gui_changes. B_restore: timers kept; t20 and t70 inputs took no snapshot and opened no burst; next baseline [1,10,11,12,60]; killed []; no gui_* events. The fix check (timers cleared) kills 60 and logs report.md. C_pause (line 157): burst dropped while paused; killed []; baseline [1,10,11,12,70]; stray alive. D (line 192): stale baseline kills the new desktop [14,15,16] when pids differ, and nothing when pids match.

### 공격 주체와 조건

Prompt-injected agent with its own sandbox's agent token, using click/type/key on a desktop sandbox (for example opening a terminal and starting a setsid background loop as uid 1001) around a human restore or pause.

- *authentication_level*: Agent token for a desktop-template sandbox, driving GUI input tools (allowed by the default policy).
- *user_interaction*: Restore variant: a human restores while the agent's last GUI input is under 60 s old and its last GUI snapshot is under 600 s old, with no active human lease (a lease's handback clears _gui_input_at). Pause variant: a human pauses while a burst is open and keeps it paused past gui_snapshot_idle while some poller (open sandbox page, GET /audit, approvals list, or any agent's tool call) runs close_idle_gui_bursts.
- *system_configuration*: gui_snapshot_interval > 0 (default 600) and gui_snapshot_idle at its default of 60.
- *timing_dependency*: Restore gap length is bounded by the remaining idle and interval windows. The agent controls both by keeping inputs frequent. The stale-baseline desktop kill additionally needs a GUI input landing between end_desktop and the container swap, and new pids that differ from the old ones.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `restore: click t=0 (snap_1, burst); human end_desktop + restore at t=10; click t=20; uid-1001 setsid loop pid 60 + report.md modified at t=25; click t=70; idle close t=150; click t=200; idle close t=300`
- `pause: click t=0 (burst); stray pid 70 + report.md modified at t=5; click t=10; pause t=20; close_idle_gui_bursts t=100 (UI audit poll); resume t=200; click t=210; idle close t=400`
- `stale baseline: click t=0; idle close t=1000; end_desktop t=1001; click t=1002 before the container swap; restore with new desktop pids (14,15,16) at t=1003; idle close t=1100`

절차:

1. In the sbx sandbox (no network, no Docker), run /usr/bin/python3.13 -I /scratch/v12_burst.py. It builds the real AgentBox with a real AuditLog, ApprovalStore, Policy.load(default_policy.yaml) and DesktopControl, and the real gui_strays. Only SandboxManager is faked: it records snapshots and kills; desktop_processes and click raise when paused, mirroring _require_running; workspace_manifest raises when paused, mirroring Docker refusing exec in a paused container. time.monotonic is patched to drive the timers.
2. Drive the agent through box.call_tool(sid, 'click', ...) and the human restore through box.end_desktop followed by the fake restore, as api.py:192-193 does. Pause and resume flip the record status, as api.py:169/175 do. Call close_idle_gui_bursts as the UI poll does. Compare the snapshots, baselines, kills, surviving pids and audit snapshot/gui_processes_stopped/gui_changes events against the control run and against a run with the timers cleared after restore.

관찰 결과:

Control: snapshot snap_1, stray 50 killed, gui_processes_stopped [50] and gui_changes modified [report.md] logged. Restore: after end_desktop the burst is closed but _gui_input_at and _gui_snap_at are kept. The t20 and t70 inputs return 200 with no snapshot and no burst. The next burst (t200, snap_2) has baseline [1,10,11,12,60]. Killed []. Stray 60 still alive. No gui_processes_stopped or gui_changes event. With the timers cleared after restore (proposed fix), t20 opens snap_2, stray 60 is killed and report.md is logged. Pause: the idle close while paused drops the burst. Killed []. Stray 70 is alive after resume. Next baseline [1,10,11,12,70]; stray 70 is still alive after the next idle close; no gui_* events. Stale baseline: a burst opened after end_desktop on the old container, with baseline [1,10,11,12], kills every uid-1001 process of the new container [14,15,16], including the windowed panel. With identical new pids nothing is killed.

### 영향과 우선순위 근거

- likelihood (medium): Pausing or restoring a sandbox while the agent is active on the GUI is the natural human reaction to suspicious activity. The pause variant only needs the pause to outlast gui_snapshot_idle (60 s) while the sandbox page is open, or while any other caller runs close_idle_gui_bursts. For the restore variant, the agent keeps the timers recent just by issuing frequent inputs. It needs no active human lease at restore.
- impact (medium): It defeats the only compensating controls on the GUI approval bypass (N-1). An agent-started uid-1001 background process survives indefinitely, and its /workspace changes are missing from gui_changes, so the audit trail the human relies on after a restore or pause is incomplete. The restore variant also skips the post-restore GUI restore point. No privilege beyond the sandbox and no network (network_mode none). A same-root-cause stale baseline can also kill the new desktop session, but only through a race and pid divergence, and it was shown only in the harness.
- confidence (high): The restore variant is pure control-plane state logic in service.py and was reproduced with the real AgentBox, AuditLog, Policy, DesktopControl and gui_strays. Clearing the timers (the proposed fix) restores the kill and the logging. The pause variant's decisive step is the source-visible _require_running status check. The harness fakes SandboxManager and does not exercise live Docker pids, the real xfce process tree, or the stale-baseline race timing. Those affect only the related desktop-kill consequence, not the confirmed stray-survival and missing-log result.

### 수정 방향

Tie GUI burst state to the container lifecycle. In end_desktop, and in the pause, resume and restore paths (API and web), close the burst and then clear _gui_input_at and _gui_snap_at, so the next GUI input always snapshots and opens a burst on the current container. Record the container_id in the burst and close a burst whose container_id no longer matches without killing anything. Skip paused sandboxes in close_idle_gui_bursts, or close the burst before pausing. In _close_gui_burst, remove the burst only after stray stop and the manifest diff succeed, and log a gui_burst_close_failed event otherwise. Add regression tests: GUI input soon after restore opens a new burst, a burst idling out while paused is kept or closed before pausing, and a burst opened before a container swap does not kill the new desktop.

`agentbox/service.py`:

```python
def _reset_gui_state(self, sid: str, reason: str) -> None:
    self._close_gui_burst(sid, reason)
    self._gui_input_at.pop(sid, None)
    self._gui_snap_at.pop(sid, None)

def end_desktop(self, sid: str, reason: str) -> None:
    self._reset_gui_state(sid, reason)
    if self.desktop.lease(sid):
        try:
            self.handback(sid, None, reason)
        except ServiceError:
            pass
    self.desktop.close_all(sid)
    # callers: also call self._gui_input_at.pop / _gui_snap_at.pop again after sandboxes.restore returns

def _open_gui_burst(self, sid, snapshot_id):
    ...
    self._gui_burst[sid] = {..., "container_id": self.sandboxes.get(sid)["container_id"]}

def close_idle_gui_bursts(self) -> None:
    idle = self.sandboxes.settings.gui_snapshot_idle
    now = time.monotonic()
    for sid in list(self._gui_burst):
        try:
            if self.sandboxes.get(sid)["status"] == "paused":
                continue
        except Exception:
            pass
        if now - self._gui_input_at.get(sid, 0.0) > idle:
            self._close_gui_burst(sid, "idle")

def _close_gui_burst(self, sid, reason):
    burst = self._gui_burst.get(sid)
    if not burst:
        return
    if self.sandboxes.get(sid)["container_id"] != burst["container_id"]:
        self._gui_burst.pop(sid, None)  # stale baseline: never kill against it
        return
    ok = self._stop_gui_strays(sid, burst, reason)  # return False on failure
    ...  # pop only after strays stopped and manifest diff logged; otherwise log gui_burst_close_failed

```

`agentbox/api.py`:

```python
@app.post("/sandboxes/{sid}/pause")
def pause(sid: str, p: Principal = Depends(human_only)):
    box.log_human("sandbox_pause", sid, {})
    box.end_gui_burst(sid, "sandbox_paused")  # close burst (kill strays, log changes) and clear timers
    guard(lambda: box.sandboxes.pause(sid))
    return box.sandboxes.get(sid)
# resume: clear timers after unpause; same changes in web.py
```


---

## [medium] v13 — Web exec approval card renders the agent's command with raw Unicode bidi controls, letting a prompt-injected agent spoof the human approver's view of what will run

- fingerprint: `agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized`
- 심각도: likelihood medium · impact medium · overall **medium**; confidence high
- 수정 상태: 이 브랜치에 `c1f88da`로 수정됨. 회귀 테스트: `tests/test_m3_acceptance.py::test_web_approval_neutralises_bidi_controls`

### 설명

The web approval card shows the agent-submitted exec command in <pre>{{ a.args.command }}</pre> under Jinja HTML autoescape only (markupsafe.escape only touches & < > ' "). Unicode bidirectional controls (U+202A-E, U+2066-9) survive escaping and are rendered live by the browser, which reorders the displayed text. The terminal approver (cli.py _show_approval) prints the same command through cli._safe, which turns those code points into visible \uXXXX escapes, so only the web approval path is affected. For non-allowlisted programs (sh/python3) the policy requires approval and the system preview computes no affected paths (sandbox.preview only handles rm/curl segments), adding a note that directs the approver to read the command text itself. A prompt-injected agent (lowest-trust agent token, assumed in the threat model) can therefore submit a Trojan-Source-laid-out command whose rendered form on the web card reads as a single benign echo while a separate approval-gated program actually executes, defeating the human's exec-approval review.

### 근본 원인

_approvals.html:8 relies on HTML autoescape, which neutralises markup but not Unicode bidi/control characters; the web UI has no equivalent of cli._safe (cli.py:34-39) for approval args, and base.html:23's pre style applies no unicode-bidi isolation. The terminal path escapes these characters (cli.py:196-199) but the web path does not, so the two human-facing surfaces disagree about the same command.

### 지켜야 할 불변식

Both human approval surfaces should show the agent-chosen command with display-reordering and control characters neutralised, so the approver's decision is bound to the exact command that will execute. The code already does this for the terminal approver via cli._safe; the web card should apply the same neutralisation.

### 경로 (trace)

1. **entrypoint** `agentbox/api.py:205` `call_tool (POST /sandboxes/{sid}/tools/{tool}, tool=exec)` — Lowest-trust agent token submits args.command containing bidi isolate controls (U+2067/U+2069).
2. **propagation** `agentbox/service.py:322` `call_tool REQUIRE_APPROVAL branch` — Approval created with the agent's original args and a preview; for python3/sh the preview lists no affected paths and tells the approver to check the command text.
3. **propagation** `agentbox/web.py:196` `approvals_view` — Pending approvals (original args) passed to _approvals.html for the web approver.
4. **sink** `agentbox/templates/_approvals.html:8` `exec approval card` — <pre>{{ a.args.command }}</pre> renders the command with autoescape only; raw bidi controls reach the browser next to the 승인 (approve) button at line 19.

### 근거 (evidence)

- `agentbox/cli.py:34` — _UNSAFE regex explicitly includes U+200E/F, U+202A-E, U+2066-9 as display-integrity controls that the terminal approver must neutralise.
- `agentbox/cli.py:199` — _show_approval prints each command line via _safe(line), so the terminal approver sees \u2067/\u2069 escapes, not active controls -- establishing the web-vs-terminal asymmetry.
- `agentbox/templates/_approvals.html:8` — Command rendered with HTML autoescape only; bidi controls are not among the characters markupsafe.escape replaces, so they survive into the DOM.
- `agentbox/templates/base.html:23` — pre style sets white-space/word-break but no unicode-bidi isolation, so the browser applies the embedded bidi controls.
- `agentbox/sandbox.py:872` — preview computes affected paths only for rm/curl segments; for an echo/python3 command it adds no affected entries and notes the approver must confirm the command text -- which is the spoofed display.
- `docs/security-audit/run-3/agents/parent-live/artifacts/l3/l5.out:1` — Parent-live real-Chromium innerText retains raw U+2067/U+2069; companion screenshot l5_card.png renders the command as a single benign-looking echo with python3 /workspace/job.py pulled inside the quoted string.
- `docs/security-audit/run-3/agents/v13/artifacts/bidi_check.out:3` — Local sbx reproduction: HTML-escaping the payload leaves U+2067/U+2069 intact while cli._safe converts them to visible escapes.

### 공격 주체와 조건

A prompt-injected agent wants to run an arbitrary approval-gated program (python3/sh) that the human would refuse if shown the real command, so it lays the command out Trojan-Source style so the web card renders it as a harmless echo.

- *authorization_role*: Attacker is a prompt-injected per-sandbox agent token (agt_), the lowest-trust network principal, acting on its own sandbox.
- *user_interaction*: A human reviews and approves the exec via the web UI approval card; the terminal approver (cli.py) escapes the bidi controls and is not affected, and the approver must not notice the reordered rendering.
- *system_configuration*: The command uses a non-allowlisted program (e.g. python3/sh) so policy.decide routes it to approval, and sandbox.preview lists no affected paths, leaving the command text as the sole decision basis.

### 재현 (대상 고유 인터페이스, 범위 제한)

입력:

- `echo 'summary done ⁧' ; python3 /workspace/job.py ; echo '⁩'`

절차:

1. As the agent, write /workspace/job.py, then POST /sandboxes/{sid}/tools/exec with args.command set to the payload above (RLI U+2067 inside the first echo's quotes, PDI U+2069 inside the last echo's quotes).
2. python3 is not in the policy allowlist, so service.call_tool creates a pending approval; the preview adds no affected paths and a note to check the command text.
3. The human opens the web UI approval card (/ui/approvals); _approvals.html:8 renders <pre>{{ a.args.command }}</pre> with the bidi controls active.
4. Observe the browser rendering versus the logical command (and versus the terminal approver's escaped rendering).

관찰 결과:

Parent-live Chromium (l5_card.png) renders the command as a single line `echo 'summary done python3 /workspace/job.py ; echo ; '` -- the separate `; python3 /workspace/job.py ;` command is visually pulled inside the first echo's quoted string, so the card reads as one benign echo while python3 /workspace/job.py is what actually executes on approval. innerText (l5.out) confirms the raw U+2067/U+2069 survive. My own sbx check (bidi_check.out) confirms HTML escaping leaves the bidi controls intact whereas cli._safe escapes them. Decisive browser rendering was reproduced by the parent (real Chromium), not by me; my local reproduction covers only the escape-survival step.

### 영향과 우선순위 근거

- likelihood (medium): The threat model assumes a prompt-injected agent, and embedding bidi isolates in an exec command is trivial. It requires the human to approve via the web UI (the terminal path escapes the controls) and to not notice the reordered rendering, which bounds likelihood below high.
- impact (medium): Defeats the human exec-approval boundary (the primary control between a prompt-injected agent and arbitrary non-allowlisted exec) via display spoofing, yielding agent-chosen arbitrary in-sandbox code execution (python3/sh) under the human's misdirected approval. Contained by the sandbox isolation (network=none, dropped caps, no-new-privileges, runc); it is not by itself a host, cross-sandbox, or human-token compromise.
- confidence (high): Source establishes the asymmetry end to end: cli._safe escapes the bidi set (cli.py:34, 196-199) while _approvals.html:8 autoescapes only (base.html:23 adds no isolation), and sandbox.preview lists nothing for python3/sh so the command text is the sole basis. The parent's real Chromium reproduction (l5_card.png / l5.out) demonstrates the concrete visual spoof, and my own sbx check confirms escaping preserves the controls. Both candidate blockers are resolved; the only part I could not run myself is the browser render, which the parent supplied.

### 수정 방향

Neutralise display-reordering and control characters on every container/agent-controlled string shown to a human in the web UI, matching the terminal cli._safe behaviour. Add a Jinja filter that maps C0/C1/DEL and bidi controls (the cli._UNSAFE set) to visible escapes, and apply it to the exec command, preview effect/path cells, and describe() output on the approval and audit templates; optionally also wrap the <pre> in CSS unicode-bidi: isolate/plaintext as defence in depth. A regression test should assert the rendered HTML for a bidi-laden command contains no raw U+202A-E/U+2066-9.

`agentbox/web.py`:

```python
import re as _re
_UNSAFE = _re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")

def _safe_display(s):
    return _UNSAFE.sub(lambda m: f"\\x{ord(m[0]):02x}" if ord(m[0]) < 0x100 else f"\\u{ord(m[0]):04x}", str(s))

# in register(): tpl.env.filters["safe_display"] = _safe_display
```

`agentbox/templates/_approvals.html`:

```python
    <div>실제로 실행될 명령 <span class="mut">(작업 폴더 {{ a.preview.cwd | safe_display }})</span>:</div><pre>{{ a.args.command | safe_display }}</pre>
```

