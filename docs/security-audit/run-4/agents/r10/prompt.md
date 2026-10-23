You are final record verifier `r10` in run-4 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91`. Every path and line must exist in THAT tree. `/home/user/agentbox` from earlier runs carries different code and must not be used for line numbers.

# Record under verification

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token",
 "title": "A restore racing a delete resurrects the deleted sandbox row and re-authorizes the agent token the delete revoked",
 "description": "DELETE /sandboxes/{sid} and POST /sandboxes/{sid}/restore each perform an unlocked read-modify-write on the same sandboxes row. If a DELETE completes between the restore's creation of the replacement container and the restore's final status write, the delete reports success and audits 'sandbox_delete', but the restore's last write puts status='running' and the new container_id back on the row. Neither operation rewrites token_hash, and revocation is expressed only as status!='deleted', so the agt_ token the delete revoked resolves to that sid again and its tool calls execute in the replacement container. The snapshots row also survives (delete removes only images), and the running replacement keeps the snapshot image in use, so the best-effort image removal raises and is swallowed. The control plane therefore reports a completed deletion while the sandbox, its /workspace and its agent authority are live again.",
 "root_cause": "Lifecycle operations take no per-sandbox lock and re-read nothing. Service.restore_sandbox and Service.delete_sandbox (service.py:462-475) call SandboxManager.restore and SandboxManager.delete (sandbox.py:387-401, 320-332); each reads the row once with _rec, acts, and writes status/container_id unconditionally through _set, which is a bare UPDATE with no status predicate (sandbox.py:234-237). SandboxManager.restore never checks status=='deleted', so its final _set (sandbox.py:398) overwrites the delete's status write (sandbox.py:326) and reinstates the record. Revocation of the agent token is expressed only as status!='deleted' (sandbox.py:216, 221), so the overwritten status silently re-authorizes the original token hash.",
 "intended_behavior": "_container (sandbox.py:225-232) and the token lookups (sandbox.py:211-223) treat status=='deleted' as final: a deleted sandbox is unusable and its agent token is invalid. DELETE is the revocation contract (service.py:471-475 logs sandbox_delete, ends the desktop, deletes the container, drops captures). No later or concurrent lifecycle call may reinstate the record, re-point it at a container, or make the revoked token valid again.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 206,
   "scope": "POST /sandboxes/{sid}/restore",
   "description": "sync human_only route hands the client-supplied snapshot_id to box.restore_sandbox and runs in the Starlette threadpool with no serialization against other lifecycle calls"
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 465,
   "scope": "AgentBox.restore_sandbox",
   "description": "calls SandboxManager.restore outside any lock, after end_desktop has already run"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 388,
   "scope": "SandboxManager.restore",
   "description": "reads the row with _rec, which returns deleted rows too, and never checks status"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 393,
   "scope": "SandboxManager.restore",
   "description": "force-removes the row's old container (NotFound swallowed), so the row's stale container_id no longer exists"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 397,
   "scope": "SandboxManager.restore",
   "description": "starts the replacement container from the snapshot image; from this point the new container exists while no lock protects the row"
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 211,
   "scope": "DELETE /sandboxes/{sid}",
   "description": "second human request for the same sid runs as a separate threadpool worker, so delete_sandbox executes concurrently with an in-flight restore"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 326,
   "scope": "SandboxManager.delete",
   "description": "marks the row deleted (unconditional UPDATE), after removing the old container_id the restore already removed"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 330,
   "scope": "SandboxManager.delete",
   "description": "snapshot image removal fails because the restore's new running container uses the image; APIError is swallowed, so the image and its snapshots row survive"
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 398,
   "scope": "SandboxManager.restore",
   "description": "final _set overwrites the deleted status with status='running' and the replacement container_id"
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 216,
   "scope": "SandboxManager.token_matches",
   "description": "only rejects status=='deleted', so the original agent token hash is accepted again"
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 221,
   "scope": "SandboxManager.sandbox_for_token",
   "description": "resolves the revoked token back to the sid, which api.principal turns into an agent principal (api.py:121-123)"
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 462,
   "description": "restore_sandbox ordering: log, end_desktop, sandboxes.restore, bursts.reset_timers, log - no lock is acquired, unlike call_tool's _snap_locks (service.py:281-284)"
  },
  {
   "file": "agentbox/service.py",
   "line": 471,
   "description": "delete_sandbox ordering: log, end_desktop, sandboxes.delete, drop_captures - no lock, so it can interleave with restore"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 185,
   "description": "_rec returns the row for any sid including deleted ones, so restore's first read succeeds after a delete"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 234,
   "description": "_set is a bare UPDATE with no status predicate, so the restore's write cannot tell that the row was deleted"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 225,
   "description": "_container is the intended choke point that rejects status=='deleted' for every other operation; restore bypasses it by using _rec directly"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 320,
   "description": "delete: read row, remove container, set status='deleted', then best-effort image removal with APIError and NotFound swallowed (327-332); the snapshots rows are never deleted"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 387,
   "description": "restore: read row, remove old container, run new container, then unconditionally set container_id and status='running'"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 211,
   "description": "token_matches expresses revocation only as status != 'deleted'"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 218,
   "description": "sandbox_for_token uses the same status filter, so the reauthorization reaches api.principal (api.py:121-123)"
  },
  {
   "file": "agentbox/api.py",
   "line": 126,
   "description": "human_only requires kind=='human'; both restore (205-207) and delete (209-212) are human-only, so the agent cannot issue either request - it only benefits from their interleaving"
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "Both requests need the human token or a browser session with scope '*'; the agent never issues them, but it holds the agt_ token whose revocation DELETE implements and needs no new credential, so the failure is a revocation/TOCTOU defect rather than an attacker-triggered request."
  },
  {
   "kind": "timing_dependency",
   "description": "The DELETE must complete its row read, status write and image-removal attempt inside the window that opens when the restore's replacement container has been created (sandbox.py:397) and closes at the restore's status write (sandbox.py:398), and the restore must be preempted in that window. This window is a few milliseconds of SQLite/thread scheduling, not the whole restore: in the measured alternative schedule where the DELETE lands during the long container-start portion, the delete removes the snapshot image first, the restore then fails with ImageNotFound, and the row stays deleted with the token invalid. So the overlap is reachable but narrow."
  },
  {
   "kind": "data_state",
   "description": "The sandbox has at least one snapshot row; DELETE never removes snapshots rows (sandbox.py:327-332 only tries to remove images) and restore accepts any row of that sid."
  },
  {
   "kind": "system_configuration",
   "description": "No special runtime or container capability is needed: the resurrection is decided entirely in the SQLite row and the token lookups. The daemon fact that matters (images.remove refusing while a running container holds the image) is what real Docker does; the harness models it, and even if the image were removed the running replacement and the surviving snapshots row would still leave the sandbox resurrected."
  }
 ],
 "execution": {
  "attacker_perspective": "Holder of the agt_ token whose authority the human tried to revoke with DELETE. It needs no new credential and takes no action: after the overlapping restore the same token maps to the sid again and its tool calls return 200. The overlap itself requires two human-issued requests (restore and delete) whose timing the agent cannot control, so this is a failed revocation contract rather than a directly attacker-triggered race.",
  "payloads": [
   "POST /sandboxes/sb_54e49093/restore {\"snapshot_id\": \"snap_b2f2d73f\"}  (started first)",
   "DELETE /sandboxes/sb_54e49093  (issued while the restore is between its replacement container's creation and its final status write)",
   "POST /sandboxes/sb_54e49093/tools/list_dir {\"args\": {\"path\": \"/workspace\"}} with Authorization: Bearer <the agt_ token DELETE was meant to revoke>"
  ],
  "instructions": [
   "Bounded local harness in the approved sbx sandbox (no network, no Docker daemon): real agentbox.config.Settings, agentbox.audit.AuditLog, agentbox.approvals.ApprovalStore, agentbox.policy.Policy, agentbox.desktop.DesktopControl, agentbox.service.AgentBox and agentbox.sandbox.SandboxManager with SQLite files under /scratch, driven through AgentBox methods (no HTTP server needed; the route bodies are one-line guard calls).",
   "Docker is replaced by a fake client that models only the daemon facts this check needs: containers.run registers name and image and refuses a duplicate container name, images.remove refuses while a running container uses the image (the real docker conflict), and running an absent image raises ImageNotFound.",
   "Create a cli-template sandbox with an empty source dir, take one snapshot (docker commit is faked into the image set), then start box.restore_sandbox(sid, snap) on a thread whose containers.run hook parks it after the replacement container exists but before its status write. The main thread runs box.delete_sandbox(sid) to completion and then releases the restore.",
   "Read back: sandboxes.get(sid)['status'] and container_id, sandboxes.token_matches(sid, old_token), sandboxes.sandbox_for_token(old_token) (the value api.principal turns into Principal('agent', sid)), box.call_tool(sid, 'list_dir', {'path': '/workspace'}), snapshot rows/images, and audit.list(sandbox_id=sid).",
   "Sequential control in the same process: create, snapshot, delete, then restore - it fails with ImageNotFound and leaves status 'deleted' with the token invalid.",
   "Alternative schedule: park the restore before the replacement container is created, then run the delete to completion and release it."
  ],
  "observed_result": "Race run (delete parked inside the post-create window): delete_sandbox returned without error after status had become 'deleted' and token_matches and sandbox_for_token reported the token invalid; the parked restore then returned normally. Read-back: status 'running', container_id c2 present and alive, sandboxes.token_matches(sid, old_token)=true, sandbox_for_token(old_token)=sid, snapshot rows still 1, the snapshot image still present (delete's image removal raised because c2 runs it), and box.call_tool(sid, 'list_dir', {'path': '/workspace'}) returned 200 {'status': 'executed', 'result': {'path': '/workspace', 'listing': '...'}}. Audit sequence: sandbox_created, snapshot_request, snapshot, restore_request, sandbox_delete, restored, tool_request, policy_decision, tool_result. Sequential control: ImageNotFound 'no such image: agentbox-snap:sb_9df2e832-snap_3e1280c2', final status 'deleted', token invalid. Alternative schedule (delete before the replacement container exists): delete removed the image, the restore raised ImageNotFound, final status 'deleted', token invalid - so this ordering does not resurrect and bounds the vulnerable window."
 },
 "remediation": {
  "strategy": "Serialize all lifecycle transitions per sandbox and make deletion final at the point of the check. Take one per-sid lifecycle lock in AgentBox (reuse the _snap_locks map with a distinct key) around pause/resume/snapshot/restore/delete so delete and restore cannot interleave, and have SandboxManager.restore re-read the row under that lock and refuse status=='deleted' before it removes the old container or starts the replacement. The two methods below are the decisive pair for this race; the same lock should wrap pause_sandbox/resume_sandbox/snapshot_sandbox as well, since pause's unconditional _set(status='paused') has the same shape. Regression case: drive restore and delete concurrently with the harness and assert that the row is either deleted with the old token invalid and no replacement container, or still not deleted only when no delete was observed.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "    def _lifecycle_lock(self, sid: str) -> threading.Lock:\n        with self._busy_lock:\n            return self._snap_locks.setdefault(\"lifecycle:\" + sid, threading.Lock())\n\n    def restore_sandbox(self, sid: str, snap_id: str, session: str | None = _NO_SESSION) -> dict[str, Any]:\n        with self._lifecycle_lock(sid):\n            self.log_human(\"restore_request\", sid, _with_session({\"snapshot_id\": snap_id}, session))\n            self.end_desktop(sid, \"sandbox_restored\")\n            rec = self.sandboxes.restore(sid, snap_id)\n            self.bursts.reset_timers(sid)\n            self.log_human(\"restored\", sid, _with_session({\"snapshot_id\": snap_id, \"container_id\": rec[\"container_id\"]}, session))\n            return rec\n\n    def delete_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> None:\n        with self._lifecycle_lock(sid):\n            self.log_human(\"sandbox_delete\", sid, _with_session({}, session))\n            self.end_desktop(sid, \"sandbox_deleted\")\n            self.sandboxes.delete(sid)\n            self.drop_captures(sid)"
   },
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "    def restore(self, sid: str, snap_id: str) -> dict[str, Any]:\n        rec = self._rec(sid)\n        if rec[\"status\"] == \"deleted\":   # 삭제는 되돌릴 수 없다: 지운 샌드박스의 행·토큰은 되살리지 않는다\n            raise SandboxError(f\"삭제된 샌드박스는 되돌릴 수 없음: {sid}\")\n        snaps = {s[\"id\"]: s for s in self.list_snapshots(sid)}\n        if snap_id not in snaps:\n            raise SandboxError(f\"이 샌드박스의 스냅샷이 아님: {snap_id}\")\n        try:\n            self.client.containers.get(rec[\"container_id\"]).remove(force=True)\n        except NotFound:\n            pass\n        tpl = self.template_of(sid)\n        c = self._run_container(tpl, snaps[snap_id][\"image\"], rec[\"source_dir\"], f\"agentbox-{sid}\")\n        self._set(sid, container_id=c.id, status=\"running\")\n        if tpl.desktop:\n            self._wait_display(c)\n        return self.get(sid)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Both endpoints are human-only (api.py:126, 205-212), so the agent cannot trigger the interleaving, and the vulnerable window is only the few milliseconds between the restore's replacement-container creation and its status write: a DELETE that lands earlier during the multi-second container start wins instead (measured: ImageNotFound, row stays deleted). It remains a real TOCTOU - the restore thread only has to be preempted once inside that window while the delete, whose slow audit write already happened at its start, finishes - but the schedule is narrow and the second human action is unusual."
  },
  "impact": {
   "score": "medium",
   "reason": "Revocation is silently undone: the agt_ token invalidated by DELETE authorizes tool calls again in a replacement container started from the snapshot (workspace restored, network none, caps dropped), the snapshots row and image survive a deletion that was reported complete, and the audit log records sandbox_delete followed by restored. The authority regained is the same single-sandbox agent authority the token had before, so this is a failed revocation and retention violation rather than host compromise."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The control-plane lineage is certain and was reproduced deterministically with the real Settings/AuditLog/ApprovalStore/Policy/DesktopControl/AgentBox/SandboxManager code against SQLite: status, token, snapshot row, audit order and an executed tool call all matched. The remaining uncertainty is external: the harness models the Docker daemon, and the real width of the post-create window and the daemon's images.remove-conflict behavior were not measured on a real daemon."
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

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it for each read and write path.
- Trace derived copies. Sanitized primary data can become unsafe in search, cache, analytics, export, previews, logs, replicas, and backups with different ACL and retention rules.
- Deletion and revocation are lifecycle contracts. Check current, historical, cached, indexed, exported, restored, and queued copies within the product's stated boundary.
- Privacy or retention preference is not automatically a security vulnerability. Require an explicit data-access boundary or deletion/revocation guarantee and an unauthorized reader or later operation.
- Use `confirmed` for complete source-visible lineage and bounded dummy-tenant tests. Use `needs_validation` when external storage policy, retention, CDN behavior, replica lag, or backup access is unavailable.
```

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use -->
**Stale authorization and derived copy use**
Membership removal, ACL update, consent withdrawal, secret revocation, or role downgrade does not invalidate sessions, caches, subscriptions, jobs, or materialized data that continue to authorize future operations.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state -->
**Restore reintroduces invalid state**
Backup, undo, undelete, or replica recovery restores data, credentials, memberships, or permissions that current policy no longer allows. Re-authorize restored state and reapply lifecycle changes made after the snapshot.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Retention and queued-work overrun -->
**Retention and queued-work overrun**
Deletion completes in primary storage while queued processors, retries, exports, analytics, or generated artifacts recreate or retain the data beyond the promised boundary. Find idempotent deletion and tombstone propagation.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Universal moves -->
## Universal moves (apply across the above)

- Pick one protected record and draw primary write, query, cache, index, event, export, backup, deletion, and restore paths. Mark principal and tenant at every edge.
- Compare two dummy tenants through the same local service methods, then repeat after ACL change, deletion, account switch, and restore. Do not use real user data.
- Start at bypass clients, background jobs, migrations, global uniqueness, and cache keys. These paths commonly omit request-scoped identity that interactive endpoints carry.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name attacker or lower-trust principal, protected data/state, affected owner/tenant, alternate copy or operation, and unauthorized disclosure or mutation.
2. Cite both intended source-of-truth policy and the path that omits or disagrees with it. Confirm another layer does not enforce the same tenant/lifecycle condition.
3. Use local dummy tenants and non-sensitive fixtures to prove cross-scope access or stale lifecycle behavior. Stop at the minimum observable record or operation.
4. If external cache, object storage, replicas, analytics, backup, or retention policy is required, classify `needs_validation` and state the owner-observed check.
5. Return `confirmed` only with complete lineage and concrete boundary impact. Return `needs_validation` with the exact unresolved storage, ACL, invalidation, retention, or restore fact.

# Execution boundary and paths

- Agent ID `r10`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/r10/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r10 <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3`.
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py r10 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{"decision":"verified","fingerprint":"agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token"}` or `{"decision":"replace","reason":"...","record":{...}}`. No prose, no code fence.

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
