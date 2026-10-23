You are candidate verifier `v10` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/service.py:delete_sandbox:racing-restore_sandbox-resurrects-deleted-record-and-revives-agent-token",
 "title": "A restore racing a delete resurrects the deleted sandbox record and re-authorizes the agent token the delete revoked",
 "description": "DELETE /sandboxes/{sid} and POST /sandboxes/{sid}/restore both perform an unlocked read-modify-write on the same sandboxes row. When a delete lands between the restore's row read and the restore's final status write, the delete reports success and audits 'sandbox_delete', but the restore then writes status='running' and the replacement container_id back over the deleted row. The row's original token_hash is untouched, so the agent token that the delete was supposed to revoke resolves to the sandbox again and tool calls execute; the snapshot row and image also survive the delete (the running replacement container keeps the image in use, so the best-effort image removal is swallowed). The control plane thus reports a completed deletion while the sandbox, its /workspace and its agent authority are still live.",
 "root_cause": "Lifecycle operations take no per-sandbox lock and re-read nothing: Service.restore_sandbox and Service.delete_sandbox (service.py:462-475) call SandboxManager.restore and SandboxManager.delete (sandbox.py:387-401, 320-332), which each read the row once with _rec, act, and write status/container_id unconditionally. SandboxManager.restore never checks status=='deleted', so its final _set (sandbox.py:398) overwrites the delete's status write (sandbox.py:326) and reinstates the record. Revocation of the agent token is expressed only as status!='deleted' (sandbox.py:216, 221), so the overwritten status silently re-authorizes the old token.",
 "intended_behavior": "_container (sandbox.py:225-232) and the token lookups (sandbox.py:211-223) treat status=='deleted' as final: a deleted sandbox is unusable and its agent token is invalid. DELETE is the revocation contract (service.py:471-475 logs sandbox_delete, ends the desktop, deletes the container, drops captures). No later or concurrent lifecycle call may reinstate the record, re-point it at a container, or make the revoked token valid again.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 206,
   "scope": "POST /sandboxes/{sid}/restore",
   "description": "human_only route hands the client-supplied snapshot_id to box.restore_sandbox with no serialization against other lifecycle calls"
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
   "description": "force-removes the old container, then the long step follows"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 397,
   "scope": "SandboxManager.restore",
   "description": "starts the replacement container from the snapshot image while no lock protects the row"
  },
  {
   "kind": "propagation",
   "file": "agentbox/api.py",
   "line": 211,
   "scope": "DELETE /sandboxes/{sid}",
   "description": "second human request for the same sid runs concurrently on the Starlette threadpool"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 326,
   "scope": "SandboxManager.delete",
   "description": "marks the row deleted"
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 330,
   "scope": "SandboxManager.delete",
   "description": "snapshot image removal fails because the restore's new running container uses the image; APIError is swallowed, so the row and image survive"
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 398,
   "scope": "SandboxManager.restore",
   "description": "final _set overwrites the deleted status with status='running' and the new container_id"
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
   "description": "resolves the revoked token back to the sid, which api.principal turns into an agent principal"
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 462,
   "description": "restore_sandbox ordering: log, end_desktop, sandboxes.restore, bursts.reset_timers, log - no lock is acquired, unlike call_tool's _snap_locks"
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
   "line": 225,
   "description": "_container is the intended choke point that rejects status=='deleted' for every other operation; restore bypasses it by using _rec directly"
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 320,
   "description": "delete: read row, remove container, set status='deleted', then best-effort image removal with APIError swallowed"
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
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "Both requests need the human token or a browser session with scope '*'; the agent never issues them, but it holds the agt_ token that DELETE is supposed to revoke and needs no new credential."
  },
  {
   "kind": "timing_dependency",
   "description": "A DELETE for the same sid must be in flight while the restore is between its row read and its final status write. The restore path is by far the longer one (end_desktop burst close, container removal, docker run), so a delete issued during a restore normally writes its status first and is then overwritten."
  },
  {
   "kind": "data_state",
   "description": "The sandbox has at least one snapshot row; DELETE never removes snapshots rows (sandbox.py:328-332 only tries to remove images), and restore accepts any row of that sid."
  },
  {
   "kind": "system_configuration",
   "description": "No special runtime or container capability is needed: the resurrection is decided entirely in the control plane's SQLite row and token lookups. The image must be present or in use when the replacement container starts; the racing restore keeps it in use."
  }
 ],
 "execution": {
  "attacker_perspective": "Holder of the agent token (agt_...) whose authority the human tried to revoke with DELETE. No new credential is needed: after the overlapping restore the same token maps to the sid again and its tool calls return 200.",
  "payloads": [
   "POST /sandboxes/sb_54e49093/restore {\"snapshot_id\": \"snap_b2f2d73f\"}  (started first)",
   "DELETE /sandboxes/sb_54e49093  (issued while the restore is between _rec and its final _set)",
   "POST /sandboxes/sb_54e49093/tools/list_dir {\"args\": {\"path\": \"/workspace\"}} with Authorization: Bearer <the agt_ token DELETE was meant to revoke>"
  ],
  "instructions": [
   "Bounded local harness in the approved sbx sandbox (no network, no Docker daemon): real agentbox.config.Settings, agentbox.audit.AuditLog, agentbox.approvals.ApprovalStore, agentbox.policy.Policy, agentbox.desktop.DesktopControl, agentbox.service.AgentBox and agentbox.sandbox.SandboxManager with a temporary SQLite file under /scratch.",
   "Docker is replaced by a fake client that models the daemon facts this check needs: containers.run registers the name and image and refuses a duplicate container name, images.remove refuses while a container is running on the image (real docker cannot force-remove an image in use), and running an absent image raises ImageNotFound (confirmed by the sequential control run).",
   "Create a cli-template sandbox with an empty source dir, take one snapshot (docker commit is faked into the image set), then start box.restore_sandbox(sid, snap) on a thread. A run() hook parks the restore after the new container exists; the main thread then runs box.delete_sandbox(sid) to completion and releases the restore.",
   "Read back: sandboxes.get(sid)['status'], container_id, sandboxes.token_matches(sid, old_token), sandboxes.sandbox_for_token(old_token), box.call_tool(sid, 'list_dir', {'path': '/workspace'}) with the old token's sandbox, and the audit event list.",
   "Sequential control in the same run: create, snapshot, delete, then restore - it fails with ImageNotFound and leaves status 'deleted' with the token invalid."
  ],
  "observed_result": "Race run: delete returned success and audited 'sandbox_delete'; restore then returned normally and audited 'restored'. Read-back: status 'running', container_id c2, container alive, old_token_valid true, token_maps_to_sid true, snapshot rows still present (1), and POST tools/list_dir with the revoked token returned 200 {'status': 'executed', 'result': {'path': '/workspace', 'listing': 'total 0'}}. Audit sequence for the race: sandbox_created, restore_request, sandbox_delete, restored, tool_request. Sequential control: ImageNotFound 'no such image: agentbox-snap:sb_54e49093-snap_b2f2d73f', status 'deleted', token invalid."
 },
 "remediation": {
  "strategy": "Serialize all lifecycle transitions per sandbox and make deletion final at the point of the check. Take one per-sid lifecycle lock in AgentBox for pause/resume/snapshot/restore/delete (reusing the _snap_locks map with a distinct key) so delete and restore cannot interleave, and have SandboxManager.restore re-read the row under that lock and refuse status=='deleted' before it removes the old container or starts the replacement. Regression case: drive restore and delete concurrently with the harness and assert that the row is either deleted with the old token invalid and no replacement container, or restored and still deleted=false only if no delete was observed.",
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
   "reason": "The two requests must overlap and both need human authority; but when a delete is issued during a restore of the same sandbox the delete's status write is the fast one and the restore's final write lands after it, so the overlap produces the resurrection rather than an error."
  },
  "impact": {
   "score": "medium",
   "reason": "Revocation is silently undone: the agent token invalidated by DELETE authorizes tool calls again on a sandbox the human was told was deleted, its /workspace stays writable, and snapshot rows plus the image survive, while the audit log records sandbox_delete followed by restored."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "medium",
  "reason": "The control-plane logic and the full source trace are certain and were reproduced deterministically, but the harness models the Docker daemon; the live run at real docker-run latency (parent Phase 3) should confirm the overlap window and the image-in-use behavior."
 },
 "x_proposed_by": "h-lifecycle"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "agentbox%2Fapi.py%23POST%20%2Fsandboxes%2F%7Bsid%7D%2Fpause%7Cresume%7Csnapshots%7Crestore%20%2B%20DELETE%20%2Fsandboxes%2F%7Bsid%7D%20%2B%20agentbox%2Fweb.py%23POST%20%2Fui%2Fsandboxes%2F%7Bsid%7D%2Fsnapshot%7Crestore%7Cdelete::agentbox%2Fservice.py%23AgentBox.pause_sandbox%2Fresume_sandbox%2Fsnapshot_sandbox%2Frestore_sandbox%2Fdelete_sandbox%20ordering%20%28audit%2C%20end_desktop%2C%20bursts%2C%20captures%2C%20timers%29%20%2B%20api%2Fweb%20guard::agentbox%2Fservice.py%23lifecycle%20methods%20%28refactor%20PR%201%29::DATA-ISOLATION-AND-LIFECYCLE.md%23Stale%20authorization%20and%20derived%20copy%20use",
  "surface": "agentbox/api.py#POST /sandboxes/{sid}/pause|resume|snapshots|restore + DELETE /sandboxes/{sid} + agentbox/web.py#POST /ui/sandboxes/{sid}/snapshot|restore|delete",
  "boundary": "agentbox/service.py#AgentBox.pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox ordering (audit, end_desktop, bursts, captures, timers) + api/web guard",
  "local_checks": [
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "DELETE /sandboxes/{sid} is an authoritative revocation: after it reports success the row stays deleted, the old agent token stays invalid, and no concurrent lifecycle request may resurrect the record or its container",
    "method": "local",
    "result": "Violated. restore_sandbox and delete_sandbox are two unlocked read-modify-write sequences on the same sandboxes row (service.py:462-475, sandbox.py:387-401, 320-332). With a deterministic schedule that lets the DELETE finish while the restore is between _rec and its final _set, delete reported success and audited sandbox_delete, then the restore's _set wrote status=running and the new container_id back over it. Observed afterwards: status 'running', container c2 alive, sandboxes.token_matches(sid, old_token)=true, sandbox_for_token(old_token)=sid, snapshot row still present, and POST tools/list_dir with the revoked token returned 200 executed. Sequential control (delete, then restore) failed with ImageNotFound and left status 'deleted' with the token invalid, so the normal path is protected only by best-effort image cleanup (sandbox.py:328-332) which the racing restore itself defeats by keeping the image in use.",
    "artifact": "agents/h-lifecycle/artifacts/h.out"
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "The intended control for a deleted sandbox is an explicit status check (sandbox.py:225-232 _container rejects status=='deleted'; token_matches/sandbox_for_token at 211-223 filter status!='deleted'), and every lifecycle operation must apply it",
    "method": "source",
    "result": "SandboxManager.restore is the one lifecycle operation that reads the row directly with _rec (sandbox.py:388, which returns deleted rows unfiltered) and never checks status, so it can set status back to 'running' (sandbox.py:398). delete and snapshot go through _container or _rec only; pause/resume reject deleted rows through _container. The gate therefore rests on _rec callers remembering the check, not on a shared choke point.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/service.py"
    ],
    "invariant": "restore_sandbox validates snapshot_id before it mutates any observable state (ordering of log_human, end_desktop, sandboxes.restore, bursts.reset_timers, log_human)",
    "method": "local",
    "result": "Violated in ordering: service.py:464 runs end_desktop before sandbox.restore validates snap_id (sandbox.py:388-391). With an installed human takeover lease, restore_sandbox(sid, 'snap_bogus') dropped the lease (desktop.close_all at desktop.py:274-280) and wrote a human_handback audit row with reason sandbox_restored, then raised SandboxError. The sandbox itself was untouched (status still running).",
    "artifact": "agents/h-lifecycle/artifacts/h.out"
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/service.py"
    ],
    "invariant": "Queued work for a deleted sandbox cannot execute later (retention/queued-work overrun): pending approvals must not outlive DELETE",
    "method": "local",
    "result": "delete_sandbox (service.py:471-475) does not expire approvals. A pending approval for the deleted sid stayed status=pending after DELETE. It is not executable: decide() -> _snapshot -> sandbox.snapshot -> _container raises 'deleted sandbox', the approval is finished as failed and the caller gets 503 (observed: ServiceError 503, final status 'failed'). No agent-controlled execution survived the delete; only a stale, un-actionable card remains until approval_timeout expires it.",
    "artifact": "agents/h-lifecycle/artifacts/h.out"
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/gui_bursts.py",
     "agentbox/service.py"
    ],
    "invariant": "GUI burst records and snapshot timers are closed/rebound across pause, resume, restore and delete so that a later GUI input never runs without a baseline bound to the current container",
    "method": "source",
    "result": "Ordering is correct: pause logs, calls bursts.end then pause (service.py:444-448); restart timers only after resume (450-454); restore closes the burst via end_desktop before the container is replaced and resets timers after (462-469); delete ends the burst before removing the container (471-474). bursts.end cannot raise: GuiBursts._finish catches container replacement and manifest failures into gui_burst_close_failed (gui_bursts.py:113-135), and open binds the burst to container_id (65-77) so a post-restore burst cannot be judged against the pre-restore file/pid lists.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/service.py"
    ],
    "invariant": "The audit pairing 'human_takeover has a matching human_handback' survives delete/restore, including when the handback audit write fails",
    "method": "source",
    "result": "end_desktop (service.py:579-587) swallows the ServiceError that _handback_locked raises when the human_handback audit append fails (528-542); the lease is then released by desktop.close_all (desktop.py:274-280), which deletes the takeover_leases row. recover_takeovers (service.py:555-565) only logs leftovers still in that table, so the missing pairing is not repaired. The gap needs an AuditWriteError during delete/restore; on the normal path the pairing is written.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/service.py"
    ],
    "invariant": "pause_sandbox ends the human desktop lease like delete/restore do",
    "method": "source",
    "result": "pause_sandbox does not call end_desktop: a takeover lease and its control WebSocket survive a pause of the frozen container and remain after resume. No approval or tool path is freed by the lease, so nothing escalates; the only effect is that agent GUI tools keep getting 423 and the lease outlives a frozen desktop. Recorded as hardening, not a finding.",
    "artifact": null
   },
   {
    "agent_id": "h-lifecycle",
    "reviewed_paths": [
     "agentbox/web.py"
    ],
    "invariant": "UI lifecycle routes use the same human authority and session attribution as the JSON API",
    "method": "source",
    "result": "web.py:245-261 routes take_snapshot/restore/delete through browser_human (screen_human, scope '*') and pass p.session into the service call, so only a scope-'*' human session can drive them and the audit row carries the session. A desktop-link session (scope = one sid) is rejected before the service method.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-3 wording)

```json
- none
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

- Agent ID `v10`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v10/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v10 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v10 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
