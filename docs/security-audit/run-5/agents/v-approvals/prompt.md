You are candidate verifier `v-approvals` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
 "title": "One agent exec call writes a pending approval row about 45x its body size, getting past the PR #20 disk guard in a single step",
 "description": "PR #20 added AgentBox.disk_low(), a free-space pre-check at the top of call_tool, and compaction of finished approval rows. Pending approval rows are still written raw and without a size bound, and the preview the system computes is amplified from the agent's command. preview_command emits one fixed ~90-byte Korean note for every shell segment it cannot classify, so a command made of 2-byte 'x;' segments (default policy: exec-needs-approval) gives a preview about 45x the request. approvals.create stores that preview plus the raw args in the shared SQLite file, which is in WAL mode, so the data is written twice on disk. The guard was evaluated once before the call and admitted it. Locally, one 131097-byte agent request, made with 1 MiB of headroom above min_free_bytes, added 6.0 MB to agentbox.db and 6.1 MB to the -wal file, and disk_low() flipped to True afterwards. At the 8 MiB body cap the same call writes about 366 MiB of row data plus WAL, which exceeds the 256 MiB default margin on its own. Each sandbox can run 4 such calls concurrently and keep up to 20 pending. Expiry compaction does not shrink the file: it grew from 6.0 to 12.1 MB. Once the volume fills, human writes fail closed (log_human 503, decide claim 503, expire_stale stops), and the human approval UI renders every note of every pending row. This is the part of the run-4 N2 root cause (agent-grown approval rows without an effective aggregate bound) that the PR #20 fix did not cover.",
 "root_cause": "The disk guard is only a threshold check at call entry (service.py:282). The REQUIRE_APPROVAL branch then calls _preview, and preview_command appends one note per unrecognised segment with no count bound (preview.py:122-125); the 200-item cap at preview.py:126 applies only to 'affected'. approvals.create (approvals.py:53-57) stores json.dumps(args) and json.dumps(preview) unbounded. bound_payload is applied only to the audit copy (audit.py append) and to finished rows (_finish, service.py:406-411), never at creation.",
 "intended_behavior": "No single agent request can make the control plane persist more than a small, fixed bound of approval data. Pending rows hold the same bounded shape as the audit log (capped args and capped preview with a bounded notes list), so the 256 MiB guard margin cannot be crossed by an admitted call.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 274,
   "scope": "call_tool route",
   "description": "An agent token posts {\"args\": {\"command\": \"x;x;...\"}}. _BodyLimit allows up to AGENTBOX_MAX_BODY (8 MiB)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 282,
   "scope": "AgentBox.call_tool",
   "description": "disk_low() is evaluated once. Free space is still above min_free_bytes, so the call is admitted."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 311,
   "scope": "AgentBox._call_tool",
   "description": "policy.decide returns exec-needs-approval because 'x' is not in the read-only allowlist (default_policy.yaml)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 332,
   "scope": "AgentBox._call_tool",
   "description": "_preview calls sandboxes.preview, which calls preview_command, for the raw command."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 125,
   "scope": "preview_command",
   "description": "One note per segment is appended without a bound: 65536 notes for 65536 'x;' segments."
  },
  {
   "kind": "sink",
   "file": "agentbox/approvals.py",
   "line": 56,
   "scope": "ApprovalStore.create",
   "description": "json.dumps(args) and json.dumps(preview) are inserted raw into the shared SQLite file (WAL)."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/preview.py",
   "line": 125,
   "description": "notes.append(f\"'{_short_seg(seg)}' 부분의 영향은 ...\") runs once per segment. Only 'affected' is truncated, at line 126."
  },
  {
   "file": "agentbox/approvals.py",
   "line": 56,
   "description": "create stores args and preview with json.dumps and no size check."
  },
  {
   "file": "agentbox/service.py",
   "line": 282,
   "description": "The only disk guard is a pre-check at call entry."
  },
  {
   "file": "agentbox/service.py",
   "line": 338,
   "description": "approvals.create is called with the uncapped preview after the guard."
  },
  {
   "file": "agentbox/audit.py",
   "line": 260,
   "description": "The shared DB is put in WAL mode, so the large insert is also written to agentbox.db-wal."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 16,
   "description": "The human approval card renders every note of every pending row."
  },
  {
   "file": "agentbox/config.py",
   "line": 57,
   "description": "Default min_free_bytes margin is 256 MiB."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Requires an agent token for a running sandbox. This is the lowest-trust principal, and the threat model assumes it may be prompt-injected."
  },
  {
   "kind": "system_configuration",
   "description": "Default policy (or any policy that sends an exec to require_approval) and AGENTBOX_MIN_FREE > 0. The body must fit AGENTBOX_MAX_BODY (8 MiB default)."
  },
  {
   "kind": "data_state",
   "description": "Fewer than PENDING_APPROVALS_MAX (20) pending approvals for the sandbox, and free space above min_free_bytes when the call starts."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent holding only its own sandbox's agent token calls the exec tool with a long command made of trivial unrecognised segments.",
  "payloads": [
   "POST /sandboxes/{sid}/tools/exec  {\"args\": {\"command\": \"x;\" * 65536}}  (131097-byte JSON body; scale to ~8 MiB for the deployed cap)"
  ],
  "instructions": [
   "In tools/sbx (no network, no Docker, 512 MiB, 120 s), build AgentBox with the real AuditLog, ApprovalStore, DesktopControl and default_policy.yaml, plus a fake SandboxManager whose preview() calls the real preview_command with empty glob/walk callbacks (scratch/h.py).",
   "Set settings.min_free_bytes = shutil.disk_usage(home).free - 1 MiB so that disk_low() is False.",
   "Call box.call_tool('sb_x', 'exec', {'command': 'x;'*65536}, actor='agent') once, then measure agentbox.db and agentbox.db-wal, the approvals row lengths, disk_low(), the audit row sizes, the rendered _approvals.html size, and the file size after expire_stale compaction."
  ],
  "observed_result": "decision=exec-needs-approval; call_tool status=202; disk_low before=False, after=True; agentbox.db 4096 -> 6004736 bytes (45.8x the body), -wal 6089392 bytes; pending row args 131087 bytes, preview 5832767 bytes, 65536 notes; audit approval_requested payload only 83141 bytes; _approvals.html fragment 7472223 bytes for this one row; after expiry, row compacted to 16533/83045 bytes but agentbox.db grew to 12054528 bytes (2890 free pages); audit verify ok. (agents/h-approvals/artifacts/h.out)"
 },
 "remediation": {
  "strategy": "Bound pending rows at creation. (1) Reject agent exec commands, and other string args, above a fixed size (for example LOGGED_ARGS_MAX) with 413 before policy and preview. (2) In preview_command, cap the notes (for example, keep the first 50 plus one 'and N more segments' summary). (3) Store bound_payload(preview) in approvals.create. (4) Re-check disk_low() immediately before approvals.create, and treat a sqlite3.Error from create or _finish as 503. (5) Optionally run 'PRAGMA wal_checkpoint(TRUNCATE)' and VACUUM after prune, so that compaction and prune actually return space.",
  "code_changes": [
   {
    "file_name": "agentbox/preview.py",
    "fixed_code": "NOTES_MAX = 50\n...\n    if len(notes) > NOTES_MAX:\n        extra = len(notes) - NOTES_MAX\n        notes = notes[:NOTES_MAX] + [f\"... 외 {extra}개 조각의 영향도 자동 계산하지 못함. 명령 원문을 확인할 것.\"]\n    return {\"command\": command, \"cwd\": WORKSPACE, \"affected\": affected, \"notes\": notes}"
   },
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "            preview = bound_payload(preview)\n            if actor == \"agent\" and self.disk_low():\n                raise ServiceError(507, \"컨트롤 플레인 디스크의 남은 공간이 부족해 승인 요청을 만들지 않음.\")\n            apr = self.approvals.create(sandbox_id=sid, tool=tool, args=args, ...)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "Any agent token can do it with one ordinary-looking request under the default policy. The threat model assumes a prompt-injected agent."
  },
  "impact": {
   "score": "medium",
   "reason": "Shared control-plane disk and availability: a few requests fill the DB volume past the guard, after which human audit-logged actions (decide, delete, pause) fail closed with 503 and the approval UI bloats. Recovery needs the operator to free disk out of band. No integrity or confidentiality loss."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "The full call_tool path ran with the real policy, preview, store and audit code and the observed byte counts. Scaling to the 8 MiB cap is linear arithmetic from the measured 45.8x ratio; filling a real disk was deliberately not tested."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Every%20agent-reachable%20write%20to%20the%20shared%20control-plane%20SQLite%20file%20and%20host%20disk%20while%20AgentBox.disk_low%28%29%20is%20true%20or%20near%20the%20threshold%20%28tool%20calls%2C%20approval%20creation%2Fexpiry%2C%20GUI%20burst%20records%2C%20desktop%20and%20file%20routes%29%2C%20plus%20finished-approval%20row%20compaction::Disk-pressure%20guard%20and%20approval%20compaction%20%28PR%20%2320%29%3A%20call_tool%20refuses%20agent%20calls%20with%20507%20when%20free%20space%20on%20db_path.parent%20is%20below%20AGENTBOX_MIN_FREE%2C%20api.py%20skips%20the%20agent%20approval_forbidden%20row%2C%20_finish%20rewrites%20finished%20rows%27%20args%2Fpreview%20to%20the%20bounded%20audit%20shape%2C%20decide%20maps%20claim%20sqlite3.Error%20to%20503%20and%20expire_stale%20stops%20on%20sqlite3.Error.%20Invariant%3A%20an%20agent%20cannot%20keep%20growing%20the%20database%20or%20host%20disk%20past%20the%20guard%20through%20another%20route%2C%20and%20the%20human%20can%20still%20decide%2C%20delete%20and%20verify%20while%20low%3B%20compaction%20keeps%20what%20the%20approval%20card%20and%20audit%20need.::agentbox%2Fservice.py%23call_tool%2Fdisk_low%2F_finish%2Fdecide%2Fexpire_stale%2Flog_best_effort%20%2B%20agentbox%2Fapprovals.py%23finish%20%2B%20agentbox%2Fapi.py%23call_tool%20route%20%2B%20agentbox%2Fgui_bursts.py%23_finish%20%2B%20agentbox%2Fconfig.py%23min_free_bytes::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Quota-accounting%20scope%20and%20reset%20gaps",
  "surface": "Every agent-reachable write to the shared control-plane SQLite file and host disk while AgentBox.disk_low() is true or near the threshold (tool calls, approval creation/expiry, GUI burst records, desktop and file routes), plus finished-approval row compaction",
  "boundary": "Disk-pressure guard and approval compaction (PR #20): call_tool refuses agent calls with 507 when free space on db_path.parent is below AGENTBOX_MIN_FREE, api.py skips the agent approval_forbidden row, _finish rewrites finished rows' args/preview to the bounded audit shape, decide maps claim sqlite3.Error to 503 and expire_stale stops on sqlite3.Error. Invariant: an agent cannot keep growing the database or host disk past the guard through another route, and the human can still decide, delete and verify while low; compaction keeps what the approval card and audit need.",
  "local_checks": [
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/api.py",
     "agentbox/preview.py",
     "agentbox/approvals.py",
     "agentbox/policy.py",
     "agentbox/default_policy.yaml",
     "agentbox/audit.py"
    ],
    "invariant": "disk_low() (service.py:282, 388-404) keeps an agent from growing the shared SQLite file past AGENTBOX_MIN_FREE: once the guard admits a call, the call's own writes must be small relative to the margin.",
    "method": "local",
    "result": "Fails. The guard is a single pre-check; the REQUIRE_APPROVAL branch then writes a pending approvals row whose preview is unbounded and amplified. preview_command (preview.py:122-125) appends one ~90-byte Korean note per unrecognised segment, so the 2-byte segment 'x;' yields a 45x larger preview, and approvals.create (approvals.py:53-57) stores args and preview raw. In the sandbox, with min_free_bytes set to free-1MiB (disk_low False), ONE agent call_tool('exec', {'command': 'x;'*65536}) (131097-byte JSON body, default policy exec-needs-approval) returned 202, grew agentbox.db from 4096 to 6004736 bytes plus a 6089392-byte -wal file (WAL mode set at audit.py:260), and disk_low() was True afterwards. The pending row held args 131087 bytes and preview 5832767 bytes (65536 notes). The audit approval_requested row was capped at 83141 bytes by bound_payload, so the growth is in the approvals table only. The ratio is linear, so a body at the 8 MiB AGENTBOX_MAX_BODY cap gives about 366 MiB of DB plus a similar WAL in one admitted call. That one call already exceeds the 256 MiB default margin, and 4 concurrent calls per sandbox (tool_concurrency) all pass the pre-check.",
    "artifact": "agents/h-approvals/artifacts/h.out"
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/gui_bursts.py",
     "agentbox/service.py",
     "agentbox/desktop.py"
    ],
    "invariant": "No other agent-token route or background path writes agent-sized data to SQLite while disk_low is true.",
    "method": "source",
    "result": "Holds apart from the candidate above. Agent-token routes: POST /sandboxes/{sid}/tools goes through call_tool and is refused with 507 before close_idle (service.py:282-285). POST /approvals/{aid} skips the approval_forbidden row while low (api.py:312-317). GET /approvals/{aid} (api.py:288-299) runs expire_stale, which only expires or compacts existing rows (at most 20 pending per sandbox) and runs close_idle. close_idle writes one gui_changes or close record per open burst through log_best_effort, and AuditLog.append bounds each payload to 128 KiB (audit.py bound_payload). No new bursts open while low, because agent GUI input is refused. GET /sandboxes/{sid} and GET /sandboxes/{sid}/desktop/state (desktop.py:210) are reads. Unauthenticated or invalid agent tokens do not write audit rows (api.py:173-182).",
    "artifact": null
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/approvals.py",
     "agentbox/templates/_approvals.html",
     "agentbox/web.py"
    ],
    "invariant": "Finished-row compaction keeps what the approval card and audit need, and the human can still decide while low.",
    "method": "source",
    "result": "Compaction keeps what the card needs. _finish (service.py:406-411) stores _logged_args (size, sha256, 16 KiB args_head) and bound_payload(preview), and the done list in _approvals.html:26 reads args.command, args.path or args.args_head. The audit row carries the same _logged_args shape. Compaction does not reclaim space: in the local run, expiring the 5.8 MB row raised agentbox.db from 6004736 to 12054528 bytes with 2890 free pages, and nothing in agentbox/ runs VACUUM. Recovery under real pressure therefore needs more free space first. In decide, only claim is wrapped for sqlite3.Error (service.py:446-449). A sqlite3.Error from _finish on the deny path (service.py:462) or after a successful run (service.py:481) propagates as a 500 after the tool has already run, and can leave the row in 'approved'. retention._DONE never prunes 'approved' rows and expire_stale never expires them. Recorded as hardening. While a pending row from the candidate exists, the human approval fragment renders every note (_approvals.html:16, web.py:233). One 128 KiB-body request produced a 7472223-byte HTML fragment, so the UI decision path degrades in proportion. The JSON decide API stays usable.",
    "artifact": null
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/config.py",
     "agentbox/service.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "The guard measures the filesystem that agent-driven writes land on.",
    "method": "source",
    "result": "disk_low checks shutil.disk_usage(db_path.parent) (service.py:395), and AGENTBOX_DB may differ from AGENTBOX_HOME (config.py:29, 95-96). Approval capture PNGs go to home/captures (api.py:154), which is bounded by the pending cap. docker commit snapshots and the container writable layer land on the Docker data root. They are bounded only by snapshot_quota and the optional AGENTBOX_DISK storage_opt (sandbox.py:263-264), which README:286,360 documents as a partial SB-5 control. While low, every agent call is refused, so no new agent-triggered commits occur. A filesystem mismatch weakens the guard but does not open a separate agent route; recorded as hardening.",
    "artifact": null
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/service.py"
    ],
    "invariant": "Prior run-4 record agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap: agent input reaches the append-only audit log only in bounded form.",
    "method": "local",
    "result": "No longer holds; the root cause is fixed. AuditLog.append applies bound_payload(self._mask(payload)) to every record, so approval previews and str(e) error strings are bounded too. Locally, the approval_requested payload for a 5832767-byte preview was stored as 83141 bytes, and tool_request as 16543 bytes. The masking pass runs before bounding (linear: about 1.0 s for 65536 notes), which is CPU only.",
    "artifact": "agents/h-approvals/artifacts/h.out"
   }
  ]
 },
 {
  "coverage_id": "approvals%20table%20rows%20%28args%2C%20preview%2C%20result%29%20written%20for%20every%20REQUIRE_APPROVAL%20tool%20call::agentbox%2Fapprovals.py%23create%20stores%20raw%20agent%20args%20and%20preview%20for%20pending%20rows%20without%20audit%20masking%20or%20a%20size%20cap%20%28finish%20compacts%20them%20since%20PR%20%2320%29%2C%20rows%20outlive%20sandbox%20deletion%2C%20and%20only%20the%20host%20prune%20command%20removes%20finished%20rows::agentbox%2Fapprovals.py%20%2B%20agentbox%2Fservice.py%23_call_tool%2Fdecide%2Fdelete_sandbox%20%2B%20agentbox%2Fapi.py%23GET%20%2Fapprovals::DATA-ISOLATION-AND-LIFECYCLE.md%23Retention%20and%20queued-work%20overrun",
  "surface": "approvals table rows (args, preview, result) written for every REQUIRE_APPROVAL tool call",
  "boundary": "agentbox/approvals.py#create stores raw agent args and preview for pending rows without audit masking or a size cap (finish compacts them since PR #20), rows outlive sandbox deletion, and only the host prune command removes finished rows",
  "local_checks": [
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/approvals.py",
     "agentbox/service.py",
     "agentbox/preview.py"
    ],
    "invariant": "Pending approvals rows have a per-row size bound in proportion to the request.",
    "method": "local",
    "result": "Fails; this is the same root cause as the disk-guard candidate. approvals.create (approvals.py:49-59) json.dumps raw args and preview, and _call_tool (service.py:332-339) passes the uncapped preview. The 'preview failed' fallback (service.py:334) also copies the raw command. Measured: a 131097-byte request produced a pending row with a 5832767-byte preview (65536 notes). Compaction happens only at finish (service.py:406-411).",
    "artifact": "agents/h-approvals/artifacts/h.out"
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/api.py",
     "agentbox/approvals.py",
     "agentbox/audit.py",
     "agentbox/retention.py"
    ],
    "invariant": "Unmasked approvals data reaches no principal lower than the human.",
    "method": "source",
    "result": "Holds. GET /approvals is human_only (api.py:282-286). GET /approvals/{aid} returns only id, status, result and decided_at to an agent, and only for its own sandbox (api.py:294-298). result is the agent's own tool output. The UI routes need a full-scope human session. approvals rows (args head, preview, result) are not passed through AuditLog._mask, and retention._write_archive (retention.py:67-84) copies them unmasked into the prune archive next to the masked audit rows. The only readers are the human and the host operator, who already hold those values, so this is recorded as hardening rather than a finding.",
    "artifact": null
   },
   {
    "agent_id": "h-approvals",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/retention.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "Approval rows and side artifacts of a deleted sandbox cannot be acted on or re-executed after deletion, and retention removes finished rows.",
    "method": "source",
    "result": "Holds. delete_sandbox (service.py:538-543) drops capture PNGs, and SandboxManager.delete marks the sandbox deleted (sandbox.py:320-326). Leftover pending rows expire through expire_stale and are compacted. Approving one reaches _snapshot, and sandboxes._container raises SandboxError for a deleted sandbox (sandbox.py:225-228), so decide records FAILED and runs nothing. Finished rows (denied, executed, failed, expired) are removed only by the host prune command (retention.py:41, 54-64), which matches the documented design. The one exception is a row stuck in 'approved' after a _finish storage error (see the unit-1 hardening note).",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-4 wording)

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention",
 "title": "Agent-grown audit and approval rows in the shared control-plane SQLite file have no aggregate bound or retention, so an agent can fill the host disk and neither recovery path keeps the audit chain",
 "description": "Every accepted agent tool request appends two audit rows (tool_request before the policy decision, policy_decision as soon as decide() returns) before any approval request, snapshot or execution, a risky call adds an approval_requested row plus an approvals row holding the full raw args, and every failed POST /approvals/{aid} adds an approval_forbidden row. Args are now capped per record (80,000-byte command is stored as a 16,384-byte head), but nothing bounds the tables: in an isolated fixture two rows per call added 17,203 bytes to the .db file, identically at n=20 and n=40, and 512 bytes per call for {command: ls}; five approval rows of 400,000-byte args took 2,007,040 bytes and every row survived executed/denied/expired. Triggers abort UPDATE and DELETE on audit, grep finds no DELETE for audit or approvals, no VACUUM, no count/size quota and no retention job, so growth is permanent and host disk is the only limit. When the volume fills, AuditLog.append raises AuditWriteError, which service.py turns into 503 for tool calls, human lifecycle, approval decisions and handbacks, so all sandboxes stop rather than the offending one. Recovery is not available either: deleting the oldest rows made verify() fail permanently at the first survivor (broken_at=7, 'id가 1 다음에 7로 건너뜀'), while deleting every row made verify() report ok=True with checked=0, so an operator must choose between permanently broken verification and a silently erased history.",
 "claimed_root_cause": "The audit table is append-only by design (audit.py:35-38) and the per-record arg cap (service.py:37-38, 180-194) is the only bound on agent-driven growth; grep over agentbox/ finds no aggregate quota, retention window, pruning command or size check for the audit or approvals tables (the only sqlite DELETEs are ui_tickets, ui_sessions and takeover_leases in desktop.py), and the delete path for a sandbox only unlinks capture PNGs (service.py:106-109, 471-475). The shared SQLite file used by AuditLog, SandboxManager, ApprovalStore and DesktopControl (api.py:86-94, config.py:84-86, default ./data/agentbox.db, host bind mount at deploy/docker-compose.yml:28) therefore has the host volume as its only limit, and capacity recovery is mutually exclusive with the integrity contract (audit.py:230-236).",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "call_tool (POST /sandboxes/{sid}/tools/{tool})",
   "description": "An agent token reaches this route through principal() (api.py:115-124). The body is ToolCall whose args is an unconstrained dict[str, Any] (api.py:51-52), and there is no request-body, key-count or value-size cap on this route; the only body cap in the API is the human upload route (api.py:278-283) and the shipped Caddyfile is a bare reverse_proxy with no request_body limit (deploy/Caddyfile:4-6)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 295,
   "scope": "_call_tool: tool_request and policy_decision appends",
   "description": "tool_request is appended with _logged_args(args) (295-296) and policy_decision is appended the moment policy.decide returns (297, appended at 303), before any approval request (324), snapshot (343) or execution, so every accepted request writes two rows even when the decision is DENY (308-309) and nothing runs."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 189,
   "scope": "_logged_args per-record cap",
   "description": "Only the single record is bounded: args over 64 KiB become a 16 KiB head plus args_bytes and args_sha256. Measured: {'command': 'a'*80000} produced args_head of exactly 16,384 bytes and args_bytes 80,015; the two rows added 17,203 bytes per call at both n=20 and n=40 (linear), and {command: 'ls'} added 512 bytes per call, so per-record capping does not bound the table."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 324,
   "scope": "_call_tool REQUIRE_APPROVAL branch",
   "description": "approvals.create stores the full raw args and preview with no cap (approvals.py:49-59); PENDING_APPROVALS_MAX=20 (service.py:44, 312-316) limits pending concurrency only, and measured rows of 400,000-byte args took 401,408 bytes each and were still present after executed, denied and expired transitions. A sandbox delete does not remove them."
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 179,
   "scope": "AuditLog.append INSERT",
   "description": "The row is inserted into the same SQLite file; the append-only triggers (audit.py:35-38) abort any UPDATE and DELETE (both reproduced: 'audit log is append-only'), and no code path in the package removes audit rows."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 592,
   "scope": "log_human fail-closed conversion",
   "description": "At disk-full every append raises AuditWriteError, which becomes ServiceError(503) here (593-594) and likewise for tool calls (305-306), approval decisions (402-404) and handbacks (539-541), so the blast radius is every sandbox and every human operation rather than the agent's own process."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 230,
   "scope": "AuditLog.verify chain and id check",
   "description": "verify starts from GENESIS with expected_id 1 and rejects the first row that does not chain (233-236). Reclaiming space by deleting the oldest rows therefore fails permanently (measured: after removing ids 1..6, ok=False, broken_at=7), while deleting every row returns ok=True with checked=0, so capacity recovery either breaks /audit/verify for good or erases the history without a trace."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/audit.py",
   "line": 35,
   "description": "audit_no_update and audit_no_delete raise ABORT 'audit log is append-only'; the fixture reproduced both rejections."
  },
  {
   "file": "agentbox/audit.py",
   "line": 233,
   "description": "verify() rejects any row whose id is not expected_id and any prev_hash that does not match, which is what makes prefix pruning distinguishable from tampering forever."
  },
  {
   "file": "agentbox/service.py",
   "line": 37,
   "description": "LOGGED_ARGS_MAX and LOGGED_ARGS_HEAD are the only size controls on the audit path and they are per record, not per table, per sandbox or per deployment."
  },
  {
   "file": "agentbox/service.py",
   "line": 182,
   "description": "The author comment states the audit log cannot be deleted and that an agent growing it with large args cannot be undone."
  },
  {
   "file": "agentbox/service.py",
   "line": 106,
   "description": "drop_captures removes only capture PNGs (106-109) and delete_sandbox only calls it (471-475); approval rows holding the full unmasked args and preview survive decision and expiry (5 of 5 measured rows remained) and nothing removes them on sandbox deletion."
  },
  {
   "file": "agentbox/config.py",
   "line": 44,
   "description": "snapshot_quota exists specifically so an agent cannot fill host disk with docker commits without a human, showing the intended invariant that agent actions are host-disk bounded; no comparable control exists for the audit or approvals tables."
  },
  {
   "file": "agentbox/approvals.py",
   "line": 49,
   "description": "create() stores json.dumps(args) and the preview with no cap, and ApprovalStore exposes no delete method; 400,000-byte args measured 401,408 bytes per row."
  },
  {
   "file": "agentbox/api.py",
   "line": 86,
   "description": "AuditLog, SandboxManager, ApprovalStore and DesktopControl all open settings.db_path, so one file carries all four components' state (config.py:84-86; the compose deployment bind-mounts that home on the host, deploy/docker-compose.yml:28)."
  },
  {
   "file": "agentbox/web.py",
   "line": 206,
   "description": "/ui/approvals loads every historical approval row for the sandbox with full args and preview parsed and then keeps the last five (208-209); agentbox/templates/index.html:25 and agentbox/templates/sandbox.html:25 poll that view every 2 s, so retained rows keep costing control-plane read work."
  }
 ],
 "blockers": [
  "Free space, any filesystem or volume quota, and the planned lifetime of the volume holding data/agentbox.db (config.py:29 home=./data, config.py:84-86 db_path, deployed as a host bind mount at deploy/docker-compose.yml:26-28) are deployment facts. Nothing in the repository bounds stored total: no retention, no count or size quota, no VACUUM. At the measured 17,203 bytes per maximum-size tool call (512 bytes for a trivial call) the time to exhaustion depends entirely on that free space, from minutes on a small volume to months on a large one, and no repository fact decides it.",
  "The call rate an agent can sustain is partly a deployment fact: the repository has no rate limit on the tool route, tool_concurrency=4 (config.py:53) and the 32-thread tool_pool (api.py:103) bound concurrency only, and the shipped Caddyfile is a bare reverse_proxy (deploy/Caddyfile:4-6), but any operator-added proxy or network control is outside the source.",
  "Whether operators prune or rotate that SQLite file out of band, and which loss they accept, is a deployment/owner decision: source and fixture show that partial pruning permanently fails /audit/verify (audit.py:230-236) while total truncation passes as an empty log, so the product offers no capacity recovery that keeps the history verifiable."
 ],
 "validation_plan": {
  "local": "Already performed in the approved sandbox (tools/sbx.py v03: /target read-only on PYTHONPATH, /scratch writable, no network, no Docker socket, uid 65534, 512 MiB, 120 s). Built AuditLog and ApprovalStore on scratch databases and replayed exactly what _call_tool writes: (1) _logged_args('exec', {'command': 'a'*80000}) returned args_head of 16,384 bytes and args_bytes 80,015; (2) 20 and 40 pairs of tool_request plus policy_decision rows added 344,064 and 688,128 bytes after PRAGMA wal_checkpoint(TRUNCATE), i.e. 17,203 bytes per call at both sizes, and 40 pairs with {'command': 'ls'} added 20,480 bytes, i.e. 512 bytes per call; (3) DELETE FROM audit and UPDATE audit both failed with sqlite3.IntegrityError 'audit log is append-only'; (4) dropping only the delete trigger and removing ids 1..6 left verify() returning ok=False, checked=0, broken_at=7, reason 'id가 1 다음에 7로 건너뜀', while deleting every row left verify() returning ok=True with checked=0; (5) five ApprovalStore rows of 400,000-byte args took 2,007,040 bytes (401,408 each) and all five were still listed after executed, denied and expired, with no delete method on the store; (6) approvals.list() re-parses full args. The disk-full to AuditWriteError to 503 conversion was not exercised (filling a filesystem is a saturation test); it rests on audit.py:193-194 wrapping sqlite3.Error and the fail-closed handlers cited in the trace. Output: scratch/fixout.txt and scratch/fixout2.txt; the numbers above were observed directly, the files are supplementary.",
  "deployment": "Owner-observed on a throwaway deployment, never a shared or production host, and without filling the volume: record the free space and any quota on the volume holding data/agentbox.db; issue 200 bounded tool calls from one agent token with 80,000-byte exec commands (denied calls are sufficient, since the two audit rows are written before any execution) and 200 with {command: ls}; confirm the .db size delta is about 3.4 MB and 0.1 MB respectively and that it does not shrink after the calls stop, after sandbox deletion, or after any documented maintenance command; then check whether the operator has any out-of-band retention or rotation for that file, and confirm that once the volume is full the tool route and the human lifecycle route both return 503 from AuditWriteError while other sandboxes are unaffected by definition only. Extrapolate from the per-call delta instead of filling the disk."
 }
}
```

# Parent-live evidence

- none (no parent-live observation was taken for this candidate)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-5)
Source ref: `346df29` (`main`, after fix PRs #16-#23). Profile `standard`, focused follow-up, budget 30. This file is the run-4 architecture (built at `9805d91` from recon-1a..1d) plus a parent-written delta in section 0. No reconnaissance agent was spent in run-5: the parent re-read every file changed since `9805d91` (15 files, +712/-148 in `agentbox/`). **Line numbers in sections 1-8 are run-4 (`9805d91`) numbers and are approximate in this tree; section 0 numbers are current.**
## 0. Run-5 delta (current line numbers, `346df29`)
- **Body cap (F1 fix, PR #16).** `api.py:89-148` `_BodyLimit` pure-ASGI middleware, added at `api.py:170`, runs before routing and auth for every `http` scope (not `websocket`). Cap = `max_upload_body_bytes` (`AGENTBOX_MAX_UPLOAD_BODY`, 256 MiB) when `POST` and path fullmatches `/sandboxes/[^/]+/files` (`api.py:86`), else `max_body_bytes` (`AGENTBOX_MAX_BODY`, 8 MiB) (`config.py:65-66`). Content-Length over cap or non-digit → 413 without reading; streamed bodies are counted in `limited_receive` and cut with a fake `http.disconnect`. Upload route `api.py:335-352` authenticates (`screen_human`) then reads `request.form()` and each file with `read(limit+1)` (`max_upload_bytes` 50 MiB). `deploy/Caddyfile` adds `request_body` caps. `web.py` has its own upload form (`web.py:~229`).
- **Audit cap (F3 fix, PR #16).** `audit.py:126-152` `_bound`/`bound_payload` bound every payload before hashing (strings 64 KiB, lists 200, row 128 KiB); `AuditLog.append` (`audit.py:281`).
- **GUI gate (F2) and quota recheck (F7), PR #17.** `_run_tool` refuses GUI input without an open burst (`GuiBursts.covers`, `gui_bursts.py:68`); allow-path commit rechecks `_over_snapshot_quota` (`service.py:254`) and logs `tool_blocked`/`snapshot_quota_changed`.
- **Lifecycle lock (F6), F4, F5, F8, PR #18.** `AgentBox._lifecycle` (`service.py:500`) serialises pause/resume/snapshot/restore/delete per sandbox; `SandboxManager.restore` refuses `deleted`. Preview `_expand`/`_walk` use NUL-separated output. `extract_novnc` (`sandbox_desktop.py:174`) single-flight with 60 s negative cache. Login failures rate-logged (`web.py:102-114`, 5/min + `suppressed_before`); token compare on bytes.
- **Control-character filter (N5, PR #19).** `display.escape_controls` escapes Unicode categories Cc/Cf/Zl/Zp; shared by `web._shown` and `cli._safe`.
- **Disk guard and approval compaction (N2 stage 1, PR #20).** `AgentBox.disk_low` (`service.py:388-404`) uses `shutil.disk_usage(db_path.parent).free < min_free_bytes` (`AGENTBOX_MIN_FREE`, 256 MiB; 0 disables); `call_tool` (`service.py:279-285`) refuses **agent** calls with 507; `api.py:313` skips the agent `approval_forbidden` row while low; state changes log `disk_low`/`disk_ok` only on transitions. `_finish` (`service.py:406-411`) rewrites finished approval rows' `args` with `_logged_args` (size/sha256/16 KiB head) and `preview` with `bound_payload` via `ApprovalStore.finish(..., args, preview)` (`approvals.py:91-100`, `COALESCE`). Pending rows still hold raw args/preview (`approvals.py:49-59`). `decide` maps a `claim` `sqlite3.Error` to 503; `expire_stale` (`service.py:422-438`) returns on `sqlite3.Error`. `_approvals.html` shows `args.args_head` for compacted rows.
- **Prune and anchor (N2 stage 2, PR #21).** `retention.py` (new): `prune(db_path, before, archive, dry_run)` — host CLI only (`cli.py:319` `cmd_prune`, `agentbox prune --before --archive [--dry-run]`), never HTTP. Plan: audit rows with `id < MIN(id WHERE ts >= cutoff)`, approvals with status in denied/executed/failed/expired and `created_at < cutoff` (`retention.py:54-64`). Archive written outside the DB lock with `open(path, "xb")` + gzip + fsync, sha256 (`:67-84`). Then `BEGIN IMMEDIATE`: concurrent-prune check, `DROP TRIGGER audit_no_delete`, `DELETE`, recreate trigger from `NO_DELETE_SQL`, insert `audit_anchor` row (always, even approvals-only), delete approvals, `insert_record(... "audit_pruned" ...)`, `COMMIT`; on any exception rollback and unlink the archive (`:105-132`). `audit.py`: `audit_anchor` table with no-update/no-delete triggers (`:44-55`), `latest_anchor:178`, `check_chain:184`, `read_archive:208` (gzip JSON Lines, header format check), `insert_record:228` (chains from last row else latest anchor else GENESIS; `append` uses it), `verify:336` (starts at latest anchor; anchor + empty table fails), `verify_archives:351` (GENESIS → each archive must match its anchor's sha256/last row → live table). `cli.py:299` `cmd_verify --archive` runs `verify_archives` locally against `Settings().db_path`. Known limit (README): anchor lives in the same DB, so a DB writer can forge it.
- **Window owner via XRes (N4, PR #22).** `sandbox_desktop.py:42-75` `_WINDOW_OWNERS` ctypes script (libX11 + libXRes `XResQueryClientIds` mask 2 → `XResGetClientPid`); `desktop_processes` (`:77-~95`) runs `sh -c 'xdotool search --onlyvisible --name . 2>/dev/null | xargs -r /usr/bin/python3 -I -c "$0"' <script>` as the desktop user inside the container; nonzero exit → no window pids (fail-closed: more strays). `gui_state._new_processes:53` returns `(stray, kept)`; `gui_kept:95`. `gui_bursts._stop_strays:89` stores `_kept[sid] = (container_id, pids)` and logs `gui_processes_kept`; `open:73` removes kept pids from the next baseline when the container id matches.
- **Docs (PR #23).** LLM-provider data path documented as an accepted limitation; out of scope for hunting.
Unchanged since run-4 and not re-hunted: N1 (`same_origin` scheme) and N3 (container output readers) remain needs_validation.
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
| Agent → approval 

# Relevant companion blocks (verbatim)

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost path, a missing effective bound, and impact on another user, shared service, safety function, or operator-owned spend. Self-limiting work in the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body/message/file caps, concurrency, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before calling a path unbounded.
- Do not run stress, saturation, or production tests. Use asymptotic analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State attacker cost, service work, persistence, scope, and recovery. One bounded input with superlinear or persistent shared effect is materially different from sustained volume.
- Use `confirmed` for source-visible bounds failures demonstrated safely. Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behavior is outside the repository.
```

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps -->
**Quota-accounting scope and reset gaps**
Accounting uses attacker-influenceable IP, route, tenant, key prefix, task ID, or other dimension, allowing one principal's work to escape its intended budget or consume another principal's allocation. Review integer overflow, distributed races, retries, reconnects, and account switching.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Retry storm and fail-open amplification -->
**Retry storm and fail-open amplification**
Timeouts, dependency errors, partially processed messages, or health-check failures trigger synchronized or unbounded retries without jitter, ceilings, circuit breaking, or deduplication. Verify one bounded failure source can create persistent aggregate work.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unsafe recovery and capacity rollback -->
**Unsafe recovery and capacity rollback**
A restart, restore, fallback, or cleanup path rebuilds unbounded state, ignores current quotas, or restores the input that immediately repeats failure. Recovery correctness is part of availability.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves -->
## Universal moves (apply across the above)

- Build an input-to-resource table: earliest accepted size/cardinality, work before auth, downstream fan-out, persistence, shared pool, limit and cleanup owner, recovery.
- Compare aggregate limits with per-object limits. Ten thousand valid one-byte items may evade a per-message cap while exhausting tenant-wide or process-wide state.
- Validate only in an isolated fixture with strict CPU/memory/time limits and small growth points. Mock external and paid calls and stop once the missing bound or cancellation is observable.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name untrusted input, requester work, service amplification or retained resource, shared blast radius, and recovery. Missing limits without concrete shared impact are hardening.
2. Confirm no source-visible upstream, parser, queue, tenant, or framework bound prevents the path. Unknown deployed controls require `needs_validation`.
3. For superlinear behavior, establish the accepted complexity and bounded local growth. For leaks, show repeatable retention after cleanup should occur. For fatal paths, identify process/supervisor isolation.
4. Prioritize by low requester work, unauthenticated reachability, cross-tenant scope, persistence, and poor recovery; do not validate with availability impact.
5. Return `confirmed` only with safe local proof and meaningful shared effect. Return `needs_validation` with the exact upstream limit, topology, quota, or recovery observation an owner must check.

<!-- ATTACK-CLASSES.md#Cryptography and secrets -->
**Cryptography and secrets** (subagent_type: `general`)
- Weak randomness for security-critical values (tokens, keys, nonces)
- Hardcoded secrets, secrets in logs, error messages, URLs, or client-visible responses
- Broken key derivation, missing HMAC verification, nonce reuse
- Timing side-channels on secret comparison
- Misuse of crypto primitives (ECB mode, unauthenticated encryption, static IVs, etc.)
- What happens when crypto operations fail? Does the error path fall back to no-crypto?

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

- Agent ID `v-approvals`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-approvals/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-approvals <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-approvals /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
