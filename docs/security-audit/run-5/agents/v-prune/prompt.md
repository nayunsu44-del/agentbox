You are candidate verifier `v-prune` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad/src-audited/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt",
 "title": "Interrupted prune deletes the only archive of audit rows it has already committed as pruned",
 "description": "retention.prune writes the archive, then deletes the audit and approval rows and records an anchor holding the archive's sha256 in one transaction. Its outer error handler unlinks the archive on any BaseException without checking whether that transaction committed. A Ctrl-C (SIGINT) that arrives while the fsync-bound COMMIT runs is raised by CPython right after COMMIT returns, still inside the inner try. The handler's ROLLBACK then fails with 'no transaction is active', and the outer handler deletes the archive. Result: the DB says rows 1..N were pruned into an archive with a recorded sha256, that archive no longer exists, verify() reports the chain intact ('pruned through #N'), and verify_archives can never pass again. The pruned audit history and its tamper evidence are gone for good, which breaks the stated invariant that a failed prune leaves the database and archive consistent.",
 "root_cause": "The cleanup in retention.py:130-131 (`except BaseException: archive.unlink(missing_ok=True)`) is keyed on 'an exception happened' rather than 'the prune transaction did not commit'. The inner handler (retention.py:127-129) runs ROLLBACK unconditionally even when conn.in_transaction is already False after a successful COMMIT (retention.py:126). Any exception that surfaces after COMMIT completes, such as KeyboardInterrupt delivered during COMMIT, therefore destroys the archive that the committed anchor (retention.py:118-121) refers to.",
 "intended_behavior": "The archive is removed only if the prune transaction did not commit. Once the anchor row referencing the archive's sha256 is durable, the archive must be kept whatever exception follows, and the failure must be reported as 'pruned; archive kept at <path>'.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/cli.py",
   "line": 322,
   "scope": "cmd_prune",
   "description": "Host operator runs `agentbox prune --before ... --archive ...`, which calls retention.prune on Settings().db_path."
  },
  {
   "kind": "propagation",
   "file": "agentbox/retention.py",
   "line": 104,
   "scope": "prune",
   "description": "The archive is written, fsynced, and its sha256 computed before the transaction."
  },
  {
   "kind": "propagation",
   "file": "agentbox/retention.py",
   "line": 118,
   "scope": "prune",
   "description": "Inside BEGIN IMMEDIATE, audit rows are deleted and an audit_anchor row with the archive name and sha256 is inserted."
  },
  {
   "kind": "propagation",
   "file": "agentbox/retention.py",
   "line": 126,
   "scope": "prune",
   "description": "COMMIT makes the deletion and anchor durable. A SIGINT pending during this call is raised as KeyboardInterrupt immediately after it returns, still inside the inner try."
  },
  {
   "kind": "propagation",
   "file": "agentbox/retention.py",
   "line": 128,
   "scope": "prune inner except",
   "description": "Unconditional ROLLBACK raises OperationalError('cannot rollback - no transaction is active'), which chains on the KeyboardInterrupt."
  },
  {
   "kind": "sink",
   "file": "agentbox/retention.py",
   "line": 131,
   "scope": "prune outer except",
   "description": "archive.unlink deletes the only copy of the rows the committed anchor says were archived."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/retention.py",
   "line": 131,
   "description": "The archive is unlinked on any BaseException with no check of commit state."
  },
  {
   "file": "agentbox/retention.py",
   "line": 128,
   "description": "ROLLBACK is issued without checking conn.in_transaction, so it raises after a successful COMMIT."
  },
  {
   "file": "agentbox/audit.py",
   "line": 341,
   "description": "verify() starts at the latest anchor, so it keeps passing after the archive is lost and hides the loss."
  },
  {
   "file": "agentbox/audit.py",
   "line": 362,
   "description": "verify_archives needs the archive whose sha256 the anchor holds. With it deleted, full-history verification is impossible from then on."
  },
  {
   "file": "agentbox/cli.py",
   "line": 323,
   "description": "cmd_prune catches only ValueError/FileExistsError/RuntimeError. The OperationalError surfaces as a traceback, and a re-run reports nothing to prune."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Host operator running the prune CLI with direct DB file access. No remote or agent principal is involved."
  },
  {
   "kind": "timing_dependency",
   "description": "SIGINT (Ctrl-C or a supervisor such as `timeout -s INT`) arrives while COMMIT executes, or in the few bytecodes after it inside the inner try. COMMIT of a large prune is fsync-bound (about 0.27 s for 20k 1 KB rows in the sandbox, longer on large production DBs)."
  },
  {
   "kind": "data_state",
   "description": "At least one audit row is older than the cutoff, so prune reaches the transaction."
  }
 ],
 "execution": {
  "attacker_perspective": "Operator mistake the code claims to handle (interrupted prune). No adversary is needed. The effect is loss of audit-log integrity evidence for the pruned range.",
  "payloads": [
   "h.py check1: AuditLog fixture with 5 rows before the cutoff and 2 after; retention.sqlite3 shimmed to a Connection subclass whose execute('COMMIT') calls the real COMMIT and then signal.raise_signal(SIGINT); prune(db, cut, 'c1.jsonl.gz')",
   "h2.py: WAL DB, synchronous=FULL, BEGIN IMMEDIATE + 20000 randomblob(1000) inserts; threading.Timer(dur/3) sends os.kill(getpid(), SIGINT) during a real COMMIT inside the same nested try/except layout as retention.prune"
  ],
  "instructions": [
   "Run tools/sbx h-retention /usr/bin/python3.13 /scratch/h.py (no network, read-only /target, uid 65534, 512 MiB, 120 s) and read check1 output.",
   "Run tools/sbx h-retention /usr/bin/python3.13 /scratch/h2.py to show that a real asynchronous SIGINT during a real COMMIT surfaces in the inner except after the commit is durable."
  ],
  "observed_result": "check1: prune raised OperationalError, context KeyboardInterrupt. Archive exists after failure: False. Audit table now holds rows 6-8 with anchor (seq 1, last_id 5, 'c1.jsonl.gz', sha 3628529612...). verify(): ok=True, pruned_through=5. verify_archives([archive]) raised FileNotFoundError; verify_archives([]) returned ok=False ('anchor count 1, archives 0'). h2: 5/5 attempts gave inner-except KeyboardInterrupt, then ROLLBACK raised 'cannot rollback - no transaction is active', then the outer except ran, with 20000 rows committed."
 },
 "remediation": {
  "strategy": "Make archive cleanup depend on the DB's commit state, not on whether an exception was raised. Roll back only while a transaction is active. Before unlinking, check whether the anchor for this archive's sha256 exists, and keep the archive if it does. Also fsync the parent directory after creating the archive so the anchor never outlives its archive's directory entry after a crash. Regression test: a Connection factory that raises KeyboardInterrupt after a successful COMMIT must leave the archive in place, and verify_archives([archive]) must pass.",
  "code_changes": [
   {
    "file_name": "agentbox/retention.py",
    "fixed_code": "        try:\n            conn.execute(\"BEGIN IMMEDIATE\")\n            try:\n                ...  # unchanged body\n                conn.execute(\"COMMIT\")\n            except BaseException:\n                if conn.in_transaction:\n                    conn.execute(\"ROLLBACK\")\n                raise\n        except BaseException:\n            committed = False\n            try:\n                committed = conn.execute(\"SELECT 1 FROM audit_anchor WHERE archive_sha256 = ? AND archive = ?\",\n                                         (sha, archive.name)).fetchone() is not None\n            except sqlite3.Error:\n                committed = True   # unknown: never destroy a possibly referenced archive\n            if not committed:\n                archive.unlink(missing_ok=True)\n            raise"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Requires the operator (or a supervisor) to send SIGINT during the COMMIT of a host-only CLI command. The window is short but real for large prunes, which are the intended use (disk pressure), and Ctrl-C on a slow-looking command is a common operator action."
  },
  "impact": {
   "score": "medium",
   "reason": "The only remaining copy of the pruned audit rows (and finished approvals) is permanently destroyed, while the in-DB anchor and verify() report the history as cleanly archived. Tamper evidence for the whole pruned range becomes unverifiable from then on. No confidentiality impact and no remote attacker."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Source path is direct. The end-to-end prune harness reproduced archive deletion after commit, and a real asynchronous SIGINT during a real COMMIT surfaced in the inner except in 5 of 5 runs on CPython 3.13."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "agentbox%2Fcli.py%23agentbox%20prune%20--before%20--archive%20%5B--dry-run%5D%20%2B%20agentbox%20verify%20--archive%20%28host%20CLI%2C%20direct%20SQLite%29%20and%20every%20later%20AuditLog.verify%28%29%2Fappend%20over%20a%20pruned%20database::Audit-log%20tamper%20evidence%20across%20pruning%3A%20retention.prune%20drops%20and%20recreates%20the%20audit_no_delete%20trigger%20inside%20BEGIN%20IMMEDIATE%2C%20records%20an%20audit_anchor%20%28last%20id%2Fhash%2C%20archive%20sha256%29%20and%20an%20audit_pruned%20row%3B%20verify%28%29%20starts%20at%20the%20latest%20anchor%20and%20verify_archives%28%29%20chains%20GENESIS%20-%3E%20archives%20-%3E%20live%20table.%20Invariant%3A%20a%20deletion%20or%20edit%20of%20audit%20history%20that%20the%20prune%20command%20did%20not%20perform%20is%20still%20detected%2C%20prune%20never%20removes%20pending%2Fapproved%20approvals%20or%20rows%20at%2Fafter%20the%20cutoff%2C%20and%20a%20failed%20prune%20leaves%20the%20database%20and%20archive%20consistent.::agentbox%2Fretention.py%20%2B%20agentbox%2Faudit.py%23SCHEMA%2Faudit_anchor%2Flatest_anchor%2Fcheck_chain%2Fread_archive%2Finsert_record%2Fappend%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fcli.py%23cmd_prune%2Fcmd_verify::ATTACK-CLASSES.md%23Cryptography%20and%20secrets",
  "surface": "agentbox/cli.py#agentbox prune --before --archive [--dry-run] + agentbox verify --archive (host CLI, direct SQLite) and every later AuditLog.verify()/append over a pruned database",
  "boundary": "Audit-log tamper evidence across pruning: retention.prune drops and recreates the audit_no_delete trigger inside BEGIN IMMEDIATE, records an audit_anchor (last id/hash, archive sha256) and an audit_pruned row; verify() starts at the latest anchor and verify_archives() chains GENESIS -> archives -> live table. Invariant: a deletion or edit of audit history that the prune command did not perform is still detected, prune never removes pending/approved approvals or rows at/after the cutoff, and a failed prune leaves the database and archive consistent.",
  "local_checks": [
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/retention.py",
     "agentbox/cli.py"
    ],
    "invariant": "A prune that fails or is interrupted leaves the database and archive consistent: the archive is unlinked only when the DB transaction did not commit.",
    "method": "local",
    "result": "Failed. retention.prune (retention.py:126-131) unlinks the archive in the outer `except BaseException` without checking whether COMMIT went through. h.py check1 used a Connection subclass that raises SIGINT right after a successful COMMIT returns. Result: prune raised OperationalError('cannot rollback - no transaction is active') chained from KeyboardInterrupt. The archive was deleted. The DB had committed: audit rows 1-5 deleted, an audit_anchor row (last_id 5, archive c1.jsonl.gz, sha256 3628...) and audit_pruned row #8 present. verify() returned ok with pruned_through 5. verify_archives([archive]) raised FileNotFoundError and verify_archives([]) failed with an anchor/archive count mismatch. cmd_prune (cli.py:321-323) catches only ValueError/FileExistsError/RuntimeError, so the operator sees a traceback, and a re-run finds nothing to prune.",
    "artifact": "agents/h-retention/artifacts/h.out"
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/retention.py"
    ],
    "invariant": "Timing prerequisite: a real asynchronous SIGINT that arrives while a real sqlite3 COMMIT runs surfaces inside the try whose last statement is COMMIT, the layout of retention.py:105-132.",
    "method": "local",
    "result": "Confirmed in 5 of 5 attempts (Python 3.13.16, SQLite 3.45.1, WAL, synchronous=FULL, a 20k-row transaction whose COMMIT took about 0.27 s, timer SIGINT at dur/3). Each time KeyboardInterrupt was raised in the inner except after the commit was durable (20000 rows committed). ROLLBACK then raised 'cannot rollback - no transaction is active' and the outer except ran, which in prune is where the archive is unlinked.",
    "artifact": "agents/h-retention/artifacts/h2.out"
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/retention.py",
     "agentbox/audit.py",
     "agentbox/approvals.py",
     "agentbox/service.py",
     "tests/test_retention.py"
    ],
    "invariant": "Prune removes only audit rows before the first row at or after the cutoff and only approvals in denied/executed/failed/expired. Deletions it did not perform are still detected by verify()/verify_archives().",
    "method": "local",
    "result": "Holds. _plan (retention.py:54-64) selects id < MIN(id WHERE ts >= cutoff). Timestamps share the UTC millisecond isoformat used by _cutoff (retention.py:44-51), and the future cutoff is rejected. DELETE is bounded by the planned last id (retention.py:114). Approvals are planned by terminal status; claim moves only pending rows (approvals.py:82-89) and finish runs only after claim (service.py:406-483), so a terminal status cannot revert before the id-only delete. h.py check3: pending and approved rows were kept and 4 terminal rows were pruned. verify and verify_archives were ok after the prune. Deleting the first row after the anchor was detected (id gap at #7). tests/test_retention.py: 7 passed in the sandbox (pytest.out, not promoted). insert_record chains from the latest anchor only when the table is empty (audit.py:228-243), and verify() fails on an anchor with an empty table (audit.py:343-344).",
    "artifact": "agents/h-retention/artifacts/h.out"
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/retention.py",
     "agentbox/audit.py"
    ],
    "invariant": "Concurrent server writes and concurrent prunes cannot make prune delete unarchived rows or leave the append-only trigger missing.",
    "method": "source",
    "result": "Holds. The plan is read outside the lock, but the audit table is append-only, so planned rows cannot change. Inside BEGIN IMMEDIATE, prune re-checks MIN(id) against the planned first row and the latest anchor (retention.py:108-111). DROP TRIGGER / DELETE / CREATE TRIGGER from NO_DELETE_SQL (audit.py:56-59) all run in the same write transaction, so other connections (AuditLog.append BEGIN IMMEDIATE, audit.py:294) never see the trigger missing, and ROLLBACK restores it on error. An approvals-only prune reuses the latest anchor, or (0, GENESIS), inside the transaction (retention.py:117), so verify_archives' per-archive last-row check (audit.py:370) stays consistent. The remaining in-DB anchor forgeability is the documented README limit and is not reported.",
    "artifact": null
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/retention.py",
     "README.md"
    ],
    "invariant": "If the archive cannot be written, nothing is deleted (README.md:190) and the archive state stays clean.",
    "method": "local",
    "result": "The DB is unchanged, but a partial file is left behind. h.py check2 simulated ENOSPC on the third gzip write: prune raised OSError 28, the DB still held 7 rows and no anchor, a 297-byte partial archive remained, and a re-run with the same path failed with FileExistsError. _write_archive (retention.py:67-84) runs before the try that unlinks. No audit loss, so recorded as hardening.",
    "artifact": "agents/h-retention/artifacts/h.out"
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/audit.py"
    ],
    "invariant": "Archive serialization and verification match live verify. A sha-pinned archive cannot carry forged audit rows, and parsing it does not amplify beyond operator-supplied content.",
    "method": "source",
    "result": "Holds. _write_archive uses json.dumps (escapes control characters, so TextIOWrapper universal-newline splitting is safe) and read_archive rebuilds the same column tuples (audit.py:208-225). check_chain recomputes hashes from GENESIS across archives into the live table (audit.py:360-378), so content swapped after the sha check (TOCTOU between read_bytes at :362 and read_archive at :364) cannot change the audit rows without breaking the chain. Approval rows in the archive are protected only by that sha check and are not otherwise verified. The archive is operator-supplied and pinned to an anchor sha, and its size is bounded by the pruned DB rows.",
    "artifact": null
   },
   {
    "agent_id": "h-retention",
    "reviewed_paths": [
     "agentbox/audit.py",
     "agentbox/retention.py",
     "agentbox/service.py"
    ],
    "invariant": "Revalidate the run-4 needs_validation record agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention against current source.",
    "method": "source",
    "result": "The retention half no longer holds. A host-only prune now exists (retention.py:87, cli.py:319) and keeps the chain verifiable through the anchor and archive (audit.py:336-379, verified locally in check3), so capacity recovery is no longer exclusive with integrity. Pruning frees pages for reuse, and file shrink needs an offline VACUUM per README.md:194. The aggregate-bound half (disk_low guard service.py:388-404, compaction service.py:406-411) belongs to the peer unit owned by h-approvals and was not re-hunted here. No candidate with that fingerprint.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-4 wording)

```json
- none
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

<!-- ATTACK-CLASSES.md#Cryptography and secrets -->
**Cryptography and secrets** (subagent_type: `general`)
- Weak randomness for security-critical values (tokens, keys, nonces)
- Hardcoded secrets, secrets in logs, error messages, URLs, or client-visible responses
- Broken key derivation, missing HMAC verification, nonce reuse
- Timing side-channels on secret comparison
- Misuse of crypto primitives (ECB mode, unauthenticated encryption, static IVs, etc.)
- What happens when crypto operations fail? Does the error path fall back to no-crypto?

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A tenant or owner field on a record is not isolation. Find the query, key, path, policy, or row-level control that enforces it for each read and write path.
- Trace derived copies. Sanitized primary data can become unsafe in search, cache, analytics, export, previews, logs, replicas, and backups with different ACL and retention rules.
- Deletion and revocation are lifecycle contracts. Check current, historical, cached, indexed, exported, restored, and queued copies within the product's stated boundary.
- Privacy or retention preference is not automatically a security vulnerability. Require an explicit data-access boundary or deletion/revocation guarantee and an unauthorized reader or later operation.
- Use `confirmed` for complete source-visible lineage and bounded dummy-tenant tests. Use `needs_validation` when external storage policy, retention, CDN behavior, replica lag, or backup access is unavailable.
```

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion -->
**Export and backup scope expansion**
An export, snapshot, portability package, report, or backup includes other tenants, inaccessible object fields, soft-deleted data, secret values, or history above the requester's access. Check per-item authorization after selection and authorization to download the final artifact.

<!-- DATA-ISOLATION-AND-LIFECYCLE.md#Soft-delete and tombstone bypass -->
**Soft-delete and tombstone bypass**
Direct lookup, search, relation traversal, object link, background processor, or restore ignores the lifecycle predicate and returns or acts on a deleted/revoked record. Check whether soft-deleted identifiers can be re-registered before all references are gone.

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

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU -->
**Local file ownership and TOCTOU**
The app checks a file/path then follows replacement, symlink, mount, or case/normalization changes during a privileged read/write. Use descriptor-relative operations and verify final ownership. Focus `MEMORY-SAFETY-AND-BINARY.md` on parsing after the file is opened.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Decompression and representation amplification -->
**Decompression and representation amplification**
Compressed, sparse, nested, aliased, or encoded input expands far beyond the checked transfer or file size. Verify limits after every expansion and across parser stages, including archives, images, fonts, structured documents, and protocol compression tables.

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

- Agent ID `v-prune`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-5/agents/v-prune/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-prune <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3.13` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `/home/user/agentbox/docs/security-audit/run-5/tools/sbx v-prune /usr/bin/sh -c "cd /target && /usr/bin/python3.13 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
