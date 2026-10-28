You are candidate verifier `v-disk-low` in run-7 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `/projects/sandbox/.scratch/src-audited/` — a git worktree of `main` at commit `3580df0` (after PR #26: 7dbda9e run-6 fixes, 5bb3c17 refactor, IF-1). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/service.py:disk_low-unmonitored-docker-data-root",
 "title": "disk_low fails open when the Docker data root is not reachable in the control-plane container",
 "description": "The run-6 N3 fix added Docker-data-root monitoring to AgentBox.disk_low by taking min(free(db_path.parent), free(docker_root)), where docker_root is the host daemon's DockerRootDir. In the documented compose deployment the control-plane container does not mount the daemon's data root, so shutil.disk_usage(docker_root) raises OSError, which is silently ignored. disk_low then measures only the SQLite db partition. If that partition differs from the host filesystem holding container writable layers and snapshot images, a prompt-injected agent can grow Docker storage without disk_low ever returning True, so the 507 back-pressure never engages.",
 "claimed_root_cause": "disk_low (service.py:461-485) treats an unreachable docker_root as no additional constraint (except OSError: pass) instead of failing closed or warning, and docker_root is taken from the daemon's DockerRootDir (sandbox.py:179-183), a path the compose control-plane container does not mount.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/sandbox.py",
   "line": 181,
   "scope": "SandboxManager._detect_runtime",
   "description": "self.docker_root is set from info['DockerRootDir'], the host daemon's data root path, only meaningful on the daemon host."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 476,
   "scope": "AgentBox.disk_low",
   "description": "free = min(free, shutil.disk_usage(docker_root).free) is wrapped in try/except OSError: pass, so an unreachable docker_root silently drops the Docker-storage term."
  },
  {
   "kind": "sink",
   "file": "agentbox/service.py",
   "line": 480,
   "scope": "AgentBox.disk_low",
   "description": "low = free < s.min_free_bytes is computed from the db partition alone; call_tool's 507 guard never trips on Docker-storage exhaustion."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 476,
   "description": "OSError on shutil.disk_usage(docker_root) is caught and ignored rather than failing closed."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 181,
   "description": "docker_root is the daemon's DockerRootDir, a host path not guaranteed to exist inside the control-plane container."
  },
  {
   "file": "deploy/docker-compose.yml",
   "line": 31,
   "description": "The control-plane service mounts only /var/run/docker.sock and the AGENTBOX_HOME volume."
  }
 ],
 "blockers": [
  "Whether, in the compose deployment, the host daemon's DockerRootDir is unreachable inside the control-plane container (compose shows it is not mounted, but a custom data_root on the AGENTBOX_HOME volume would be reachable).",
  "Whether the host's Docker data-root filesystem is distinct from the AGENTBOX_HOME filesystem; if they are the same, the db measurement still reflects Docker storage.",
  "Whether a sandbox can grow the Docker data root without an effective size cap (AGENTBOX_DISK default empty) long enough to exhaust host storage."
 ],
 "validation_plan": {
  "local": "In the approved sandbox, construct an object exposing docker_root=Path('/nonexistent/docker/root') and a db path on scratch, set min_free_bytes so disk_low is True only when the docker term counts, and confirm the except-OSError branch returns False.",
  "deployment": "On a real compose deployment: run `docker compose exec agentbox python3 -c 'import shutil,docker; r=docker.from_env().info()[\"DockerRootDir\"]; print(r); print(shutil.disk_usage(r))'` and observe FileNotFoundError; compare df of AGENTBOX_HOME and the host data root; grow a sandbox writable layer and confirm no disk_low event."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Completeness%20of%20the%207dbda9e%20fixes%20for%20run-6%20F1-F3%20and%20N1-N3%3A%20GuiBursts.covers%20container_id%20check%20and%20restore_sandbox%20bursts.end%20%28gui_bursts.py%3A72-83%2C%20service.py%3A625-635%29%3B%20idx_audit_sandbox_id%20and%20batched%20_verify_live%20outside%20_lock%20%28audit.py%3A38%2C%20337-400%29%3B%20_expand%20~%2F%7B%20handling%20and%20head%20-z%20-n%20cap%20plus%20preview%20notes%20%28sandbox.py%3A600-626%2C%20preview.py%3A88-114%29%3B%20same_origin%20scheme%20check%20and%20HSTS%20%28api.py%3A221-235%2C%20web.py%3A177%2C187%2C%20cli.py%3A102%2C%20deploy%2FCaddyfile%3A8%29%3B%20_exec_head%2C%20outbox%20head%20-c%2C%20screenshot%20link%2Fsize%20checks%20%28sandbox.py%3A41%2C%20422-461%2C%20564-574%2C%20sandbox_desktop.py%3A37%2C%20113-123%29%3B%20DockerRootDir%20and%20disk_low%20%28sandbox.py%3A179-183%2C%20service.py%3A461-485%29::Each%20run-6%20fix%20must%20close%20its%20root%20cause%20for%20all%20variants%20without%20introducing%20a%20new%20defect%3A%20no%20GUI%20input%20runs%20under%20a%20burst%20whose%20baseline%20belongs%20to%20another%20container%3B%20verify%28%29%20cannot%20hold%20AuditLog._lock%20for%20long%2C%20load%20the%20table%2C%20loop%20forever%2C%20or%20report%20a%20broken%20chain%20as%20intact%3B%20the%20rm%20preview%20does%20not%20show%20a%20real%20target%20as%20absent%20without%20a%20warning%3B%20a%20cross-scheme%20Origin%20is%20refused%20whenever%20cookies%20are%20secure%20%28including%20behind%20the%20TLS%20proxy%20and%20when%20secure_cookie%20is%20off%20by%20configuration%29%3B%20no%20container%20reader%20buffers%20unbounded%20output%20or%20follows%20an%20attacker%20link%3B%20disk_low%20sees%20the%20filesystem%20that%20holds%20container%20layers%20and%20snapshot%20images%20or%20fails%20closed%20when%20it%20cannot.::agentbox%2Fgui_bursts.py%23covers%2Fend%20%2B%20agentbox%2Fservice.py%23restore_sandbox%2Fdisk_low%20%2B%20agentbox%2Faudit.py%23_verify_live%2Fverify%2Fverify_archives%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_exec_head%2Flist_dir%2Foutbox_list%2F_detect_runtime%20%2B%20agentbox%2Fpreview.py%23preview_command%20%2B%20agentbox%2Fsandbox_desktop.py%23screenshot%20%2B%20agentbox%2Fapi.py%23same_origin%2Fsecure_cookie%20%2B%20deploy%2FCaddyfile::ATTACK-CLASSES.md%23Business%20logic",
  "surface": "Completeness of the 7dbda9e fixes for run-6 F1-F3 and N1-N3: GuiBursts.covers container_id check and restore_sandbox bursts.end (gui_bursts.py:72-83, service.py:625-635); idx_audit_sandbox_id and batched _verify_live outside _lock (audit.py:38, 337-400); _expand ~/{ handling and head -z -n cap plus preview notes (sandbox.py:600-626, preview.py:88-114); same_origin scheme check and HSTS (api.py:221-235, web.py:177,187, cli.py:102, deploy/Caddyfile:8); _exec_head, outbox head -c, screenshot link/size checks (sandbox.py:41, 422-461, 564-574, sandbox_desktop.py:37, 113-123); DockerRootDir and disk_low (sandbox.py:179-183, service.py:461-485)",
  "boundary": "Each run-6 fix must close its root cause for all variants without introducing a new defect: no GUI input runs under a burst whose baseline belongs to another container; verify() cannot hold AuditLog._lock for long, load the table, loop forever, or report a broken chain as intact; the rm preview does not show a real target as absent without a warning; a cross-scheme Origin is refused whenever cookies are secure (including behind the TLS proxy and when secure_cookie is off by configuration); no container reader buffers unbounded output or follows an attacker link; disk_low sees the filesystem that holds container layers and snapshot images or fails closed when it cannot.",
  "local_checks": [
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/gui_bursts.py",
     "agentbox/service.py"
    ],
    "invariant": "F1: no GUI input runs under a burst whose baseline belongs to another container; bursts.end after restore must not kill/record against the new container",
    "method": "source",
    "result": "covers() (gui_bursts.py:77-83) returns burst.get('container_id')==sandboxes.get(sid)['container_id'] under gui_lock, and open() binds the burst to the container id read at snapshot time; _run_tool refuses GUI input when covers() is False (service.py:155). restore_sandbox calls bursts.end(sid,'sandbox_restored') after sandboxes.restore (service.py:630); end->close->_finish computes replaced = current container_id != burst container_id and, when replaced, returns close_failed without _stop_strays, so no process on the new container is killed; _kept is keyed by container id. Every close path funnels through _finish's replaced guard. F1 root cause closed.",
    "artifact": null
   },
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/audit.py"
    ],
    "invariant": "F2: verify() must not hold _lock across the whole table, load it all into memory, loop forever, or report a broken chain as intact; the new index must not change recent() ordering",
    "method": "source",
    "result": "_verify_live (audit.py:339-369) pages WHERE id>? ORDER BY id LIMIT 200, taking _lock only to re-check latest_anchor and fetch one batch; check_chain runs outside the lock. A prune between batches changes latest_anchor -> returns None -> verify() retries from the new anchor; appended rows get higher ids and are verified in later batches; check_chain validates prev_hash linkage. The anchor-exists-but-no-rows case returns a broken result. verify_archives does the same tail check and fails if the anchor moved. idx_audit_sandbox_id(sandbox_id,id) only backs recent()'s WHERE + ORDER BY id DESC LIMIT. F2 root cause closed.",
    "artifact": null
   },
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "F3: the rm impact preview must not show a real target as absent without a warning under brace/tilde expansion",
    "method": "source",
    "result": "preview_command appends a command-level note when the command contains $, backtick, <(, 'eval ', '{' or '~' (preview.py:88-89), and for an rm operand with no _expand match the effect is '삭제 시도 (중괄호·틸드 확장 — 명령 원문 확인)' whenever ('{' in op and '}' in op) or op.startswith('~') (preview.py:109-114). Even where dash fails to resolve a '~'-leading operand (parent-live: _expand('~/tilde_target.txt') -> [] for an existing file), op.startswith('~') routes it to the warning effect, so a real target is never reported absent without a warning. F3 root cause closed (the tilde expansion itself is ineffective; recorded as hardening by the parent).",
    "artifact": null
   },
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/api.py",
     "deploy/Caddyfile"
    ],
    "invariant": "N1: a cross-scheme Origin must be refused whenever cookies are secure (incl. behind the TLS proxy); HSTS set",
    "method": "source",
    "result": "same_origin (api.py:225-235) returns False when secure_cookie(req_or_headers) is true and the Origin scheme is not https; secure_cookie (api.py:221-223) is settings.secure_cookie or url.scheme in ('https','wss'). The compose deployment sets AGENTBOX_BEHIND_TLS_PROXY=1, which makes settings.secure_cookie true, so behind Caddy the scheme is enforced; an http attacker origin is refused. deploy/Caddyfile:8 adds Strict-Transport-Security. On plain loopback with secure_cookie unset, cookies are not Secure-flagged, so there is no https credential to attack cross-scheme. Closed.",
    "artifact": null
   },
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/sandbox_desktop.py"
    ],
    "invariant": "N2: no container reader buffers unbounded output or follows an attacker link (exec/list_dir/outbox/screenshot)",
    "method": "source",
    "result": "exec and list_dir use _exec_head (sandbox.py:422-451), streaming into _Head buffers capped at _OUT_LIMIT+1; list_dir maps 124/137 to a timeout error. outbox_list pipes find -printf into head -c 512KiB under _timed, and _parse_outbox skips malformed/partial records. screenshot runs '[ -f ] && [ ! -L ] && head -c 16MiB+1' and the control plane rejects output over _SHOT_MAX or without PNG magic. Closed (see hardening).",
    "artifact": null
   },
   {
    "agent_id": "h-fixes",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/sandbox.py",
     "deploy/docker-compose.yml"
    ],
    "invariant": "N3: disk_low must see the filesystem that holds container layers/snapshot images, or fail closed when it cannot",
    "method": "source",
    "result": "disk_low (service.py:461-485) takes min(free(db_path.parent), free(docker_root)) but swallows OSError on docker_root (fail-open). docker_root is the host daemon's DockerRootDir (sandbox.py:180-183). In the compose deployment the control-plane container mounts only /var/run/docker.sock and AGENTBOX_HOME; the daemon's data root is not mounted, so shutil.disk_usage(docker_root) raises and is ignored, leaving disk_low measuring only the db partition. The N3 fix is incomplete for that topology; carried as needs_validation with the prior fingerprint.",
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
 "fingerprint": "agentbox/service.py:disk_low-unmonitored-docker-data-root",
 "title": "disk_low measures SQLite db_path.parent rather than Docker daemon storage root allowing complete host disk exhaustion",
 "description": "AgentBox.disk_low checks free disk space strictly via shutil.disk_usage(self.settings.db_path.parent). In deployments where the agentbox database volume (AGENTBOX_HOME) and Docker's data root (/var/lib/docker) reside on separate filesystems, container layer growth and docker commit snapshot images (up to 50 per sandbox) consume Docker storage without decreasing free space on db_path.parent. The 507 guard never trips, allowing agents to exhaust host Docker disk, cause daemon failures, and prevent administrative log_human operations which fail closed with 503.",
 "claimed_root_cause": "The disk guard in AgentBox.disk_low (service.py:421-437) assumes all disk growth occurs on the filesystem containing db_path.parent. However, Docker container writable layers and commit images (sandbox.py:356-370) grow inside Docker's data root (e.g. /var/lib/docker). In deploy/docker-compose.yml, AGENTBOX_HOME (/var/lib/agentbox) is a separate bind mount. When db_path.parent and Docker data root are on distinct partitions, or when an admitted exec runs dd/fallocate for up to exec_timeout (since AGENTBOX_DISK is empty by default so containers have no storage_opt size quota), host Docker storage can be completely filled without triggering disk_low.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 296,
   "scope": "AgentBox.call_tool",
   "description": "Agent calls an admitted tool (e.g. exec writing large files to /workspace, or write_file triggering snapshot)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 428,
   "scope": "AgentBox.disk_low",
   "description": "disk_low evaluates shutil.disk_usage(s.db_path.parent).free against s.min_free_bytes; because Docker storage is on a separate filesystem, db_path.parent free space remains high and disk_low returns False."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 361,
   "scope": "SandboxManager.snapshot",
   "description": "c.commit commits container writable layer into a new Docker image in Docker data root, accumulating up to snapshot_quota (50) images per sandbox."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 269,
   "scope": "SandboxManager._run_container",
   "description": "Container has no storage_opt disk quota (disk_limit is empty by default), allowing unrestricted accumulation of data in Docker's storage root until the host filesystem is exhausted."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 428,
   "description": "disk_low measures shutil.disk_usage(s.db_path.parent).free exclusively."
  },
  {
   "file": "agentbox/config.py",
   "line": 42,
   "description": "disk_limit defaults to empty string, disabling container storage_opt size limits."
  },
  {
   "file": "agentbox/config.py",
   "line": 46,
   "description": "snapshot_quota defaults to 50 snapshots per sandbox without aggregate disk quota."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 361,
   "description": "snapshot calls c.commit(), creating full container layer image copies in Docker root."
  },
  {
   "file": "deploy/docker-compose.yml",
   "line": 31,
   "description": "AGENTBOX_HOME is mounted to /var/lib/agentbox separately from Docker host root."
  },
  {
   "file": "agents/v-disk-low/artifacts/v.out",
   "line": 1,
   "description": "Sandboxed verification reproducing that AgentBox.disk_low strictly measures shutil.disk_usage(s.db_path.parent), and returns False when Docker data-root is simulated as exhausted while db_path.parent has available space."
  },
  {
   "file": "agents/parent-live/artifacts/disk_low_live.out",
   "line": 1,
   "description": "Live disposable sandbox verification confirming DockerRootDir=/var/lib/docker with settings.disk_limit='' while disk_low samples only settings.home and settings.db_path.parent."
  }
 ],
 "blockers": [
  "Simulating separate filesystem mounts for AGENTBOX_HOME and Docker root (/var/lib/docker) along with live docker commit image accumulation requires access to a host Docker daemon and multiple mount points, which is unavailable in the isolated sandbox.",
  "Exhausting host Docker disk on live test infrastructure is destructive and forbidden under audit execution boundaries; confirming complete host exhaustion requires an operator-owned multi-volume test deployment."
 ],
 "validation_plan": {
  "local": "On a dedicated non-production host running Docker with AGENTBOX_HOME on a loopback mount or separate partition from /var/lib/docker: (1) configure min_free_bytes=256MB, (2) run an agent script that creates files in /workspace and triggers snapshots up to snapshot_quota, (3) verify that disk_low continues returning False while Docker data root disk usage increases until /var/lib/docker is exhausted.",
  "deployment": "Check host partition layout in production deployments to verify whether /var/lib/docker and AGENTBOX_HOME are on separate volumes, and monitor Docker daemon root volume free space independently of the application database volume."
 }
}
```

# Parent-live evidence

- `agents/parent-live/artifacts/disk_low_compose_live.out` (at `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/parent-live/artifacts/disk_low_compose_live.out`)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-7)
Source ref: `3580df0` (`main`, after PR #26 merge). Profile `standard`, focused follow-up on the delta `530b29e..3580df0`, owner budget 15 subagent invocations. No reconnaissance agent was spent: the parent read the full diff of the six non-merge commits (`7dbda9e`, `5bb3c17`, `d4e956e`, `79d8211`, `ccaf367`, `a0a186c`). **Line numbers in section 0 are exact at `3580df0`. Section 1 is the run-6 delta (`530b29e` numbers). Sections 2-6 are the run-4/run-6 baseline and only describe code the delta did not change.**
## 0. Run-7 delta `530b29e..3580df0` (exact line numbers at `3580df0`)
### 0.1 `7dbda9e` — fixes for run-6 F1-F3 and hardening N1-N3 (not audited before this run)
- **F1 GUI burst container binding (`gui_bursts.py`, `service.py`).** `GuiBursts.covers(sid)` (`gui_bursts.py:72-83`) returns `True` when `gui_snapshot_interval <= 0`; otherwise `False` if no burst, else `burst.get("container_id") == self.sandboxes.get(sid)["container_id"]` (any exception → `False`). `restore_sandbox` (`service.py:625-635`) now calls `self.bursts.end(sid, "sandbox_restored")` after `self.sandboxes.restore` (`service.py:630`; `end` = `close` + `reset_timers`, `gui_bursts.py:186-195`). `restore_sandbox` holds `_lifecycle(sid)`; `call_tool`/`_snapshot` do not.
- **F2 audit index and batched verify (`audit.py`).** `CREATE INDEX IF NOT EXISTS idx_audit_sandbox_id ON audit (sandbox_id, id)` (`audit.py:38`). `_VERIFY_BATCH = 200` (`audit.py:337`). `_verify_live(anchor, prev, expected, total)` (`audit.py:339-369`) loops: under `self._lock` re-reads `latest_anchor` (returns `None` if it changed) and fetches the next 200 rows `WHERE id > cursor`, then runs `check_chain` outside the lock. `verify()` (`audit.py:371-379`) retries forever while `_verify_live` returns `None`. `verify_archives()` (`audit.py:381-`) checks archives, then calls `_verify_live` once and fails if the anchor changed.
- **F3 preview braces/tilde (`preview.py`, `sandbox.py`).** `preview_command` adds a note when the command contains `$`, `` ` ``, `<(`, `eval `, `{` or `~` (`preview.py:88-89`); an unmatched `rm` operand with `{…}` or a leading `~` shows `삭제 시도 (중괄호·틸드 확장 — 명령 원문 확인)` (`preview.py:111-114`). `_expand(c, pattern, limit)` (`sandbox.py:600-610`) runs dash `sh -c` with `case "$1" in "~") pat="$HOME";; "~/"*) pat="$HOME/${1#~/}";; *) pat="$1";; esac; for p in $pat; …| head -z -n "$2"` and `limit+1`. Execution still uses `bash -c` (`sandbox.py:437-451`).
- **N1 origin scheme and HSTS (`api.py`, `web.py`, `deploy/Caddyfile`).** `secure_cookie(request)` (`api.py:221-223`) = `settings.secure_cookie or request.url.scheme in ("https","wss")`. `same_origin(req_or_headers)` (`api.py:225-235`): empty/missing `Origin` → `True`; `netloc != Host` → `False`; if `secure_cookie(...)` and `Origin` scheme is not `https` → `False`. Callers pass the request/WebSocket (`api.py:244`, `api.py:454`, `web.py:177`, `web.py:187`). `cli.py:102` sets `secure_cookie` when `--tls-*` or `--behind-tls-proxy`. `deploy/Caddyfile:8` adds `Strict-Transport-Security "max-age=31536000"`.
- **N2 container output caps (`sandbox.py`, `sandbox_desktop.py`).** New `_exec_head(c, argv, user, workdir)` (`sandbox.py:422-435`) streams with `exec_create`/`exec_start(stream=True, demux=True)` into two `_Head` buffers, falling back to `c.exec_run` + `_truncate` when `client.api` is absent. `exec` (`sandbox.py:437-451`) and `list_dir` (`sandbox.py:453-461`, now `_timed(_READ_TIMEOUT, "ls","-la","--",p)`) use it. `outbox_list` (`sandbox.py:564-574`) pipes `find … -printf '%s\t%T@\t%f\0' | head -c _OUTBOX_CAP` (512 KiB, `sandbox.py:41`) under `_timed(_READ_TIMEOUT)`; `_parse_outbox` (`sandbox.py:110-133`) skips malformed records. `screenshot` (`sandbox_desktop.py:113-123`) runs `mkdir -p dirname && rm -f SHOT && scrot -o -z SHOT && [ -f SHOT ] && [ ! -L SHOT ] && head -c 16MiB+1 SHOT` as the `desktop` user and rejects output over `_SHOT_MAX` (`sandbox_desktop.py:37`).
- **N3 Docker data root (`sandbox.py`, `service.py`).** `_detect_runtime` stores `self.docker_root = Path(info["DockerRootDir"])` (`sandbox.py:179-183`). `disk_low()` (`service.py:461-485`) takes `min(free(db_path.parent), free(docker_root))`; `OSError` on `docker_root` is ignored (the path is the daemon's path and may not exist, or may be a different filesystem, inside the control-plane container).
### 0.2 `5bb3c17` — refactor ("no behaviour change" claim to verify)
- `GuiBursts.human_active(sid)` (`gui_bursts.py:55-57`) = `(desktop.lease(sid) and not desktop.is_stale(sid)) or self._takeover_pending(sid)`; `_takeover_pending` is `AgentBox._takeover_pending` passed into the constructor (`service.py:99`, `gui_bursts.py:24-30`). Used by `needs_snapshot` (`gui_bursts.py:59-`) and `decide` (`service.py:545`), replacing two inline copies.
- `_request_approval(sid, tool, args, actor, req_id, decision)` (`service.py:413-449`) is the former inline `REQUIRE_APPROVAL` branch of `_call_tool`: pending cap (20) → `_preview` (exceptions become a note) → `bound_payload(preview)` → agent `disk_low()` recheck (507) → `_capture` → `approvals.create` → capture file write → `approval_requested` audit (on `AuditWriteError`: claim FAILED, drop capture, 503).
- Test doubles moved to `tests/conftest.py`; `tests/test_m2_unit.py` and `tests/test_m5_unit.py` reuse them.
- Unchanged and relevant: `_check_control` (`service.py:173-182`, called with `gui_lock` held), `_gui_locked` (`service.py:190-198`), `_snapshot` (`service.py:300-326`), `call_tool` (`service.py:329-352`, `_snap_locks` for `SNAPSHOT_TOOLS`), `_call_tool` (`service.py:354-411`), `decide` (`service.py:520-575`).
### 0.3 `d4e956e`, `79d8211`, `ccaf367`, `a0a186c` — IF-1 agent instruction files
- **New module `agentbox/instruction_files.py` (imports nothing from agentbox).**
  - `_NAMES` (`:27-40`, lower-case file names: `claude.md`, `claude.local.md`, `agents.md`, `agents.override.md`, `agent.md`, `gemini.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.goosehints`, `copilot-instructions.md`, `.mcp.json`), `_DIRS` (`:43-52`: `.claude`, `.cursor`, `.windsurf`, `.clinerules`, `.continue`, `.gemini`, `.codex`, `.roo`), `_GITHUB_DIRS` (`:55`: `instructions`, `prompts`, `chatmodes` under `.github`).
  - `_norm(name)` (`:66-76`): `unicodedata.normalize("NFKC", name).casefold()`, then `split(":", 1)[0]`, then `rstrip(". ")`.
  - `_parts(path)` (`:79-92`): `posixpath.normpath(raw.strip())`, `PurePosixPath(...).parts` minus `/`, each part split on `\`, each piece `_norm`ed; empty, `.` and `..` pieces dropped (backslash `..` is never resolved).
  - `kind(path)` (`:95-108`): last part in `_NAMES`, or any earlier part in `_DIRS`, or `.github/<_GITHUB_DIRS>/…` with at least one more part. The last part alone is never matched against `_DIRS` (so `kind("/workspace/.claude")` is `None`; `scan` calls `kind(rel + "/_")` for directories).
  - `mark_read(result)` (`:115-121`) sets `instruction_file`/`notice` from `kind(result["path"])` (the requested, `safe_path`-normalised path; no link resolution).
  - `with_notice(res, text)` (`:124-137`): if `res["notice"]`, wraps `text` in `[<notice> … 'agentbox-data <tag>' …]\n<<<agentbox-data <tag> 시작>>>\n<text>\n<<<agentbox-data <tag> 끝>>>` with `tag = secrets.token_hex(8)` redrawn while `tag in text`.
  - `paths_in_words(words)` (`:140-147`): words whose `strip("'\"")` value has a `kind`.
  - `scan(root)` (`:150-193`): DFS with `os.scandir`, `SCAN_MAX_ENTRIES=200_000`, `SCAN_MAX_HITS=200`, `SCAN_MAX_SECONDS=10.0` checked per entry inside the `scandir` iteration; unreadable dir or `is_dir` error → `complete=False`; does not follow links; instruction directories recorded once as `rel/`.
- **Service (`service.py`).**
  - `_run_tool` (`service.py:133-147`): `exec` result gets `instruction_files` + `notice` when `IF.paths_in_words(command_words(command))` hits (no boundary wrapping); `read_file` result goes through `IF.mark_read`.
  - `_summary` (`service.py:218-233`) keeps `instruction_files` / `instruction_file` flags in `tool_result`.
  - `_resolved(sid, tool, args)` (`service.py:235-247`): only for `write_file`/`delete_file`; calls `SandboxManager.resolve`; any exception → `None` ("judge by the requested path"). `_policy_args` (`service.py:249-251`) passes `{**args, "resolved_path": real}` to `policy.decide` only (`service.py:369`); stored approval args, audit args and execution use the original `args`.
  - `_preview` (`service.py:253-289`) for `write_file`/`delete_file` calls `_resolved` **a second time**, adds `{"path": real, "effect": "링크를 따라간 실제 대상"}` when `real != p`, and when `IF.kind(p) or IF.kind(real)` adds a note and `out["instruction_file"] = k` (approval card then renders the full content).
  - `create_sandbox` (`service.py:577-597`): after `sandboxes.create` and the `sandbox_created` record, runs `IF.scan(rec["source_dir"])` synchronously on the request thread (no `_lifecycle`), logs `instruction_files_found` (best effort) when there are hits or `complete` is `False`, returns `instruction_files` and `instruction_files_complete`.
  - `import_file` (`service.py:643-662`): if `IF.kind(name)`, logs `instruction_files_found` (`via: import`) and returns `instruction_file`.
  - `export_file` (`service.py:664-672`): `file_exported` record gets `instruction_file`.
  - New `AgentBox.outbox(sid)` (`service.py:674-681`): `sandboxes.outbox_list(sid)` plus `instruction_file` per name; used by `GET /sandboxes/{sid}/outbox` (`api.py:394-396`) and the UI fragment (`web.py:273-280`).
  - `FOUND_PATH_MAX = 512` and `_found_payload(via, paths, complete)` (`service.py:778-786`): `{"via", "count", "paths" (each cut to 512 chars + "…"), "complete"}`; the audit row still goes through `bound_payload`.
- **Sandbox (`sandbox.py`).** New `SandboxManager.resolve(sid, path)` (`sandbox.py:487-496`): `_require_running`, `safe_path`, `c.exec_run(_timed(_READ_TIMEOUT=30, "realpath", "-m", "--", p), user=agent)`; non-zero exit or output not starting with `/` raises `SandboxError`. `write_file` (`sandbox.py:502-515`) writes `{p}.agentbox-tmp-<hex>` in chunks then `mv -f -- tmp p`; `delete_file` (`sandbox.py:517-525`) `rm -f -- p` after `-d`/`-e` checks. `upload` uses `clean_name` (`sandbox.py:46-51`: no `/`, `\`, C0, DEL; ≤200 bytes).
- **Policy (`policy.py`, `default_policy.yaml`).** `PATH_TOOLS = {list_dir, read_file, write_file, delete_file}` (`policy.py:23`). In `Policy.decide` (`policy.py:214-254`, first matching rule wins) a rule with `match.instruction_files` matches only path tools whose `args["path"]` or `args["resolved_path"]` is a string with a `kind`; other match keys in the same rule are ignored. `command_words(command)` (`policy.py:82-84`) strips quotes and `\;&|()<>` from `_words`. Default policy is `version: 4` with rule order `rm-curl-needs-approval` → `instruction-file-write-needs-approval` (`tool: write_file`) → `delete-file-needs-approval` → `read-only-exec` (allowlist includes `mkdir`, `touch`, `realpath`, `readlink`) → `exec-needs-approval`; `default: allow`. Policy files do not check `version`.
- **Readers of results.** `agent.py:118-126` `ToolClient.call_text` and `mcp_server.py:119-125` `read_file` both return `with_notice(res, content + ("\n…(잘림)" if truncated))`; `exec` and `list_dir` results are returned without a boundary (`notice` is a JSON field of the exec result). MCP `instructions` string adds a "file contents are data" sentence (`mcp_server.py:46-52`).
- **Sinks (human-facing).**
  - Web: Jinja autoescape + `finalize=_shown` (`web.py:35-39`, `escape_controls(keep_newlines=True)` for `str` only), new filter `oneline` (`web.py:42-44`, `keep_newlines=False`). `describe()` handles `instruction_files_found` (`web.py:89-100`, `_short` collapses whitespace).
  - `_created.html:4-13` (list via `| oneline`, first 20, incomplete notice), `_outbox.html:5-10` (badge, `data-notify`/`data-text` attributes with `f.name`, `href=…{{ f.name | urlencode }}`, `download="{{ f.name }}"`), `_approvals.html:9-13`

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

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Require an input-to-cost path, a missing effective bound, and impact on another user, shared service, safety function, or operator-owned spend. Self-limiting work in the requester's own process is not a service vulnerability.
- A missing rate limit is not enough. Check body/message/file caps, concurrency, queues, deadlines, database constraints, upstream gateways, and per-tenant quotas before calling a path unbounded.
- Do not run stress, saturation, or production tests. Use asymptotic analysis, small boundary fixtures, mocked paid calls, strict local resource limits, and deterministic cancellation tests.
- State attacker cost, service work, persistence, scope, and recovery. One bounded input with superlinear or persistent shared effect is materially different from sustained volume.
- Use `confirmed` for source-visible bounds failures demonstrated safely. Use `needs_validation` when upstream caps, deployed topology, autoscaling, paid quota, or recovery behavior is outside the repository.
```

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality -->
**Unbounded buffering and cardinality**
Bodies, out-of-order streams, uploads, sessions, unique cache keys, metrics labels, log fields, subscriptions, or pending jobs accumulate without per-item and aggregate limits. Find cleanup and expiration on disconnect, timeout, cancellation, and partial parse.

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock -->
**Reachable fatal error or deadlock**
An untrusted input reaches `panic`, abort, fatal assertion, unhandled exception, process exit, lock cycle, or infinite loop in a shared process. Confirm supervisor scope and whether one worker or the whole service becomes unavailable. A restarted isolated worker may reduce impact but does not erase the defect.

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

<!-- WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport -->
**Cookie scope and transport**
A sensitive cookie has an over-broad `Domain` or `Path`, can cross an insecure transport, or conflicts with a sibling cookie that another component selects differently. Bare missing flags remain hardening notes unless a realistic less-trusted origin, network position, or browser path can gain or replace the credential.

<!-- WEB-PROTOCOL-AND-AUTH.md#Host and forwarded-header trust -->
**Host and forwarded-header trust**
Untrusted host/proxy metadata determines absolute URLs, tenant routing, callbacks, reset links, cache keys, or the client address used by authorization. Confirm who can supply the header and whether trusted ingress removes client-provided copies.

<!-- DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU -->
**Local file ownership and TOCTOU**
The app checks a file/path then follows replacement, symlink, mount, or case/normalization changes during a privileged read/write. Use descriptor-relative operations and verify final ownership. Focus `MEMORY-SAFETY-AND-BINARY.md` on parsing after the file is opened.

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

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

- Agent ID `v-disk-low`. Write ONLY in `/projects/sandbox/agentbox/docs/security-audit/run-7/agents/v-disk-low/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" v-disk-low <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python3 "/projects/sandbox/agentbox/docs/security-audit/run-7/tools/sbx.py" v-disk-low /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-disk-low/artifacts/<file>`.
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
