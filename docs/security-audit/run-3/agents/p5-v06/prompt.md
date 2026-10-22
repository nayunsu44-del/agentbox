You are Phase 5 final-record verifier `p5-v06` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.
- A change for this root cause was committed after Phase 3 as `152b8e4`. It does not change the audited source; ignore it for verification.

# Execution boundary (verbatim from the skill)

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
```

# Phase 5 checks for a `needs_validation` record (verbatim from the skill)

```text
1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.
```

A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# Final record (from findings.json)

```json
{
 "verdict": "needs_validation",
 "fingerprint": "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass",
 "title": "source_dir overlap guard compares resolved path strings case-sensitively; on a case-insensitive WSL2 drvfs data dir a case-variant source_dir may bypass it and re-expose the run-2 N-4 human-token copy",
 "description": "SandboxManager.create (sandbox.py:398-405) resolves source_dir with Path.expanduser().resolve() and rejects it only if src == d, d in src.parents, or src in d.parents for d in {settings.home.resolve(), db_path.resolve().parent}. On Linux, resolve()/posixpath.realpath only follows symlinks and keeps the caller's spelling, and PurePosixPath equality is case-sensitive, so the guard is a pure string decision with no (st_dev, st_ino) or samefile check. v06 reproduced this independently in the sbx sandbox with a fake Docker client: exact, trailing-slash, '..', ancestor and descendant spellings were refused, but '/scratch/ci/C/users/me/proj', '.../users/me/proj/data' and '/scratch/ci/C/USERS/ME/PROJ' were accepted and passed unchanged to the /source bind mount (agents/v06/artifacts/guard_v06.out). That only shows that the string guard accepts the variant. On this case-sensitive kernel the variant is a separate stand-in directory, so the alias itself was not observed. README.md:17 lists Windows WSL2 as supported, and Settings.home defaults to ./data resolved from the server's cwd (config.py:29). If the data dir sits on a drvfs mount (/mnt/<drive>) under parent directories without the per-directory case-sensitivity flag, a source_dir that differs only in letter case (for example the project dir containing ./data, typed or cd'ed with different case and then passed through cli.py:136 os.path.abspath) would name the same directory. The guard would accept it, the daemon would bind-mount it read-only at /source, and the root setup 'cp -a /source/. /workspace/ && chown -R 1000:1000 /workspace' (sandbox.py:421-422, container has DAC_OVERRIDE/CHOWN) would copy the 0600 human_token (config.py:94-99) and agentbox.db into agent-owned /workspace. That is the run-2 N-4 escalation from the lowest-trust principal (the agent token / prompt-injected agent) to full human authority. The trigger is human_only (api.py:152) or a '*'-scope browser session (web.py:161-164 via screen_human, api.py:126-132), so this is a bypass of an operator-mistake safety control, not an attacker-chosen input; an agent cannot set source_dir. The compose deployment fails safe because its control plane sees only /var/lib/agentbox. macOS is not a supported platform per README, so the original macOS/APFS claim is dropped. Same root cause also covers other non-symlink aliases (e.g. bind mounts). Suggested fix: decide overlap on filesystem identity, i.e. reject when any of src and its ancestors is os.path.samefile with a protected dir, or any of a protected dir and its ancestors is samefile with src, instead of comparing Path strings.",
 "claimed_root_cause": "Overlap containment in SandboxManager.create is decided on resolved, case-preserving path strings (Path ==, .parents membership) instead of filesystem identity (st_dev, st_ino / samefile). Where two spellings name one directory, as on case-insensitive WSL2 drvfs lookups, the guard does not recognise the data directory or its ancestors.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 152,
   "scope": "create_sandbox (POST /sandboxes, human_only); also web.py:161 POST /ui/sandboxes via screen_human ('*' scope)",
   "description": "Human operator (API/CLI or full-scope browser session) submits source_dir. The CLI sends os.path.abspath(source), which keeps the spelling of $PWD (cli.py:136). Agent tokens and desktop-scoped sessions cannot reach this route."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 429,
   "scope": "Service.create_sandbox",
   "description": "Forwards source_dir unchanged to SandboxManager.create after audit logging."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 398,
   "scope": "SandboxManager.create",
   "description": "src = Path(source_dir).expanduser().resolve(): follows symlinks only and keeps the caller's letter case (verified: realpath returned the lowercase variant)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 404,
   "scope": "SandboxManager.create overlap guard",
   "description": "src == d / d in src.parents / src in d.parents against home and DB dir are case-sensitive string comparisons. A case-variant spelling matches no arm and is accepted (reproduced with fake Docker)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 375,
   "scope": "SandboxManager._run_container (called at sandbox.py:415 with str(src))",
   "description": "The accepted variant string becomes the read-only bind source at /source. Whether the daemon resolves it to the same inode as the data dir depends on the host filesystem (unobserved)."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 421,
   "scope": "SandboxManager.create workspace setup (exec as 0:0)",
   "description": "Root 'cp -a /source/. /workspace/' plus chown -R 1000:1000 (sandbox.py:422) with DAC_OVERRIDE copies every file under /source, including a 0600 human_token and agentbox.db if the alias holds, into agent-owned /workspace."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 403,
   "description": "Protected set is {settings.home.resolve(), settings.db_path.resolve().parent}; no samefile/st_ino/casefold anywhere in create() (checked via inspect in harness)."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 404,
   "description": "Path ==/.parents comparison is case-sensitive on POSIX (PurePosixPath('/a/Users') != PurePosixPath('/a/users'))."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 398,
   "description": "expanduser().resolve() keeps the caller's case; only symlinks are canonicalised."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 375,
   "description": "Accepted src string is the bind-mount source for /source (ro)."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 421,
   "description": "Root cp -a /source/. /workspace/ then chown -R 1000:1000 (line 422); container has CAP_DAC_OVERRIDE/CHOWN (line 382)."
  },
  {
   "file": "agentbox/config.py",
   "line": 29,
   "description": "AGENTBOX_HOME defaults to ./data resolved against the server cwd, so a project dir often contains the data dir."
  },
  {
   "file": "agentbox/config.py",
   "line": 94,
   "description": "human_token lives in settings.home and is written 0600 (line 99); root copy ignores this."
  },
  {
   "file": "agentbox/cli.py",
   "line": 136,
   "description": "CLI create sends os.path.abspath(source), which keeps the shell's spelling of the path."
  },
  {
   "file": "agentbox/api.py",
   "line": 130,
   "description": "screen_human requires scope '*', so only full human sessions reach POST /ui/sandboxes; agents cannot choose source_dir."
  },
  {
   "file": "README.md",
   "line": 17,
   "description": "Supported platforms: Linux or Windows WSL2 with Docker. WSL2 /mnt/<drive> drvfs lookups are case-insensitive in directories without the per-directory case-sensitivity flag."
  },
  {
   "file": "agents/v06/artifacts/guard_v06.out",
   "line": 7,
   "description": "sbx harness (fake Docker): exact/trailing/'..'/ancestor/descendant spellings REFUSED; lowercase and uppercase variants ACCEPTED and passed to the bind mount. Run on a case-sensitive FS with a stand-in directory, so the alias is not demonstrated."
  }
 ],
 "blockers": [
  "No case-insensitive filesystem exists in this container/kernel (no casefold ext4, no vfat/ntfs/drvfs mount can be created), so v06 could not observe a case-variant source_dir naming the same inode as the data dir. That is the decisive step; only the string-level guard acceptance was reproduced.",
  "Deployment fact: whether any real agentbox install keeps AGENTBOX_HOME (or the AGENTBOX_DB directory) under a WSL2 drvfs path (/mnt/<drive>/...) whose ancestor directories are case-insensitive (no per-directory case-sensitivity flag). The default ./data under a Windows-hosted project is plausible but unobserved.",
  "Whether the Docker daemon used with WSL2 (Docker Desktop WSL integration or native dockerd in the distro) resolves the case-variant bind source to the same directory, so that root cp -a copies the real human_token into /workspace (the copy behaviour itself is source-evident and was observed live for exact-path overlap in run-2 N-4)."
 ],
 "validation_plan": {
  "local": "On an isolated disposable Linux host with root and Docker (not this container), run: truncate -s 64M /tmp/ci.img && mkfs.ext4 -O casefold /tmp/ci.img && mkdir /mnt/ci && mount -o loop /tmp/ci.img /mnt/ci && mkdir /mnt/ci/cf && chattr +F /mnt/ci/cf && mkdir -p /mnt/ci/cf/Users/Me/proj. Alternatively use mkfs.vfat on the loop image and mount it with uid set to the test user. Export AGENTBOX_HOME=/mnt/ci/cf/Users/Me/proj/data with a dummy token (AGENTBOX_HUMAN_TOKEN unset so human_token is written 0600). (1) Run agents/v06/scratch/guard_v06.py adapted to these paths with the fake Docker client and assert that create('/mnt/ci/cf/users/me/proj') is ACCEPTED and that os.stat(src) has the same (st_dev, st_ino) as os.stat(home.parent). (2) With the real daemon and buildpack-deps:noble-curl, create the sandbox with the lowercase path, then as the agent call read_file /workspace/data/human_token and expect the dummy hum_ token. Delete the sandbox and unmount afterwards. Pass criterion: same inode and dummy token readable by uid 1000. Fail criterion: guard refuses or bind source differs.",
  "deployment": "Owner-observed on a WSL2 host with Docker: in a throwaway Windows-created folder C:\\Users\\<u>\\abx-test, confirm case-insensitivity with 'fsutil.exe file queryCaseSensitiveInfo C:\\Users\\<u>\\abx-test' (expect disabled). cd /mnt/c/Users/<u>/abx-test and start 'agentbox serve' with default AGENTBOX_HOME=./data and a fresh dummy token. Run 'agentbox create /mnt/c/users/<u>/abx-test' (different case). Record whether creation succeeds and whether the agent token's read_file of /workspace/data/human_token returns the dummy token. Then delete the sandbox and the test folder. Do not use a production data directory or real token."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.
Checks marked (after Phase 3) were run after this record was written and are not yet reflected in it.

- agents/parent-live/artifacts/l8_alias.out (after Phase 3)
- agents/parent-live/artifacts/l8_alias.py (after Phase 3)

# Architecture facts

# agentbox architecture summary (run-3)

Source ref: `0e4b958` on `ccr-e10bee8e-6wt669` (PR #5 head; `agentbox/` identical after merge to `main`). Profile `standard`, whole repo.

## 1. Product, principals, protected resources

agentbox is a self-hosted control plane (FastAPI + SQLite) that gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. A desktop mode adds Xvfb/Xfce/noVNC so a human can watch or take over the screen.

- **Human token** `hum_…` (one shared admin secret, `config.py:88-100`): full API.
- **Web UI cookie session**, scope `*` (token login form or one-time `*` ticket): full UI (`web.py:208-242`, `desktop.py`).
- **Desktop-link session**, scope = one sandbox id (redeemed per-sandbox ticket): only that sandbox's desktop page/state/takeover/handback/WS (`api.py:134-140,298-336`, `desktop.py:147-152`).
- **Agent token** `agt_…` per sandbox (hash stored): tool calls on its own sandbox, read own sandbox/approval/desktop state (`api.py:160-230,315`). Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (tool execs), uid 1001 `desktop` (X session, GUI tools, x11vnc; member of the agent group, `/workspace` group-writable). Container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listings, file names) is attacker-controlled input to the control plane.
- **MCP stdio server / agent.py LLM loop**: hold an agent token; inherit trust from the local launcher.

Protected resources: the human token and approval authority; host filesystem and Docker daemon (control plane holds `docker.sock` = host root); other sandboxes; integrity of `/workspace` restore points (AP-2 snapshots before destructive actions); audit-log integrity and secret masking; control-plane availability (shared thread pool, memory, host disk via `docker commit`).

## 2. Comparable baseline

No source-grounded comparable product. Components: MCP (FastMCP stdio), VNC/RFB via x11vnc+noVNC, gVisor/Kata runtimes. A runc sandbox shares the host kernel; the code refuses runc only when the control plane is exposed (`cli.py:79-115`).

## 3. Stack, deployment, offline limits

Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: local `agentbox serve` (127.0.0.1), direct TLS, `--behind-tls-proxy` (compose + Caddy, `forwarded_allow_ips="*"` by default), `--insecure`, and the bare `uvicorn agentbox.api:create_app --factory` path that skips serve-time checks. Container flags: `network_mode=none`, `/source` read-only bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits; no userns, default seccomp (`sandbox.py:367-388`). Host: Docker 29.9.1, runtimes `runc` and `io.containerd.runc.v2` only (no gVisor/Kata), cgroup v1, images `agentbox-desktop:0.1`, `buildpack-deps:noble-curl`. Pure-function harnesses and the three unit test modules fit the parent's `sbx` sandbox; anything that builds the app needs the Docker daemon (parent-live checks).

## 4. Entry surfaces and important paths

- JSON API `POST /sandboxes/{sid}/tools/{tool}` → `service.call_tool` (per-sandbox concurrency 4, 429) → audit → `policy.decide` → allow / approval queue → `sandbox.exec|read_file|write_file|delete_file|list_dir|gui_*` (`docker exec` as uid 1000/1001), dedicated 32-thread `tool_pool` (`api.py:81`). Exec output streamed and capped (`_Head`, 64 KB).
- Approvals `POST /approvals/{aid}` (human only) → atomic claim → pre-snapshot → run with the agent's original args; terminal approver `cli.py` renders args through `_safe()`.
- Snapshots: `docker commit` before write/delete overwrite and per GUI burst; quota 50 → approval (`service.py:199-204`); per-sandbox `_snap_locks`.
- GUI bursts (`service.py:186-260`): snapshot + manifest + baseline pids at burst start; at close, kill new uid-1001 processes classified by `gui_strays` from root `ps` output and `xdotool` window pids (`sandbox.py:174-225,686-697`), diff `find -printf` manifest (8 MB cap) and log `gui_changes`. Closed on idle from `expire_stale`, `call_tool`, `GET /audit`, UI audit fragment, takeover, end_desktop.
- Files: `read_file` (`timeout` + `[ -f ]` FIFO guard), `outbox_list/read`, `POST /sandboxes/{sid}/files` upload, `source_dir` copy at create (refuses overlap with `settings.home`/DB dir).
- Desktop: tickets (60 s, one-time, hashed), sessions (12 h, hashed, `scope`), leases keyed by public session id `hs_`+32 bits, WS `/desktop/ws` (cookie + same_origin; control needs lease; re-check every 30 s, `session_ended` handback), logout `end_ui_session`.
- Audit: hash chain with append-only triggers, `mask_text` regex set (`audit.py`), UI/CLI timelines render container-controlled strings (`web.py describe`, Jinja autoescape; `cli._safe`).
- Serve: `bind_problem`, `runtime_problem` (literal `"runc"` only), `--allow-runc`/`AGENTBOX_ALLOW_RUNC`.

## 5. Trust boundaries and strongest control

| Boundary | Strongest control |
|---|---|
| Agent → host/other sandboxes | container hardening + runtime (runc here) |
| Agent → approval gate (exec) | `policy.simple_programs` allowlist + `has_bash_comment` + `>` gate |
| Agent → approval gate (GUI) | none by design; burst snapshot, `gui_changes`, stray kill (partial, N-1) |
| Agent → human authority | token kinds, `human_only`, scope checks, source_dir overlap check |
| Agent → control-plane availability | tool_pool, tool_concurrency, `_Head`, snapshot quota, read timeouts |
| Container output → control plane | parsers `_parse_ps`, `_parse_manifest`, `_parse_outbox`; masking; escaping |
| Browser → UI | SameSite=Strict HttpOnly cookie, `same_origin` (missing Origin allowed) |
| Desktop-link session → rest of UI | `scope` column, `desktop_human` |
| Network → control plane | `bind_problem` TLS gate; proxy trust `*` |

## 6. Starting paths

`agentbox/service.py`, `sandbox.py`, `api.py`, `policy.py`, `desktop.py`, `audit.py`, `web.py`, `cli.py`, `config.py`, `approvals.py`, `mcp_server.py`, `agent.py`, `default_policy.yaml`, `images/desktop/`, `deploy/`.

## 7. Prior coverage and revalidation

run-1 (`7fc501f`, standard, source-only) ledger: 15 units; run-2 validated live. 9 confirmed records, all with changed source (fixed in PR #1–#5; N-1 GUI bypass only partially mitigated) → `prior_confirmed_changed_source` revalidation units, not excluded from hunting. One rejected claim (`desktop.py:redeem:sandbox-scoped-ticket-mints-unscoped-full-admin-session`): source changed (scope column), so the unit is current work. No same-source confirmed exclusions. Changed since `7fc501f`: 9 source files (+598/−67) — first priority.

## 8. Companion selection

- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: agent-driven work consumes the shared pool, memory, host disk.
- `AI-AND-LLM.md`: tool-calling agent behind an approval gate; MCP server; prompt-injection threat model.
- `WEB-PROTOCOL-AND-AUTH.md`: cookie sessions, tickets, login, proxy headers.
- `CLIENT-SIDE.md`: browser UI with htmx and a cookie-authenticated WebSocket.
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md`: x11vnc/docker-exec bridge, uid 1001 desktop helper killed/inspected by the control plane.
- `CLOUD-AND-DEPLOYMENT.md`: container capabilities, runtime selection, compose/proxy precedence.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: snapshots/restore, delete, audit as alternate reader.
- Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native code in scope), `SUPPLY-CHAIN-AND-RELEASE.md` (no release/signing path; CI only runs tests), `PROTOCOLS-RPC-AND-MESSAGING.md` (no broker/RPC beyond HTTP/WS/MCP stdio covered elsewhere).


# Execution paths

- Agent ID `p5-v06`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5-v06/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5-v06 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5-v06/artifacts/<file>`.

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


# report-schema.json branches (verbatim): confirmed, needs_validation, rejected

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


# Output

Return exactly one JSON object with no prose and no markdown fence, one of:
{"decision": "verified", "fingerprint": "<the record's fingerprint>"}
{"decision": "replace", "reason": "<what failed and why>", "record": {...}, "artifacts_to_promote": [...]}
A replacement record must match its `confirmed`, `needs_validation`, or `rejected` branch exactly (additionalProperties: false) and keep the same fingerprint unless you identified a genuinely different root cause. `artifacts_to_promote` is optional. Overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
