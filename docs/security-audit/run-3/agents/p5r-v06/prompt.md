You are independent re-verifier `p5r-v06` in a defensive security audit of agentbox.
A Phase 5 verifier proposed the replacement record below; it changes the verdict, root cause, evidence or demonstrated result of an earlier final record, so it may be applied only after an independent check. You did not hunt it, validate it in Phase 3, or propose it. Recheck the current audited source and independently reproduce any decisive local result under the execution boundary (where the decisive result is the parent's live run, re-read the script and output and judge whether they establish it), then return `verified` or another replacement.

# Source under audit

- Read source ONLY from the audited tree `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/src-audited/` (git worktree at commit 8e4db9e; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.
- A fix for this record was committed after Phase 3 as `152b8e4` (`git -C /home/user/agentbox show 152b8e4`). Use it only to judge check 6 (does the proposed remediation enforce the invariant). It is never evidence that the record is wrong for the audited source.

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

# Phase 5 checks for a `confirmed` record (verbatim from the skill)

```text
1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.
```

A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# Proposed replacement record

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass",
 "title": "source_dir overlap guard compares path strings instead of filesystem identity: a second name for the data dir's project folder (bind mount; case variant on case-insensitive drvfs) bypasses it and copies the human token to the agent",
 "description": "SandboxManager.create (sandbox.py:398-405) resolves source_dir with Path.expanduser().resolve() and refuses it only if src == d, d in src.parents or src in d.parents for d in {settings.home.resolve(), db_path.resolve().parent}. resolve() only follows symlinks and keeps the caller's spelling, and Path equality and .parents membership are string decisions with no (st_dev, st_ino) or samefile check. Any second name for the data directory or one of its ancestors that is not a symlink therefore passes the guard. The accepted string becomes the read-only /source bind (sandbox.py:375, 415). The container's root setup 'cp -a /source/. /workspace/ && chown -R 1000:1000 /workspace' (sandbox.py:421-422, with CAP_DAC_OVERRIDE/CHOWN at 381) then copies the 0600 human_token (config.py:94-99) and agentbox.db into agent-owned /workspace. The agent can read them through read_file. That is the run-2 N-4 escalation from the lowest-trust principal (agent token, prompt-injected agent) to full human authority. Observed by the parent against the real Docker-backed control plane with a dummy token: a bind mount of the project dir (same inode, not a symlink) was ACCEPTED, and the agent's read_file of /workspace/data/human_token returned the real human token. The exact project path was REFUSED in the same run. v06 also showed the string guard accepts case variants of the path (agents/v06/artifacts/guard_v06.out) on a case-sensitive FS with a fake Docker client, where the variant is a separate directory. A real case-insensitive alias (WSL2 /mnt/<drive> drvfs, which README.md:17 lists as supported, with ./data under the Windows-hosted project dir as the default per config.py:29) is the plausible natural trigger but was NOT observed. The trigger is operator-supplied (POST /sandboxes human_only, or a '*'-scope browser session via POST /ui/sandboxes). The CLI sends os.path.abspath(source), which keeps the shell's spelling. An agent cannot set source_dir. This is therefore a bypass of an operator-mistake safety control, not an attacker-chosen input. The compose deployment fails safe because its control plane sees only /var/lib/agentbox.",
 "root_cause": "The overlap check at sandbox.py:403-404 decides containment on resolved, spelling-preserving path strings (Path ==, .parents membership) instead of filesystem identity (os.path.samefile / st_dev+st_ino). Where two names resolve to one directory without being a symlink, such as a bind mount or a case variant on a case-insensitive filesystem, neither the data directory nor its ancestors are recognised, and the protected folder is mounted and copied to the agent.",
 "intended_behavior": "The comment at sandbox.py:400-401 states the intent: if the source folder overlaps the data folder, the human token, DB and other sandboxes' sources would be handed to the agent, so such a source_dir must be refused. The check should refuse every name for the data directory, its ancestors or its descendants, whatever the spelling or alias.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 152,
   "scope": "create_sandbox (POST /sandboxes, human_only); also web.py:161 POST /ui/sandboxes via browser_human, which api.py:437 wires to screen_human ('*' scope)",
   "description": "A human operator (API/CLI or full-scope browser session) submits source_dir. The CLI sends os.path.abspath(source) (cli.py:136), which keeps the shell's spelling. Agent tokens and desktop-scoped sessions cannot reach these routes."
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
   "description": "src = Path(source_dir).expanduser().resolve() follows symlinks only and keeps the caller's spelling (a bind-mount alias or case variant is preserved)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 404,
   "scope": "SandboxManager.create overlap guard",
   "description": "src == d / d in src.parents / src in d.parents for d in {home, DB dir} are string comparisons with no samefile/st_ino check. An alias spelling matches no arm and is accepted."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 375,
   "scope": "SandboxManager._run_container (called at sandbox.py:415 with str(src))",
   "description": "The accepted alias string becomes the read-only bind source at /source, so the daemon mounts the real data directory's parent."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 421,
   "scope": "SandboxManager.create workspace setup (exec as 0:0)",
   "description": "Root 'cp -a /source/. /workspace/' plus chown -R 1000:1000 (line 422) with DAC_OVERRIDE (line 381) copies every file under /source, including the 0600 human_token and agentbox.db, into agent-owned /workspace, where the agent's read_file returns them."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 404,
   "description": "Guard is 'src == d or d in src.parents or src in d.parents': pure path-string comparison. There is no samefile, st_ino or casefold in sandbox.py."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 398,
   "description": "expanduser().resolve() canonicalises symlinks only and keeps the caller's spelling."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 421,
   "description": "Root cp -a /source/. /workspace/ then chown -R (line 422). The container has CAP_DAC_OVERRIDE and CAP_CHOWN (line 381), so the 0600 token is copied regardless of mode."
  },
  {
   "file": "agentbox/config.py",
   "line": 99,
   "description": "human_token is written to settings.home/human_token with mode 0600 (lines 94-99). Root copy ignores the mode. AGENTBOX_HOME defaults to ./data (config.py:29), so the project dir often contains the data dir."
  },
  {
   "file": "agentbox/cli.py",
   "line": 136,
   "description": "CLI create sends os.path.abspath(source), which keeps the shell's spelling of the path."
  },
  {
   "file": "agentbox/api.py",
   "line": 130,
   "description": "screen_human requires scope '*', so only full human sessions reach POST /ui/sandboxes. Agents cannot choose source_dir."
  },
  {
   "file": "agents/parent-live/artifacts/l8_alias.out",
   "line": 3,
   "description": "Parent-live run against the real Docker-backed control plane with a dummy 0600 token: the bind-mount alias is not a symlink but has the same inode as the project dir. The exact project dir is REFUSED. The alias is ACCEPTED as sb_5f282ecc, and the agent's read_file /workspace/data/human_token returned the real human token (equals real human token: True). The decisive reproduction is the parent's. The guard line it exercised is byte-identical to audited sandbox.py:404, because the script ran before fix 152b8e4."
  },
  {
   "file": "agents/v06/artifacts/guard_v06.out",
   "line": 6,
   "description": "v06 harness with a fake Docker client: exact, trailing-slash, '..' and ancestor spellings refused. Case-variant spellings were accepted and passed unchanged to the /source bind. This only shows the string guard accepts them. On a case-sensitive FS they are separate directories."
  },
  {
   "file": "README.md",
   "line": 17,
   "description": "Linux or Windows WSL2 with Docker is listed as supported, so the case-insensitive drvfs trigger is plausible but unobserved."
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "The caller must be a human principal (human token on POST /sandboxes, or a '*'-scope browser session on POST /ui/sandboxes). An agent token cannot choose source_dir, so the lowest-trust principal only receives the result."
  },
  {
   "kind": "user_interaction",
   "description": "The operator must supply a source_dir that is a non-symlink alias of the data dir's project folder or one of its ancestors: a bind mount (observed), or a case variant on a case-insensitive filesystem such as WSL2 /mnt/<drive> drvfs (plausible, not observed)."
  },
  {
   "kind": "system_configuration",
   "description": "AGENTBOX_HOME (or the DB directory) is on a filesystem or mount where such an alias exists. The compose deployment is not affected, because its control plane sees only /var/lib/agentbox."
  },
  {
   "kind": "environmental_dependency",
   "description": "A Docker daemon that resolves the alias string to the same directory (true for the bind-mount case observed live)."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent with an agent token. It cannot trigger creation. It benefits when the operator creates a sandbox whose source_dir is an alias (for example a bind mount or case-variant spelling) of the folder containing the agentbox data directory. The agent then reads the human token with the ordinary read_file tool.",
  "payloads": [
   "source_dir = <non-symlink alias of the directory that contains ./data> (observed: a bind mount of the project dir)",
   "agent tool call: read_file {\"path\": \"/workspace/data/human_token\"}"
  ],
  "instructions": [
   "Create a disposable project dir P with AGENTBOX_HOME=P/data and a dummy human token written 0600 by Settings (AGENTBOX_HUMAN_TOKEN unset).",
   "Create a second name for P that is not a symlink (mount --bind P ALIAS).",
   "POST /sandboxes with source_dir=P and observe the refusal.",
   "POST /sandboxes with source_dir=ALIAS and observe that it is accepted.",
   "As the new sandbox's agent, call read_file /workspace/data/human_token.",
   "Delete the sandbox and unmount ALIAS. Reproduction script: agents/parent-live/artifacts/l8_alias.py."
  ],
  "observed_result": "Parent-live, loopback only, dummy token: exact project dir REFUSED with the overlap error. The bind-mount alias was ACCEPTED (sb_5f282ecc), and the agent's read_file of /workspace/data/human_token returned status 200 with content equal to the real human token. The case-variant instance on a real case-insensitive filesystem was not observed."
 },
 "remediation": {
  "strategy": "Decide overlap on filesystem identity, not strings. Refuse when src or any of its ancestors is os.path.samefile with a protected directory, or when a protected directory or any of its ancestors is samefile with src. Fix 152b8e4 implements this as overlaps() in sandbox.py. Add a regression test with a bind mount or a case-insensitive fixture.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "def overlaps(a: Path, b: Path) -> bool:\n    def same(x: Path, y: Path) -> bool:\n        try:\n            return x == y or os.path.samefile(x, y)\n        except OSError:\n            return False\n    return any(same(x, b) for x in (a, *a.parents)) or any(same(a, y) for y in (b, *b.parents))\n\n# in create(): if overlaps(src, d): raise SandboxError(...)"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Only a human operator can choose source_dir, and it must be a non-symlink alias of the data dir's project folder: a bind mount, or a case variant on a case-insensitive drvfs data dir. Both are unusual operator mistakes. The case-insensitive path is unobserved."
  },
  "impact": {
   "score": "high",
   "reason": "The agent obtains the shared human token and the DB, which is full human authority (approval gate, other sandboxes, audit). Demonstrated live with the bind-mount alias."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Source path re-read line by line in the audited tree, and the string-only guard is unambiguous. The parent's live run shows acceptance of an inode-identical alias and the agent reading the real token, with the exact path refused as a control. The remaining uncertainty is only whether real WSL2 drvfs case variants alias in practice, which affects likelihood, not the root cause."
 }
}
```

Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.

# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.
Checks marked (after Phase 3) were run after this record was written and are not yet reflected in it.

- agents/parent-live/artifacts/l8_alias.out
- agents/parent-live/artifacts/l8_alias.py (after Phase 3)
- agents/parent-live/artifacts/l8_alias.py.

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

- Agent ID `p5r-v06`. Write ONLY in `/home/user/agentbox/docs/security-audit/run-3/agents/p5r-v06/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `/tmp/claude-0/-home-user-agentbox/1357e46b-55dd-58a4-b1d6-d791486808ee/scratchpad/sbx5 p5r-v06 <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/p5r-v06/artifacts/<file>`.

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
