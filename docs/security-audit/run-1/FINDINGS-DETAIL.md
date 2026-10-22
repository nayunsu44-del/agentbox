# agentbox — confirmed findings detail (run-1)

Target `nayunsu44-del/agentbox` @ `7fc501f`. Target-neutral; no live-probe steps. Reproductions use only source review and a bounded pure-function harness (no Docker, network, or shared state). The one `low` confirmed record (`_DEVNULL` `>&<digit>`) is summarized in REPORT.md §3.3; this file details the `high` and `medium` records.

---

## F-1 [high] Quoted `#` comment hides a non-allowlisted program from the read-only-exec allowlist

**Fingerprint:** `agentbox/policy.py:simple_programs:quoted-comment-hides-program-from-allowlist`

**Security invariant.** Any `exec` command whose executed programs are not all on the read-only-exec allowlist must route to `exec-needs-approval` and require human approval before running. Equivalently: the policy's view of which programs will run must be consistent-with-or-stricter-than bash's.

**Root cause.** `simple_programs` tokenizes with `shlex` configured `lex.commenters = ""` (`agentbox/policy.py:89`), so `#` is an ordinary character; bash, the actual executor, treats an unquoted word-initial `#` as a comment to end-of-line. When a non-allowlisted command is placed on its own line and a single quote is opened immediately after a `#`, the `'\n' -> ' ; '` rewrite plus the quote swallow the separators and the hidden line into one single-quoted argument token. `simple_programs` then sees only the leading allowlisted program and returns `{ls}`.

**Ordered trace.**
1. entrypoint — `agentbox/api.py:188` `POST /sandboxes/{sid}/tools/{tool}`: the per-sandbox agent principal supplies `body.args['command']`, forwarded unchanged (`api.py:191`).
2. propagation — `agentbox/service.py:185` `AgentBox.call_tool`: `decision = self.policy.decide(tool, args)`; on ALLOW the same raw string is run via `_run_tool` → `sandbox.exec`.
3. propagation — `agentbox/policy.py:89` `simple_programs`: `commenters=""`; the quote after `#` groups the hidden line into one token, leaving only `ls` in command position.
4. propagation — `agentbox/policy.py:153` `Policy.decide`: `only_commands` subset test passes (`{ls} ⊆ allowlist`) → ALLOW, rule `read-only-exec` (returned at `:155`).
5. propagation — `agentbox/service.py:220` ALLOW branch: `_needs_snapshot` returns `False` for exec (`:169`) → **no pre-snapshot**.
6. sink — `agentbox/sandbox.py:379` `SandboxManager.exec`: runs `timeout -k 5 T bash -c "umask 002\n"+command` as uid `1000:1000`; bash strips the `#` comment lines and executes the hidden non-allowlisted program.

**Evidence.** `policy.py:89` (`lex.commenters=""`); `policy.py:153` (subset test → ALLOW); `sandbox.py:379` (`bash -c` wrapper honours `#`/newlines); `service.py:169` (`_needs_snapshot` False for exec); `api.py:191` (agent command reaches exec).

**Dummy attacker / affected resource.** Attacker = prompt-injected agent with only its sandbox agent token. Affected = the operator's approval gate and the `/workspace` contents (no pre-snapshot to restore).

**Bounded reproduction (performed).**
- Pure-function: `python3 -I`, import `agentbox.policy`, `Policy.load("agentbox/default_policy.yaml").decide("exec", {"command": "ls #'\ncp dummy_src SENTINEL\n#'"})` → `action=allow, rule_id=read-only-exec, matched=['ls']`, `simple_programs()=={'ls'}`. A single-quote inside the hidden line instead → `require_approval` (confirms the no-single-quote constraint on the payload).
- Fixture: in a scratch dir with only dummy files, run `bash -c ("umask 002\n" + command)` (the exact `sandbox.exec` wrapper); the hidden `cp dummy_src SENTINEL` (and, separately, a non-allowlisted `python3 -c` writing a sentinel) executes and creates the file.

**Observed result.** The policy classed the command read-only (`{ls}`) yet bash ran a non-allowlisted program; approval and pre-snapshot both bypassed. Bounded to scratch; no target sandbox/Docker/network/shared state touched.

**Containment.** The container's final defenses still hold (`network=none`, `/source` read-only, `cap_drop ALL`, `no-new-privileges`), so impact is confined to the writable `/workspace` inside the container — high, not critical.

**Conditions.** Valid sandbox agent token (no human); default policy active; hidden command contains no single quote and none of `$ ` `` ` `` `>` `<(` (else `simple_programs` returns `None` → approval).

**Smallest effective fix.** In `agentbox/policy.py`, make the lexer bash-faithful: before tokenizing, drop from an unquoted word-initial `#` to end-of-line (per physical line, before the `'\n'->' ; '` rewrite), applied in `simple_programs` and the sibling lexers sharing `commenters=""` (`_words`/`command_names`). More conservatively, return `None` (force approval) whenever an unquoted `#` or any un-modelable construct appears — fail closed on lexing ambiguity. Regression test: the payload above must yield `require_approval`.

---

## F-2 [medium] Container-controlled outbox filename crashes the outbox listing

**Fingerprint:** `agentbox/sandbox.py:outbox_list:unguarded-int-float-on-container-filename`

**Security invariant.** The control plane must treat all container output (here, `find -printf` over agent-created filenames) as untrusted and parse it without crashing or being spoofed.

**Root cause.** `outbox_list` runs `find {OUTBOX} -mindepth 1 -maxdepth 1 -type f -printf "%f\t%s\t%T@\n"` (`agentbox/sandbox.py:488`) where `%f` is the agent-controlled basename emitted raw, then parses each `splitlines()` line with `parts = line.split('\t')` and unguarded `int(parts[1])` / `float(parts[2])` (`:494-495`). A filename containing a newline + tabs both injects forged rows and, with a non-numeric field, raises `ValueError`.

**Ordered trace.**
1. entrypoint — `agentbox/sandbox.py:379` `exec`: the agent's default-allowed `touch` creates a regular file in `/workspace/outbox` with a crafted basename.
2. propagation — `agentbox/api.py:260` `GET /sandboxes/{sid}/outbox` → `outbox()`: `guard()` wraps the call but catches only `ServiceError/SandboxError`.
3. propagation — `agentbox/sandbox.py:488` `outbox_list`: `find -printf "%f…"` prints the basename raw, including embedded newline/tab.
4. sink — `agentbox/sandbox.py:494` parse loop: `int(parts[1])`/`float(parts[2])` with no `try/except` → `ValueError`.

**Evidence.** `sandbox.py:494` (unguarded conversions); `sandbox.py:488` (`%f` raw; GNU findutils 4.9.0 emits LF/TAB verbatim); `default_policy.yaml:27` (`touch` auto-allowed — pure-function harness → `allow`); `api.py:127` and `web.py:209` (only `ServiceError/SandboxError`/`APIError` caught, so `ValueError` → HTTP 500 for API and UI).

**Dummy attacker / affected resource.** Attacker = sandbox code (uid 1000) choosing an outbox filename. Affected = the operator, whose outbox listing (API `GET /sandboxes/{sid}/outbox` and the UI fragment) returns 500 or shows spoofed rows.

**Bounded reproduction (performed).** Pure-function harness confirmed the `touch` command is `allow/read-only-exec` (runs unapproved). A real GNU `find` `-printf "%f\t%s\t%T@\n"` over a dummy file whose basename embeds `\nFAKE\tNOTANUM\tNOTFLOAT` produced the forged line, and feeding that real output through the parse loop raised `ValueError`.

**Observed result.** The operator cannot list the outbox (denial of a control-plane feature) and can be shown forged entries before the crash. No cross-container effect.

**Conditions.** Default policy active (so `touch` is unapproved); the agent writes one crafted-name regular file; the operator lists that sandbox's outbox.

**Smallest effective fix.** In `agentbox/sandbox.py`, wrap the per-line `int()/float()` in `try/except` and skip malformed lines; frame records with NUL and put the attacker-controlled `%f` last (`find … -printf '%s\t%T@\t%f\0'`, split on `\0`) so embedded newlines/tabs cannot inject rows. Regression test: a file whose name contains `\n`/`\t`/non-numeric tokens lists as one benign entry (or is skipped), never 500.
