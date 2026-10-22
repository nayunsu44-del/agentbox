# agentbox — security audit report (run-1)

## 1. Run parameters and scope

| Field | Value |
|---|---|
| Target | `nayunsu44-del/agentbox` @ `7fc501f` (clean worktree) |
| Profile | `standard`, scope = whole repo |
| Execution policy | **sandboxed-source-and-local-only** |
| Prior runs | none (first pass) |
| Agents spent | recon 6 · hunters 7 · adversarial verifiers 9 · record verifiers 8 (+ parent inline coverage-critic) |
| Coverage ledger | 15 units — 8 covered, 7 candidate, 0 planned/deferred; validator **PASS** |
| findings.json | 9 records — 3 confirmed, 5 needs_validation, 1 rejected; validator **PASS** |

**Execution-boundary disclosure (partial-pass caveat).** No OS-enforced sandbox was provisioned for this run and the Docker daemon was unreachable, so **no target-controlled code was executed** (no `pytest`, `docker`, demo, or target shell). Source inspection was exhaustive; two policy/tokenizer defects were additionally reproduced with a bounded pure-function harness (importing the side-effect-free `agentbox/policy.py` under `python3 -I`, and running the exact `bash -c "umask 002\n"+command` wrapper on dummy files in scratch — touching neither Docker, the network, nor shared state). Every finding whose decisive proof needs the live Docker sandbox, a runtime, or a deployment fact is recorded as **needs_validation** with that exact blocker rather than confirmed. A single run does not exhaust the target; re-runs improve coverage.

## 2. Security posture

agentbox is a well-structured MVP with real, layered controls: per-sandbox agent tokens, an atomic human-approval queue, a fail-closed hash-chained audit log, pre-snapshots before destructive tool calls, `network=none` + read-only `/source` containers, and a plaintext-bind refusal. The audit correctly reproduced several of these as *working* controls (upload path hardening, Jinja autoescape, outbox symlink exclusion, agent-cannot-approve). The central weakness is in the **exec policy engine**: its command parser (`simple_programs`) and the executing `bash -c` disagree on `#` comments and on one redirection form, so the read-only-exec allowlist — the gate that is supposed to force human approval for anything beyond read-only commands — can be bypassed, defeating both the approval step and the pre-snapshot that the product's own threat model relies on. The remaining confirmed issue is a container-controlled DoS of the operator's outbox listing. The rest are deployment/runtime-dependent and are handed off for validation.

## 3. Confirmed findings

| Severity | Title | Boundary | Observed result |
|---|---|---|---|
| **high** | Quoted `#` comment hides a non-allowlisted program from the read-only-exec allowlist | agent → exec approval gate | `policy.decide` returns `allow/read-only-exec` (programs `{ls}`) while `bash -c` runs the hidden non-allowlisted program; approval **and** pre-snapshot bypassed (confined to the container: `network=none`, `/source` read-only) |
| **medium** | Container-controlled outbox filename crashes the outbox listing (unguarded `int()/float()`) | sandbox container → control plane | A sandbox-created filename with an embedded newline + non-numeric fields makes `outbox_list` raise `ValueError` → HTTP 500 for the operator's outbox (API and UI), and can inject forged rows |
| **low** | `_DEVNULL` regex strips `>&<digit>` before the `>`-means-approval check | agent → exec approval gate | `policy.decide` returns `allow` for `echo DATA >&2evil` while `bash` writes/overwrites a digit-prefixed `/workspace` file with no approval and no pre-snapshot |

### 3.1 [high] Quoted `#` comment bypasses the exec allowlist
- **Where:** `agentbox/policy.py:89` (`simple_programs`, `lex.commenters=""`) vs `agentbox/sandbox.py:379` (`bash -c "umask 002\n"+command`); gate at `agentbox/policy.py:153`; no snapshot on the exec ALLOW path (`agentbox/service.py:169`).
- **Lower-trust principal:** the per-sandbox agent token holder (e.g. a prompt-injected agent). No human is involved.
- **Bounded reproduction (target-neutral):** in `python3 -I`, `Policy.load(default_policy.yaml).decide("exec", {"command": "ls #'\\n<cmd>\\n#'"})` returns `action=allow, rule_id=read-only-exec, matched=['ls']`; running the exact `bash -c ("umask 002\n"+command)` wrapper in a scratch dir executes the hidden `<cmd>` (demonstrated with a non-allowlisted `python3`/`cp` writing a sentinel). A single-quote inside `<cmd>` flips the decision to `require_approval` (the only constraint on the hidden payload).
- **Result:** unapproved arbitrary code execution as uid 1000 and unapproved destructive actions with no recovery snapshot. Bounded by the container (no network, read-only `/source`), hence high, not critical.
- **Priority rationale:** this is the product's core control and the exact scenario its own demo advertises as "caught at approval." Trivial to craft; high likelihood × high impact.
- **Smallest fix:** make the policy lexer treat the command as bash will — strip bash comments (unquoted word-initial `#` to end-of-line, per physical line) before tokenizing, or fail closed (`return None` → approval) on any unquoted `#` / un-modelable construct. Apply to `simple_programs` and the sibling lexers that share `commenters=""`.

### 3.2 [medium] Outbox listing crashes on a container-controlled filename
- **Where:** `agentbox/sandbox.py:488` (`find … -printf "%f\t%s\t%T@\n"`, `%f` raw) → `:494-495` (unguarded `int()/float()` in the parse loop); `guard()` catches only `ServiceError/SandboxError` (`agentbox/api.py:127`), `outbox_frag` only `SandboxError/APIError` (`agentbox/web.py:209`), so a `ValueError` becomes HTTP 500.
- **Lower-trust principal:** sandbox code (uid 1000) choosing an outbox filename; the affected principal is the operator whose outbox view breaks.
- **Bounded reproduction:** the default policy auto-allows `touch` (pure-function harness), so the agent creates one regular file under `/workspace/outbox` whose basename embeds a newline and three tab-separated tokens with a non-numeric middle; GNU `find` (4.9.0) emits the basename verbatim, and feeding that output through the parse loop raises `ValueError` (and, before crashing, forged rows parse as fake entries).
- **Result:** the operator cannot list the outbox (denial of a control-plane feature), and spoofed rows can mislead the human. No cross-container effect.
- **Smallest fix:** wrap per-line conversion in `try/except` and skip malformed lines; use a NUL record framing with the attacker-controlled `%f` last (`-printf '%s\t%T@\t%f\0'`) so embedded newlines/tabs cannot inject rows.

### 3.3 [low] `>&<digit>` redirect slips past the `>`-means-approval guard
- **Where:** `agentbox/policy.py:77` (`_DEVNULL` second alternative `\d*>&\d`) stripped at `:83` before the `any('>' in cmd)` guard at `:84`.
- **Result:** an allowlisted `echo DATA >&2evil` is granted `allow` while bash creates/overwrites a digit-prefixed `/workspace` file with no approval and no pre-snapshot. Marginal over the already-allowed `write_file` tool, so low.
- **Smallest fix:** anchor `_DEVNULL` so only genuine `/dev/null` discards and bare `N>&M` fd-duplications are stripped (e.g. `r"\d*>>?\s*/dev/null(?![\w./-])|\d*>&\d+(?![\w./-])"`), leaving `>&2evil` with its `>` so it routes to approval.

## 4. NEEDS VALIDATION (prioritized leads, no severity)

| Lead | Repository trace | Exact blocker | Resolution |
|---|---|---|---|
| GUI tools → uid 1001 terminal exec | `service.py:94` → `sandbox.py:568` → `images/desktop/Dockerfile:19` | Whether the shipped Xfce session lets `type`/`key` reach a terminal emulator (runtime/image UI fact); and whether the resulting uid-1001 process writes `/workspace` with no approval/snapshot (needs live desktop sandbox) | Start a desktop sandbox in an OS sandbox; drive GUI tools only to open `xfce4-terminal` and run a marker; confirm no approval card / no snapshot and survival across takeover |
| exec output buffered before truncation | `sandbox.py:379-385` (`exec_run(demux=True)`), cap only at `:96` | Real socket throughput × 60 s timeout vs control-plane RSS; whether a deployment memory bound exists | Bounded local: stream a high-rate stdout producer under a cgroup memory limit and watch control-plane RSS; owner confirms any `MemoryMax`/cgroup |
| unbounded `docker commit` snapshots | `sandbox.py:336-349`; `service.py:160-169` overwrite path | Actual image accumulation / host-disk exhaustion; whether an external image reaper runs | Owner observes snapshot-image growth under repeated overwrite/delete; confirm any prune job |
| `source_dir` arbitrary host copy → secret disclosure | `sandbox.py:271-294` (root `cp -a` with DAC_OVERRIDE) | Whether container uid 0 is host-root-equivalent under the deployed runtime (userns/rootless?) so 0600 host files (e.g. `human_token`) become agent-readable | Owner confirms runtime + userns config; local test under the real runtime with a dummy 0600 file |
| terminal approval escape-sequence spoof | `cli.py:165,172-178` print agent strings raw | Whether the operator uses the terminal `approve` flow (vs the safe web UI), and whether the system-computed "affected" section neutralizes deception in practice | Owner confirms approval surface; local: render a crafted command in a terminal and observe |

## 5. Rejected (retained so future runs do not repeat the claim)

- `agentbox/desktop.py:redeem:sandbox-scoped-ticket-mints-unscoped-full-admin-session` — **not a vulnerability.** Only the full-admin human-token holder can mint a desktop ticket (`api.py:272`, `human_only`); the session it yields is identical to a login session, so sharing the link is equivalent to sharing a login link — no trust boundary is crossed. The single-admin model has no session sub-scopes by design (README known limitation). *(Breadth-reduction hardening is still listed below.)*

## 6. Hardening notes and positive patterns

**Confirmed-safe (good patterns, not findings):** upload path is robust (`clean_name` blocks traversal/control chars; `mv -f --` argv, no shell; replaces symlinks rather than writing through); Jinja autoescape is on, so agent-controlled approval/outbox/audit strings cannot become stored XSS; outbox excludes symlinks (`find -type f`, `! -L`); agent cannot approve (403, audited); audit is fail-closed (write failure → no execution).

**Hardening (defense-in-depth, no reachable boundary violation today):**
- Subject GUI tools to the policy and/or omit a terminal emulator from the desktop image if the exec allowlist is meant to be a hard command-execution boundary (same root idea as the needs_validation GUI lead).
- Bind a desktop-ticket session to its sandbox scope (store a scope on `ui_sessions`; enforce in `screen_principal`/`may_connect`) so a "view one screen" link cannot reach `/ui/*` admin routes — reduces the blast radius of the rejected finding.
- Policy allowlist is labelled "read-only" but includes `mkdir`/`touch`; `_DEVNULL` also over-strips `>/dev/null<suffix>` (currently inert because `/dev` is root-owned). Tighten the allowlist semantics and the regex.
- `same_origin()` fails open when `Origin` is absent (backstopped by `SameSite=Strict`); add a CSRF token or reject state-changing requests lacking both Origin and Referer.
- Audit chain is keyless SHA-256: in-place edits and id-gaps are detected, tail-truncation/rollback are not — anchor the chain head externally (README already notes this). `_mask` ignores JSON keys and space-separated credential forms (`--password x`); `register_secret` silently drops values < 8 chars.
- `mcp_server.py` does not reject a `hum_` token in `AGENTBOX_AGENT_TOKEN` (CLI `cmd_agent` does) — add the same guard so a mis-set MCP config cannot grant self-approval authority.
- Pin `AGENTBOX_RUNTIME=runsc`/`kata` in strong-isolation deployments so startup fails closed instead of silently falling back to runc.
- Disable FastAPI `/docs`,`/redoc`,`/openapi.json` and consider gating `/healthz` in production (non-secret structure disclosure to P0).
- Pin/lock dependencies (currently `>=` ranges, no lockfile) and image digests (floating tags).
- Weak (32-bit) and echoed `hs_` public session id; `put_files` has no per-request file-count cap; approval preview/capture is request-time only (matters only if an operator adds a GUE-tool `require_approval` rule); write_file-overwrite snapshot is check-then-act (narrow concurrency gap).

## 7. Coverage summary

15 ledger units, all reached: **8 covered**, **7 candidate** (policy-injection, policy-access-control, GUI, outbox, source_dir, resource-exhaustion, wildcard), **0 planned/deferred/out-of-scope**. Companions applied: AI-AND-LLM, WEB-PROTOCOL-AND-AUTH, DESKTOP-MOBILE-AND-LOCAL-IPC, RESOURCE-EXHAUSTION, CLOUD-AND-DEPLOYMENT. Excluded with reason: MEMORY-SAFETY-AND-BINARY (no native/unsafe code), CLIENT-SIDE SPA classes (server-rendered Jinja only), PROTOCOLS broker/queue (no broker), SUPPLY-CHAIN CI/release (no CI/release pipeline in-repo), DATA-ISOLATION tenant/export (single-admin, one shared SQLite). Final coverage-critic pass: the parent (acting as inline critic) reopened the two policy units and the GUI unit that the hunters closed as "covered," promoting the quoted-`#` and `>&<digit>` bypasses and the GUI lead to candidates. **This is a first, partial pass** — not a clean-coverage guarantee; the needs_validation leads and a Docker-enabled re-run remain.
