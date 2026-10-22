# agentbox — needs-validation leads (run-1)

Source-grounded candidates whose decisive fact was not resolvable from source plus the bounded pure-function harness (no OS-enforced sandbox / Docker available this run). These are **prioritized leads without severity** — not confirmed vulnerabilities. Each gives the source trace, the exact blocker, and a safe bounded-local or owner-observed resolution. Do not turn any of these into live-probe traffic against a shared or production system.

---

## N-1 GUI tools → uid 1001 terminal execution, bypassing the exec allowlist/approval/snapshot
**Fingerprint:** `agentbox/sandbox.py:gui-tools-uid1001-terminal-bypasses-exec-allowlist`

- **Trace.** `agentbox/service.py:94` (GUI branch, default-allowed) → `agentbox/sandbox.py:568` (`xdotool type … as uid 1001`) → `images/desktop/Dockerfile:19` (`xfce4-terminal` installed).
- **Claimed root cause.** GUI tools (`screenshot/click/type/key`) have no policy rule and fall to `default: allow`; they run as the desktop user (uid 1001, in group `agent`, with write access to the setgid group-writable `/workspace`). If a terminal can be focused and driven, the agent executes arbitrary commands outside the exec allowlist, the approval queue, and the snapshot-before-delete protection. Such processes also survive a human takeover (the 423 gate blocks only *new* GUI tool calls).
- **Blockers.** (1) Terminal reachability is a runtime/image UI fact: `agentbox-desktop-start` launches `startxfce4` but auto-starts no application, so reaching a terminal depends on the shipped Xfce session's menu/launcher/keybindings and on-screen coordinates — none pinned in-repo. (2) Confirming the uid-1001 process writes/deletes `/workspace` with no approval card and no AP-2 snapshot needs the live Docker desktop sandbox.
- **Local plan.** In an OS sandbox with the `agentbox-desktop` image, create a desktop sandbox and, using only GUI tools (`screenshot` to read layout, `click`/`key` to open `xfce4-terminal`), run a marker that creates and deletes a dummy `/workspace` file; observe absence of an approval card and of any snapshot event, and survival across a takeover.
- **Deployment plan.** Owner confirms whether the deployed desktop image's Xfce session exposes any launcher/keybinding that starts a terminal (or any command-executing app) reachable via `type`/`key`, and whether GUI tools are intended to be a hard command-execution boundary.

## N-2 exec stdout fully buffered in control-plane memory before the 64 KB cap
**Fingerprint:** `agentbox/sandbox.py:exec-output-buffered-unbounded-before-truncate`

- **Trace.** `agentbox/api.py:188` → `agentbox/service.py:85` → `agentbox/sandbox.py:379-385` (`exec_run(demux=True)`, non-streaming) → cap only afterward at `:93-98`.
- **Claimed root cause.** `_OUT_LIMIT`/`_truncate` apply only *after* docker-py's non-streaming `exec_run` concatenates every stdout frame into control-plane memory; `timeout -k 5 60` bounds time, not bytes, and `mem_limit` is a container cgroup, not a control-plane bound. An allowlisted producer (`cat /dev/zero`, `head -c … /dev/zero`, `tr '\0' a < /dev/zero`) runs unapproved (confirmed by the pure-function harness) and streams into the single shared, fail-closed control-plane process.
- **Blockers.** (1) The decisive OOM/outage can only be observed by running a live producer against a real daemon and watching RSS. (2) Real per-second socket throughput × the 60 s timeout determines whether enough accumulates. (3) Whether a deployment memory bound (systemd `MemoryMax`, a service cgroup, a ulimit) or an auto-restart limits the blast radius.
- **Local plan.** Under a cgroup memory limit, stream a high-rate stdout producer through the exec path and watch control-plane RSS climb toward the limit within the timeout.
- **Deployment plan.** On an owner-run isolated instance, invoke exec once with a large stdout producer under the 60 s timeout and watch `/proc/<pid>/status` RSS; confirm any configured memory bound.

## N-3 Unbounded `docker commit` snapshots (host-disk exhaustion)
**Fingerprint:** `agentbox/sandbox.py:auto-snapshot-unbounded-no-gc`

- **Trace.** `agentbox/api.py:188` → `agentbox/service.py:220` (`_needs_snapshot` True for an existing `write_file` target, ALLOW with no approval) → `agentbox/sandbox.py:341` (`c.commit`) ; `delete` removes only the container (`:312`), leaving snapshot images.
- **Claimed root cause.** Each overwrite of an existing file (and each `delete_file`) forces an unconditional `docker commit` with no snapshot count/size cap and no image GC; `write_file` is default-allowed, so the agent can drive commits with no human in the loop.
- **Blockers.** (1) Actual image accumulation / host-disk exhaustion needs commits against a live daemon. (2) Whether the deployment runs an external image reaper (`docker image prune` cron). (3) Per-commit footprint (new layers vs shared storage) and how fast N commits approach the disk.
- **Local plan.** Pure-function harness already confirms `write_file` → allow and `delete_file` → require_approval; the disk-growth step needs a daemon.
- **Deployment plan.** On an owner-run isolated instance, `write_file` the same existing path N≈200 times via the agent token; observe `agentbox-snap:*` image count/size growth and whether anything reaps them.

## N-4 Unconstrained `source_dir` → arbitrary host-file disclosure into agent-readable `/workspace`
**Fingerprint:** `agentbox/sandbox.py:create:source_dir-no-allowlist-arbitrary-host-copy`

- **Trace.** `agentbox/web.py:150` (UI create takes `source_dir`) → `agentbox/service.py:309` → `agentbox/sandbox.py:272` (resolve, no allowlist) → `agentbox/sandbox.py:290` (`cp -a /source/. /workspace/` as root with DAC_OVERRIDE, then `chown` to uid 1000).
- **Claimed root cause.** `create()` applies no allowlist/containment to the create-supplied `source_dir` before bind-mounting it read-only and root-copying it into the agent-readable `/workspace`. If the operator points it at a sensitive host path (e.g. `AGENTBOX_HOME`), root `cp -a` with DAC_OVERRIDE can read 0600 host files (such as `human_token`) and lay them down owned by the agent.
- **Blockers.** (1) Whether, under the deployed runtime (`_RUNTIME_PREFERENCE` kata-fc/runsc/runc) and compose setup (root control plane, host `docker.sock`, no userns remap), the container uid 0 is host-root-equivalent so `cp -a` actually reads host root-owned 0600 files through the read-only `/source` bind. (2) Whether a userns remap / rootless Docker is in effect (would collapse impact to files an unprivileged uid can read). (3) Whether an operator ever points `source_dir` at a sensitive path (README documents the single-admin model with no path allowlist).
- **Local plan.** Reproduce the cp+chown *laundering mechanic* non-destructively in scratch (root creates `src/human_token` 0:0 0600, `cp -a` into a dest, `chown` to an unprivileged uid, confirm it becomes readable) — this shows the mechanic under an *assumed* host-root-equivalence, not that the container attains it.
- **Deployment plan.** In a disposable staging install matching `deploy/docker-compose.yml`, as the human create a sandbox with `source_dir` = the data dir containing a dummy 0600 `human_token`, then have the agent `read_file` it; confirm whether it is readable. Confirm the runtime and userns configuration.

## N-5 Terminal approval screen renders agent-controlled strings without control-char stripping (display spoofing)
**Fingerprint:** `agentbox/cli.py:approval-terminal-escape-spoof`

- **Trace.** `agentbox/mcp_server.py:136` (agent exec request) → `agentbox/service.py:202` (raw `args` stored on the approval) → `agentbox/cli.py:165` (`_show_approval` prints `apr['args']['command']`) and `:174` (prints `item['path']`) between ANSI codes with no neutralization.
- **Claimed root cause.** `cmd_approve`/`_show_approval` print the agent-controlled command and affected paths to the operator's terminal without stripping terminal control sequences, so a crafted command could visually paint a benign-looking line over the real one. (The **web** approval UI is safe — Jinja autoescape.)
- **Blockers.** (1) The decisive harm — the terminal painting a benign command while a different one is stored/executed — depends on the operator using the terminal `approve` flow and on their terminal emulator's escape handling. (2) Whether the independently system-computed "affected" section (which the agent does not control) neutralizes the deception in practice is runtime/policy-dependent.
- **Local plan.** In a scratch dir, build a dummy approval dict and render it through the same print path to observe whether a crafted (non-exploit) escape sequence repaints the visible command; compare against the system-computed affected list.
- **Deployment plan.** Owner-observed on a non-production control plane: have an agent request an exec whose command embeds a benign escape sequence (no working exploit chain), run `agentbox approve`, and observe whether the rendered command differs from the stored one.
