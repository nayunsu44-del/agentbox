# agentbox — architecture & coverage plan (run-1, source-only)

**Source ref.** HEAD `7fc501f`, clean worktree. Profile `standard`, scope `.` (whole repo). No prior runs.

**Execution policy.** No OS-enforced sandbox was provisioned and the Docker daemon is unreachable in this environment (no `/var/run/docker.sock`; target deps `fastapi`/`docker`/`httpx` not importable). Therefore **no target-controlled code is executed**: no `pytest`, `docker`, demo, or target shell. Findings whose decisive proof needs the live Docker sandbox, a runtime, or a deployment fact are recorded `needs_validation` with that exact blocker. Two policy/tokenizer divergences are also checkable by a pure-function harness (import `agentbox/policy.py`, which has no side effects, and a local `bash -c` on dummy files in scratch) without touching the target's Docker sandbox, network, or shared state.

## 1. Product, principals, authority, protected resources
agentbox (MIT, v0.1.0, Python ≥3.11) is a self-hosted control plane giving AI agents isolated Docker sandboxes with human approval and a hash-chained audit log. Principals, lowest-trust first:
- **P0 unauthenticated peer** — `/healthz`, `/static/htmx.min.js`, `/static/novnc/{path}` (triggers `docker create` on cache miss), `GET/POST /login` (no rate limit), ticket redemption, `/` redirects. FastAPI default `/docs`,`/openapi.json` on.
- **P1 agent token** (`agt_`, one per sandbox, sha256-stored) — 9 tools on its own sandbox, read own sandbox record (incl host `source_dir`), read own approval status, read own desktop state. Cannot approve (403, audited), cannot mint tickets.
- **P2 sandbox code uid 1000** — `exec` + file tools run here; `safe_path`/`_workspace_path` are lexical only (no symlink resolution).
- **P3 sandbox `desktop` uid 1001** — GUI tools + x11vnc; in group `agent`; `/workspace` is group-writable+setgid.
- **P4 injected LLM/file content** — drives tool calls; only mitigation is the system prompt; approval is the real control.
- **P5 browser cookie session** — every `screen_human`/`browser_human` route = full UI admin (create/approve/snapshot/restore/delete/upload/takeover).
- **P6 human token** — one shared global token, no per-user identity.
- **P7 control plane** — holds Docker daemon authority (root-equivalent); runs as root in compose.
- **P8 Caddy proxy** — trusted for TLS/Host/`X-Forwarded-*`; `forwarded_allow_ips` defaults `*`.

Protected resources: host (via Docker socket), human token, the approval gate, the audit chain, `/source` read-only original, cross-sandbox isolation, control-plane availability.

## 2. Comparable baseline
No competing agent-sandbox product is named in-repo. Protocol baselines present: MCP (stdio), OpenAI/Anthropic chat APIs, VNC/RFB + noVNC, `docker commit` snapshots, Caddy TLS, a SHA-256 audit chain the README itself says needs an external anchor. Calibration only.

## 3. Tech stack, deployment paths, offline limits
FastAPI + uvicorn + starlette, Jinja2 + HTMX UI, `docker` SDK, one shared SQLite file (`audit`, `approvals`, `sandboxes`/`snapshots`, `ui_tickets`/`ui_sessions`/`takeover_leases`; only `audit` is append-only-triggered + hash-chained). Deployment: plain loopback `serve`; direct TLS; `--behind-tls-proxy`; `docker compose` + Caddy (mounts host `docker.sock`, runs root, `expose` 8765 only). Dependency bounds are lower-only, no lockfile, floating image tags, no CI. Offline-testable today: pure policy/audit/desktop unit logic; API boundaries need Docker or a `SandboxManager`/`docker.from_env` stub.

## 4. Entry surfaces → sinks (important paths)
- Agent tool call → `api.call_tool` → `service.call_tool` (audit `tool_request` → `policy.decide` → deny/approve/execute) → `sandbox.exec` runs `timeout -k 5 T bash -c "umask 002\n"+command` as uid 1000. Policy reads the command with three shlex lexers (`_words`, `simple_programs`, `_split_segments`) configured `commenters=""`; bash honours `#` comments and newlines — a tokenizer/shell divergence surface.
- Approval: preview + screen capture taken **at request time**; on approve an unconditional snapshot then the **stored args** execute with no re-preview and no re-policy — a request-time-vs-execute-time surface.
- Browser: ticket (`tkt_`, 60 s, hashed, single-use, scope sid or `*`) → unscoped 12 h session cookie usable on **all** `/ui/*`. `same_origin` passes when `Origin` absent.
- WebSocket `/desktop/ws`: cookie + origin + mode; view allowed for any session/any sandbox; control needs the 32-bit `hs_` lease; `-viewonly` enforced by x11vnc server-side.
- Files: upload `clean_name` → base64 chunks → `mv -f` as uid 1000 (redirect/`mv` follow symlinks; `exists`/`is_dir` follow symlinks). Outbox `find -printf` parsed with unguarded `int()/float()`. Host `source_dir` bind (no allowlist) copied as root with DAC_OVERRIDE then chowned to uid 1000.
- Container→control-plane trust: `find` outbox list, screenshot PNG, preview glob/`find`, RFB stream, noVNC tar — all container-controlled.

## 5. Trust boundaries & strongest source-visible control
- agent↔control plane: per-sandbox token binding; agent cannot approve (403, audited). **Strong in source.**
- approval gate: policy allowlist + human decision + atomic `claim`; **but** preview≠execution, no re-policy on approve, exec ALLOW path takes no snapshot, GUI/write_file unapproved.
- human-control (takeover): 423 blocks GUI *tools* only, not uid 1001 processes; lease idle never fires while a control WS is open; logout doesn't release the lease or close the WS.
- container isolation: `network=none`, read-only `/source`, `cap_drop ALL`+5 adds, `no-new-privileges`, limits — **enforcement depends on the deployed runtime** (auto-falls back to runc with only a UI warning).
- audit: append-only triggers + unkeyed SHA-256 chain recomputed from genesis; tail-truncation undetected; masking is regex + registered tokens (value-only, known gaps).
- host: Docker socket = root-equivalent; `source_dir` unrestricted.

## 6. Repository-relative starting paths
`agentbox/policy.py`, `agentbox/default_policy.yaml`, `agentbox/service.py`, `agentbox/approvals.py`, `agentbox/sandbox.py`, `agentbox/api.py`, `agentbox/web.py`, `agentbox/desktop.py`, `agentbox/audit.py`, `agentbox/config.py`, `agentbox/cli.py`, `agentbox/agent.py`, `agentbox/mcp_server.py`, `agentbox/templates/*.html`, `images/desktop/*`, `deploy/*`.

## 7. Prior coverage
None. No compatible prior ledger exists; one run does not exhaust the target.

## 8. Companion selection
- `AI-AND-LLM.md` — the product is an LLM/agent tool runner; injected content drives tools; approval is the only control (U15).
- `WEB-PROTOCOL-AND-AUTH.md` — cookies/tickets/sessions, CSRF/origin, reverse-proxy header trust (U5).
- `DESKTOP-MOBILE-AND-LOCAL-IPC.md` — VNC bridge, takeover lease identity, local Docker-exec channel (U6/U7).
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` — container output buffering, FIFO hangs, unbounded snapshots (U12).
- `CLOUD-AND-DEPLOYMENT.md` — runtime fallback, trusted-proxy, docker.sock, image provenance (U13).
Excluded: `MEMORY-SAFETY-AND-BINARY.md` (no native/unsafe target code), `CLIENT-SIDE.md` service-worker/prototype classes (no SPA; only server-rendered Jinja + one inline desktop page — DOM-injection folded into U9/U14), `PROTOCOLS-RPC-AND-MESSAGING.md` broker/queue classes (no broker; the one RFB channel is in U6), `SUPPLY-CHAIN-AND-RELEASE.md` CI/release/signing (no CI, no release pipeline in-repo; dependency-pinning folded into U13), `DATA-ISOLATION-AND-LIFECYCLE.md` tenant/export classes (no multi-tenant store; single shared SQLite, one human principal).
