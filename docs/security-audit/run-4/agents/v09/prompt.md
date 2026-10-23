You are candidate verifier `v09` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
 "title": "Agent tool input still reaches the append-only audit log uncapped through approval previews and tool error strings",
 "description": "One agent request can append a permanent audit row whose size is the request body size, roughly 1:1. _logged_args caps only the tool_request and tool_execute copies at 64 KiB, but the same input still reaches audit.append unchanged through two other sinks: the approval_requested payload embeds the preview, which carries the raw exec command (preview.py:131) and one uncapped note per command segment (preview.py:125), and tool_error embeds the raw str(SandboxError), which contains the agent path verbatim (sandbox.py:156). Neither the route nor the shipped Caddyfile bounds the tool-args body. Audit rows are append-only, so every byte is retained; when the disk fills, every audit-writing API call fails closed with 503.",
 "root_cause": "_call_tool caps only the two _logged_args mirrors (service.py:295-296,413-414). The approval_requested payload passes preview through unchanged (service.py:330-333) while _preview copies the raw command and one note per segment, and the SandboxError handler at service.py:360-362 logs str(e) untruncated although safe_path (sandbox.py:156) embeds the agent raw path. audit.append imposes no length bound of its own.",
 "intended_behavior": "Every payload that reaches the append-only audit log is bounded before the insert regardless of the producing call site: error strings, preview command, notes and affected paths are truncated to a fixed budget, note counts are capped, and the tool-args body is rejected above a small limit.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 216,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "Agent-token route; ToolCall.args (api.py:51-52) is parsed from the JSON body with no size limit."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 295,
   "scope": "tool_request record",
   "description": "Records args through the capped _logged_args, then evaluates policy; the capped copy is not the only path the arguments take."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 318,
   "scope": "_preview producer",
   "description": "For exec the whole raw command is copied into preview.command; for an invalid workspace path the safe_path message embeds the raw path as a preview note."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 330,
   "scope": "approval_requested audit append",
   "description": "The payload carries preview minus the capture image, with no truncation of command, notes or affected entries."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 361,
   "scope": "SandboxError handler",
   "description": "The untruncated str(e) is appended as payload.error; read_file and write_file need no approval, so this row is written on the first request."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 183,
   "scope": "AuditLog.append INSERT",
   "description": "json.dumps of the masked payload is inserted into the append-only audit table."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 189,
   "description": "The LOGGED_ARGS_MAX branch exists only inside _logged_args, used by tool_request and tool_execute."
  },
  {
   "file": "agentbox/service.py",
   "line": 332,
   "description": "approval_requested payload includes the preview dict verbatim."
  },
  {
   "file": "agentbox/preview.py",
   "line": 131,
   "description": "preview_command returns the full original command with no length cap."
  },
  {
   "file": "agentbox/preview.py",
   "line": 125,
   "description": "One or more notes per command segment; segment count is unbounded, only affected is truncated."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 156,
   "description": "safe_path raises SandboxError with the raw agent path in the message."
  },
  {
   "file": "agentbox/service.py",
   "line": 361,
   "description": "tool_error payload stores str(e) without truncation."
  },
  {
   "file": "agentbox/api.py",
   "line": 51,
   "description": "ToolCall.args is an unbounded dict; no route-level body limit exists."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 5,
   "description": "Shipped proxy is a bare reverse_proxy with no request body limit."
  },
  {
   "file": "agentbox/audit.py",
   "line": 37,
   "description": "The DELETE trigger makes audit rows undeletable."
  },
  {
   "file": "agentbox/audit.py",
   "line": 183,
   "description": "No size check on the inserted payload."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Any valid agent token for one sandbox; the human token is not needed."
  },
  {
   "kind": "system_configuration",
   "description": "Default policy: delete_file always requires approval, non-allowlisted exec requires approval, while read_file and write_file are allowed, so the tool_error variant needs no approval at all."
  },
  {
   "kind": "user_interaction",
   "description": "None: approval_requested rows are written before any human sees the request."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent sends one oversized tool argument and picks whichever tool gives the largest uncapped echo.",
  "payloads": [
   "POST /sandboxes/sb_x/tools/read_file with a 131072-byte invalid path",
   "POST /sandboxes/sb_x/tools/delete_file with a 262145-byte invalid path",
   "POST /sandboxes/sb_x/tools/exec with a 262145-byte command"
  ],
  "instructions": [
   "Run scratch/h.py inside the approved audit sandbox: real AgentBox, AuditLog, ApprovalStore and Policy on SQLite files under /scratch, with only the Docker-facing SandboxManager faked.",
   "Call box.call_tool with the payloads and read back SELECT id,event,length(payload) FROM audit plus the stored approval row sizes."
  ],
  "observed_result": "tool_request rows stayed at 16543 bytes while approval_requested stored 262343 bytes for the 262145-byte path and 274733 bytes for the exec command; the approval row held 262245 bytes of preview and 262157 bytes of args; read_file wrote a 131145-byte tool_error row with no approval and returned a 131148-byte 400; a 2001-segment command produced 2001 notes."
 },
 "remediation": {
  "strategy": "Bound payloads at the audit sink and at the producers: one recursive bounder inside AuditLog.append (string truncation plus list cap), truncate preview command/notes before the append, replace raw SandboxError text with a short form, and reject oversized tool-args bodies at the route.",
  "code_changes": [
   {
    "file_name": "agentbox/audit.py",
    "fixed_code": "AUDIT_STR_MAX = 4096\nAUDIT_LIST_MAX = 200\n\ndef _bound(v):\n    if isinstance(v, str):\n        return v if len(v) <= AUDIT_STR_MAX else v[:AUDIT_STR_MAX] + f\"...({len(v)} bytes)\"\n    if isinstance(v, dict):\n        return {k: _bound(x) for k, x in list(v.items())[:AUDIT_LIST_MAX]}\n    if isinstance(v, list):\n        return [_bound(x) for x in v[:AUDIT_LIST_MAX]]\n    return v\n\npayload = _bound(self._mask(payload or {}))"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "One authenticated agent request per row; the read_file variant needs no approval, snapshot or concurrency, and the row size equals the body size."
  },
  "impact": {
   "score": "medium",
   "reason": "Permanent undeletable growth of the shared SQLite file; at disk-full every audit-writing call fails closed with 503, stopping tools, approvals and lifecycle actions, and recovery needs an operator to rebuild the database."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Row sizes measured through the real AuditLog, ApprovalStore and Policy with only the Docker-facing SandboxManager faked; the two surviving sinks are unmodified code paths the fix did not touch."
 },
 "x_proposed_by": "h-queue"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "container%20output%20and%20agent%20request%20bodies%20%28tool%20args%2C%20uploads%29::agentbox%2Fsandbox.py%23_Head%20exec%20cap%20%2B%20read%2Foutbox%2Fmanifest%2Fscreenshot%20caps%20%2B%20agentbox%2Fservice.py%23_logged_args%20cap::agentbox%2Fsandbox.py%20%2B%20agentbox%2Fsandbox_common.py%20%2B%20agentbox%2Fservice.py::RESOURCE-EXHAUSTION-AND-AVAILABILITY.md%23Unbounded%20buffering%20and%20cardinality",
  "surface": "container output and agent request bodies (tool args, uploads)",
  "boundary": "agentbox/sandbox.py#_Head exec cap + read/outbox/manifest/screenshot caps + agentbox/service.py#_logged_args cap",
  "local_checks": [
   {
    "agent_id": "h-queue",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/preview.py",
     "agentbox/sandbox.py",
     "agentbox/audit.py"
    ],
    "invariant": "No audit payload built from agent input exceeds a fixed byte budget.",
    "method": "local",
    "result": "Fails. _logged_args itself holds (3 MiB command -> 16534-byte blob; tool_request for a 262145-byte argument -> 16543 B), but delete_file with a 262145-byte invalid path produced an approval_requested row of 262343 B, exec with a 262145-byte command produced 274733 B, and read_file with a 131072-byte invalid path (no approval needed) wrote a 131145-byte tool_error row and returned a 131148-byte 400. The approval row stored 262245 B preview and 262157 B args. A 2001-segment command produced 2001 preview notes while affected is capped at 200.",
    "artifact": "agents/h-queue/artifacts/h.out"
   },
   {
    "agent_id": "h-queue",
    "reviewed_paths": [
     "agentbox/sandbox.py",
     "agentbox/sandbox_desktop.py",
     "agentbox/sandbox_common.py",
     "agentbox/api.py",
     "deploy/Caddyfile"
    ],
    "invariant": "Every reader of container-controlled output applies the _Head byte cap or a container-side head -c plus timeout, and the HTTP layer bounds the tool-args body.",
    "method": "source",
    "result": "Only exec/read_file/outbox_read/workspace_manifest are capped (sandbox.py:413-421,441,545,376-378). list_dir (428), outbox_list (534), preview _expand (560) and screenshot (sandbox_desktop.py:86-88) read the whole stream: locally an 8 MiB fake stream was accepted by screenshot (returned an 8388616-byte png, base64 11184824 B) and by list_dir (65556-char listing after truncation). ToolCall.args is an unbounded dict (api.py:51-52) and deploy/Caddyfile has no request_body limit. Real growth happens in the Docker SDK stream reader, which the sandbox cannot exercise.",
    "artifact": null
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint (run-3 wording)

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
 "title": "Prompt-injected agent writes unbounded, undeletable rows into the shared audit log via uncapped tool-call args",
 "description": "The agent token (lowest-trust principal, assumed prompt-injected) controls the free-form args dict of every tool call. service._call_tool writes an event=tool_request audit row with payload {\"args\": _logged_args(tool, args)} as its very first action, before policy.decide, so even denied or approval-requiring calls still persist the row. _logged_args only special-cases write_file content (replacing it with size+sha256); for every other tool and every other key the args pass through verbatim. No size cap exists at any layer: FastAPI/Starlette/uvicorn impose no default request-body limit, ToolCall.args is an unconstrained dict[str, Any], Settings has read/write/upload caps but no args/body cap, the shipped Caddy reverse_proxy has no request_body max_size, and audit.append serializes and INSERTs the payload with no size check. One request therefore persists an arbitrarily large row into the shared, append-only control-plane SQLite audit DB (a single DB for all sandboxes, on host disk). UPDATE/DELETE are blocked by triggers, so the operator cannot prune oversized rows without rebuilding the DB and destroying the hash chain. audit.verify() loads every row and rehashes each full payload, and /ui/verify calls audit.list(limit=100000), so one agent can permanently bloat the shared audit store and make the operator's own audit/verify tooling slow and memory-heavy for the life of the DB.",
 "root_cause": "_logged_args (service.py:131-137) returns agent args unchanged except write_file content, and _call_tool (service.py:297-298) persists them via audit.append before any policy decision; neither the HTTP layer (api.py:50-51,206-211), configuration (config.py:54-57), shipped proxy (deploy/Caddyfile:5) nor audit.append (audit.py:143-187) bounds the serialized payload; the append-only triggers (audit.py:35-38) make the oversized rows unrecoverable.",
 "intended_behavior": "Agent-supplied tool arguments recorded for audit are bounded in serialized size (as write_file content already is), so one lowest-trust request cannot persist an arbitrarily large, undeletable row into the shared audit DB or amplify the operator's verify/list path.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 206,
   "scope": "call_tool(sid, tool, body: ToolCall)",
   "description": "Agent POSTs /sandboxes/{sid}/tools/{tool}; body.args is an unconstrained dict[str, Any] (api.py:50-51) passed straight to box.call_tool with actor=p.kind; no request-body or args size limit."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 297,
   "scope": "AgentBox._call_tool",
   "description": "First action in the tool path: audit.append(event='tool_request', payload={'args': _logged_args(tool, args)}), executed before policy.decide (line 299), so the row persists even for calls that are later denied or sent to approval."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 131,
   "scope": "AgentBox._logged_args",
   "description": "Static method returns the args dict unchanged for every tool except write_file; only write_file 'content' is replaced with content_bytes+content_sha256. All other keys/tools (e.g. a 3 MiB 'junk' value on read_file) pass through verbatim."
  },
  {
   "kind": "propagation",
   "file": "agentbox/audit.py",
   "line": 153,
   "scope": "AuditLog.append",
   "description": "payload = self._mask(payload or {}); _mask recurses over the dict and json.dumps serializes it with no size check before the INSERT."
  },
  {
   "kind": "sink",
   "file": "agentbox/audit.py",
   "line": 176,
   "scope": "AuditLog.append INSERT",
   "description": "The full json.dumps(payload) is persisted into the append-only audit table; verify() (audit.py:208-233) and list(limit=100000) (web.py:270) later re-load and rehash every full row."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/service.py",
   "line": 133,
   "description": "Only the write_file 'content' key is special-cased; every other tool/key is returned unchanged."
  },
  {
   "file": "agentbox/service.py",
   "line": 297,
   "description": "tool_request row appended as the first action, before policy.decide at line 299."
  },
  {
   "file": "agentbox/audit.py",
   "line": 176,
   "description": "INSERT persists json.dumps(payload) with no size cap."
  },
  {
   "file": "agentbox/audit.py",
   "line": 36,
   "description": "audit_no_update / audit_no_delete triggers (RAISE ABORT 'audit log is append-only') make oversized rows unprunable."
  },
  {
   "file": "agentbox/audit.py",
   "line": 210,
   "description": "verify() selects all rows ORDER BY id and rehashes each full payload."
  },
  {
   "file": "agentbox/web.py",
   "line": 270,
   "description": "/ui/verify calls box.audit.list(sandbox_id=..., limit=100000), re-loading up to 100k full payloads."
  },
  {
   "file": "agentbox/config.py",
   "line": 54,
   "description": "Settings defines max_read_bytes/max_write_bytes/max_upload_bytes but no args/request-body cap."
  },
  {
   "file": "deploy/Caddyfile",
   "line": 5,
   "description": "Shipped behind-proxy deployment uses a bare 'reverse_proxy agentbox:8765' with no request_body max_size."
  },
  {
   "file": "agentbox/api.py",
   "line": 50,
   "description": "ToolCall.args: dict[str, Any] = {} is unconstrained; passed to box.call_tool (api.py:210) with no body limit."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "Valid agent token for its own sandbox (lowest-trust network principal; threat model assumes a prompt-injected agent)."
  },
  {
   "kind": "data_state",
   "description": "Each request appends one unprunable row sized to the body; recovery requires rebuilding the DB and losing the hash chain, since UPDATE/DELETE are trigger-blocked."
  },
  {
   "kind": "system_configuration",
   "description": "Both the default local serve and the shipped behind-proxy Caddy deployment lack a body cap; an operator-added body cap would reduce per-row magnitude but not cross-request accumulation."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent adds a large junk field to tool args it already controls; the control plane records the full args into the shared append-only audit DB permanently and re-reads them on every operator verify/list.",
  "payloads": [
   "POST /sandboxes/{sid}/tools/read_file  body {\"args\": {\"path\": \"/workspace/x\", \"junk\": \"<3 MiB of 'A'>\"}}",
   "Repeat with list_dir, exec, key, type, etc. (any non-write_file tool, or any non-'content' key)."
  ],
  "instructions": [
   "In the OS-enforced sandbox (sbx v08: /usr/bin/python3.13, /target read-only on sys.path, /scratch writable, no network, no Docker, uid 65534, 512 MiB, 1 CPU), reproduce service._logged_args verbatim and confirm a non-write_file args dict with a 3 MiB junk value is returned unchanged while write_file content is stripped.",
   "Open agentbox.audit.AuditLog on a scratch DB and append actor='agent', event='tool_request', tool='read_file', payload={'args': logged_args(...)} with the 3 MiB junk; measure length(payload) of the stored row.",
   "Append 3 more rows with junk; sum length(payload).",
   "Attempt DELETE and UPDATE on a row; observe the append-only triggers.",
   "Call verify() and list(limit=100000)."
  ],
  "observed_result": "logged_args kept the 3,145,728-byte junk key unchanged (write_file content was stripped); the stored row's payload was 3,145,774 bytes; 4 rows totalled 12,583,024 bytes; both DELETE and UPDATE raised sqlite3.IntegrityError 'audit log is append-only'; verify() returned ok=True after re-checking all 4 rows; list(limit=100000) returned all 4 rows with the full 3 MiB payload intact. Independently reproduced in sbx v08 (/scratch DB); see agents/v08/artifacts/repro_v08.out (consistent with the hunter's agents/h-buffer/artifacts/audit_cap.out)."
 },
 "remediation": {
  "strategy": "Bound the serialized size of the agent-supplied args that reach the audit log, after the existing write_file content strip and for every tool, so the cap cannot be sidestepped by combining write_file content with an extra large key. When the json-serialized args exceed a fixed limit, store a byte count, sha256 and a truncated head. Keep content_bytes and content_sha256 in the truncated form, since the approval preview uses them. The same _logged_args also feeds the approval payload (service.py:167 and :408), so the fix covers those rows too. Add a request-body/args size limit on the tool endpoint (and a request_body max_size in the shipped Caddyfile) as defense in depth.",
  "code_changes": [
   {
    "file_name": "agentbox/service.py",
    "fixed_code": "# add `import json` at the top of the module\nLOGGED_ARGS_MAX = 64 * 1024    # args kept verbatim in the audit log (JSON bytes)\nLOGGED_ARGS_HEAD = 16 * 1024   # head kept when exceeded\n\n@staticmethod\ndef _logged_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:\n    if tool == \"write_file\" and \"content\" in args:\n        data = str(args.get(\"content\", \"\")).encode(\"utf-8\")\n        args = {k: v for k, v in args.items() if k != \"content\"} | {\n            \"content_bytes\": len(data), \"content_sha256\": hashlib.sha256(data).hexdigest()}\n    # the size cap applies to the result of the write_file strip too, so write_file + small content + huge extra key is also bounded\n    blob = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str).encode(\"utf-8\")\n    if len(blob) <= LOGGED_ARGS_MAX:\n        return args\n    kept = {k: args[k] for k in (\"content_bytes\", \"content_sha256\") if k in args}\n    return kept | {\"args_truncated\": True, \"args_bytes\": len(blob),\n                   \"args_sha256\": hashlib.sha256(blob).hexdigest(),\n                   \"args_head\": blob[:LOGGED_ARGS_HEAD].decode(\"utf-8\", errors=\"replace\")}"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "high",
   "reason": "The agent controls the args dict in normal operation; adding a large field is trivial with its own token and requires no special conditions."
  },
  "impact": {
   "score": "medium",
   "reason": "Persistent, unprunable growth of the shared append-only audit DB (single DB for all sandboxes, on host disk) plus memory/CPU amplification on every operator verify()/ui-verify list(100000); recovery requires rebuilding the DB and losing the hash chain. Not RCE or a guaranteed crash."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Every layer read from source: uncapped pass-through in _logged_args, pre-decision persistence, absence of any HTTP/config/proxy/audit body or row cap, append-only triggers, and full re-read in verify/list all confirmed. Uncapped persistence, trigger-blocked DELETE/UPDATE, and full re-read independently reproduced in the sandbox (repro_v08.out)."
 }
}
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

<!-- RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#File descriptor, handle, and temporary-resource leaks -->
**File descriptor, handle, and temporary-resource leaks**
Malformed or canceled work misses cleanup and retains sockets, files, database cursors, timers, subprocesses, temporary files, or object references. Confirm the leak repeats through bounded local iterations and affects a shared pool.

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

- Agent ID `v09`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v09/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v09 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v09 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
