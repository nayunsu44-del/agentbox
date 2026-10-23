You are candidate verifier `v12` in run-4 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/temp/agentbox-run4/src-audited/` — a git worktree of `main` at commit `9805d91` (after refactor PRs #11-#14). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-4`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "needs_validation",
 "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
 "title": "The approval card still renders U+061C (a Bidi_Control character) and other format/separator characters raw, so a prompt-injected agent can still make the displayed command differ from the executed one",
 "description": "The run-3 fix routes every template output through web._shown -> display.escape_controls (web.py:33-37, 94), and that closes the reported RLO/LRO/PDF/LRI/PDI and LRM/RLM cases: rendering the real _approvals.html with a crafted command turns them into literal escapes while HTML markup is autoescaped. The filter itself is a hand-written character class (display.py:13-21) that misses U+061C ARABIC LETTER MARK - a member of Unicode's Bidi_Control class, the ALM sibling of the LRM/RLM it does cover - together with the format characters U+200B-200D, U+2060, U+FEFF, U+00AD and the separator characters U+2028/U+2029. A prompt-injected agent therefore still chooses characters that the browser's bidi algorithm may use to reorder a command or a container-derived path in the card, and that force a line break inside the same pre block, while the argv that box.decide executes keeps the original bytes. This is a display-integrity failure on the human approval surface, not XSS.",
 "claimed_root_cause": "display.py:13/15 enumerate C0/C1 and the bidi controls by hand and omit U+061C (Bidi_Control=Yes) plus the Cf invisibles U+200B-200D, U+2060, U+FEFF, U+00AD and the line/paragraph separators U+2028-U+2029; web._shown applies that class to every str template output (web.py:35-36), so the residual characters reach the approval card verbatim and the terminal path (cli._safe, cli.py:33-35) has the identical gap.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool} (agent token)",
   "description": "A prompt-injected agent supplies args.command for an exec call; policy.decide sends it to the approval queue and the string is stored verbatim."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 208,
   "scope": "approvals_view",
   "description": "Pending approvals, including the agent's args and the system-computed preview paths, are rendered into _approvals.html."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 94,
   "scope": "tpl.env.finalize = _shown",
   "description": "finalize applies _shown to each output expression, which calls escape_controls(value, keep_newlines=True) for str values only (web.py:33-37)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/templates/_approvals.html",
   "line": 8,
   "scope": "pre block with the agent's command",
   "description": "The single sink that shows the human what will run; only autoescape and the finalize hook apply, and autoescape does not touch format characters."
  },
  {
   "kind": "sink",
   "file": "agentbox/display.py",
   "line": 13,
   "scope": "UNSAFE / _UNSAFE_KEEP_NEWLINES",
   "description": "The regex does not contain U+061C, U+200B-200D, U+2060, U+FEFF, U+00AD or U+2028-U+2029, so those code points are written into the HTML and handed to the renderer unchanged, while the executed argv carries the same bytes."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/display.py",
   "line": 13,
   "description": "UNSAFE covers x00-x1f, x7f-x9f, U+200E/U+200F, U+202A-202E, U+2066-2069; U+061C is absent although it has Bidi_Control=Yes and the same visual-reordering role as the U+200F it replaces."
  },
  {
   "file": "agentbox/display.py",
   "line": 15,
   "description": "The keep_newlines variant used by the web UI omits exactly the same characters, so neither surface filters them."
  },
  {
   "file": "agentbox/web.py",
   "line": 35,
   "description": "_shown returns non-str values unchanged; today every template output is a str or an int, so containers do not reach a sink, but the filter's coverage depends on that."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 14,
   "description": "Container-derived affected paths are rendered in the same card with the same unfiltered character class, so a reordered path is shown to the approver too."
  },
  {
   "file": "agentbox/templates/base.html",
   "line": 23,
   "description": "The pre/pre-wrap styling makes U+2028/U+2029 render as a real line break inside the command box, so one argv can read as two shell lines."
  },
  {
   "file": "agentbox/cli.py",
   "line": 35,
   "description": "cli._safe uses the same escape_controls class, so the terminal approval view agrees with the web view but carries the same omission."
  },
  {
   "file": "docs/security-audit/run-4/agents/h-webui/artifacts/h.out",
   "line": 1,
   "description": "Local render of the real template plus the per-code-point coverage table: U+202E/U+2066/U+200E escaped, U+061C/U+200B/U+2028 present raw in both cells."
  }
 ],
 "blockers": [
  "Renderer behaviour is not observable in the sandbox: sbx has no browser, terminal renderer or network (only fastapi/jinja2/pyyaml plus the repo), so the claimed visual reordering from U+061C and the forced break from U+2028 are unverified; the local check proves only that the code points reach the HTML while the argv keeps the same bytes.",
  "Which browser engine versions and terminal/font stacks the operator actually uses - the fact that decides whether ALM and the separator characters produce a visible difference between the approved view and the executed command."
 ],
 "validation_plan": {
  "local": "Already executed (agents/h-webui/artifacts/h.out): render _approvals.html through web.py's exact Jinja wiring with a command containing U+202E, U+2066, U+200E, U+061C, U+200B, U+2028 and an inline script tag; confirm the first three and the markup are neutralised while U+061C/U+200B/U+2028 stay raw. Next: a loopback browser fixture that renders that fragment beside the intended argv and captures the rendered order (Playwright Chromium/Firefox/WebKit, dummy data). Regression: extend each regex in display.py to the full Bidi_Control and Cf classes (keeping tab/newline in the web variant) and assert escape_controls neutralises U+061C, U+200B and U+2028.",
  "deployment": "Owner opens a real pending exec approval whose command contains U+061C and U+2028 in the operator's browser and terminal and compares the rendered order with the argv shown by agentbox approve; no probing of live endpoints."
 },
 "x_proposed_by": "h-webui"
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "container-controlled%20strings%20rendered%20to%20humans%20%28outbox%20names%2C%20gui_changes%20paths%2C%20ps%20args%2C%20exec%20output%2C%20errors%2C%20approval%20cards%29::agentbox%2Fdisplay.py%23escape_controls%20%2B%20agentbox%2Fweb.py%23describe%2F_shown%2Ffinalize%20%2B%20Jinja%20autoescape%20%2B%20agentbox%2Fcli.py%23_safe::agentbox%2Fdisplay.py%20%2B%20agentbox%2Fweb.py%20%2B%20agentbox%2Fcli.py%20%2B%20agentbox%2Ftemplates::AI-AND-LLM.md%23Insecure%20output%20rendering",
  "surface": "container-controlled strings rendered to humans (outbox names, gui_changes paths, ps args, exec output, errors, approval cards)",
  "boundary": "agentbox/display.py#escape_controls + agentbox/web.py#describe/_shown/finalize + Jinja autoescape + agentbox/cli.py#_safe",
  "local_checks": [
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/templates/_approvals.html",
     "agentbox/web.py",
     "agentbox/display.py"
    ],
    "invariant": "The approval card shows the agent's command and the system-computed paths with every character that can reorder or hide text neutralised.",
    "method": "local",
    "result": "Rendered the real _approvals.html through web.py's exact Jinja wiring (Jinja2Templates + env.finalize = _shown + the short filter) with a command containing U+202E, U+2066, U+200E, U+061C, U+200B, U+2028 and an inline script tag. Output: U+202E/U+2066/U+200E were replaced by their literal backslash-u escapes and the script tag was HTML-escaped (the run-3 RLO/LRI fix works, markup is safe), but U+061C, U+200B and U+2028 survived raw into both the command cell and the affected-path cell.",
    "artifact": "agents/h-webui/artifacts/h.out"
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/display.py",
     "agentbox/cli.py"
    ],
    "invariant": "The shared control-character filter covers every character class that changes how a human reads the same bytes.",
    "method": "source",
    "result": "escape_controls (display.py:13-21) escapes C0/DEL/C1 and the bidi set U+200E/U+200F/U+202A-E/U+2066-2069, identically for the web variant (keep_newlines=True) and cli._safe (keep_newlines=False). It omits U+061C (Unicode Bidi_Control=Yes, the ALM sibling of the LRM/RLM it does cover) and the format/separator characters U+200B-200D, U+2060, U+FEFF, U+00AD, U+2028 and U+2029, so both human surfaces share the same residual gap.",
    "artifact": null
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/cli.py",
     "agentbox/agent.py"
    ],
    "invariant": "Container and model output printed by the CLI agent goes through cli._safe (prior run-3 confirmed record revalidation).",
    "method": "source",
    "result": "cmd_agent.log (cli.py:355-357) now applies _safe line-by-line to 'say', 'call' and 'result', so ToolClient.call_text's raw read_file/list_dir content (agent.py:116-126) is neutralised at the sink; cmd_audit applies _safe to the whole detail (cli.py:293) and _show_approval/cmd_approve do the same for rule text, command lines, affected paths, notes and stderr (cli.py:188-208, 241-248). The run-3 root cause no longer holds. Residual raw prints are server-generated only: cmd_snapshots (cli.py:312), cmd_verify (cli.py:305), _check detail (cli.py:53).",
    "artifact": null
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/templates/base.html",
     "agentbox/templates/_outbox.html",
     "agentbox/templates/_verify.html",
     "agentbox/audit.py"
    ],
    "invariant": "Container-controlled names, counts and paths reach only escaping or plain-text sinks in the remaining templates.",
    "method": "source",
    "result": "No template uses |safe or Markup, and finalize applies to every output expression. The outbox file name (container-controlled) is autoescaped in text, in the download attribute and in data-text, and data-text is consumed by new Notification(body) and dataset reads (base.html:69-76), which are plain-text sinks; _outbox.html:7 urlencodes the name in the href. _verify.html:4 interpolates only an int (audit.py:100 broken_at: int | None) into a script block.",
    "artifact": null
   },
   {
    "agent_id": "h-webui",
    "reviewed_paths": [
     "agentbox/desktop.py",
     "agentbox/sandbox.py",
     "agentbox/api.py"
    ],
    "invariant": "The desktop page's string-replacement HTML build cannot be injected through the sandbox id or runtime name.",
    "method": "source",
    "result": "desktop.page (desktop.py:356-358) substitutes __SID__/__RUNTIME__ into PAGE with no escaping, including inside a script block (desktop.py:309,317), but the id is always 'sb_' + secrets.token_hex(4) (sandbox.py:273), the page is only served for an existing sandbox row with a valid session scope (api.py:319-323), and runtime comes from Settings. No attacker-controlled string reaches that replacement.",
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
 "fingerprint": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
 "title": "Web exec approval card renders the agent's command with raw Unicode bidi controls, letting a prompt-injected agent spoof the human approver's view of what will run",
 "description": "The web approval card shows the agent-submitted exec command in <pre>{{ a.args.command }}</pre> under Jinja HTML autoescape only (markupsafe.escape only touches & < > ' \"). Unicode bidirectional controls (U+202A-E, U+2066-9) survive escaping and are rendered live by the browser, which reorders the displayed text. The terminal approver (cli.py _show_approval) prints the same command through cli._safe, which turns those code points into visible \\uXXXX escapes, so only the web approval path is affected. For non-allowlisted programs (sh/python3) the policy requires approval and the system preview computes no affected paths (sandbox.preview only handles rm/curl segments), adding a note that directs the approver to read the command text itself. A prompt-injected agent (lowest-trust agent token, assumed in the threat model) can therefore submit a Trojan-Source-laid-out command whose rendered form on the web card reads as a single benign echo while a separate approval-gated program actually executes, defeating the human's exec-approval review.",
 "root_cause": "_approvals.html:8 relies on HTML autoescape, which neutralises markup but not Unicode bidi/control characters; the web UI has no equivalent of cli._safe (cli.py:34-39) for approval args, and base.html:23's pre style applies no unicode-bidi isolation. The terminal path escapes these characters (cli.py:196-199) but the web path does not, so the two human-facing surfaces disagree about the same command.",
 "intended_behavior": "Both human approval surfaces should show the agent-chosen command with display-reordering and control characters neutralised, so the approver's decision is bound to the exact command that will execute. The code already does this for the terminal approver via cli._safe; the web card should apply the same neutralisation.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 205,
   "scope": "call_tool (POST /sandboxes/{sid}/tools/{tool}, tool=exec)",
   "description": "Lowest-trust agent token submits args.command containing bidi isolate controls (U+2067/U+2069)."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 322,
   "scope": "call_tool REQUIRE_APPROVAL branch",
   "description": "Approval created with the agent's original args and a preview; for python3/sh the preview lists no affected paths and tells the approver to check the command text."
  },
  {
   "kind": "propagation",
   "file": "agentbox/web.py",
   "line": 196,
   "scope": "approvals_view",
   "description": "Pending approvals (original args) passed to _approvals.html for the web approver."
  },
  {
   "kind": "sink",
   "file": "agentbox/templates/_approvals.html",
   "line": 8,
   "scope": "exec approval card",
   "description": "<pre>{{ a.args.command }}</pre> renders the command with autoescape only; raw bidi controls reach the browser next to the 승인 (approve) button at line 19."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/cli.py",
   "line": 34,
   "description": "_UNSAFE regex explicitly includes U+200E/F, U+202A-E, U+2066-9 as display-integrity controls that the terminal approver must neutralise."
  },
  {
   "file": "agentbox/cli.py",
   "line": 199,
   "description": "_show_approval prints each command line via _safe(line), so the terminal approver sees \\u2067/\\u2069 escapes, not active controls -- establishing the web-vs-terminal asymmetry."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 8,
   "description": "Command rendered with HTML autoescape only; bidi controls are not among the characters markupsafe.escape replaces, so they survive into the DOM."
  },
  {
   "file": "agentbox/templates/base.html",
   "line": 23,
   "description": "pre style sets white-space/word-break but no unicode-bidi isolation, so the browser applies the embedded bidi controls."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 872,
   "description": "preview computes affected paths only for rm/curl segments; for an echo/python3 command it adds no affected entries and notes the approver must confirm the command text -- which is the spoofed display."
  },
  {
   "file": "docs/security-audit/run-3/agents/parent-live/artifacts/l3/l5.out",
   "line": 1,
   "description": "Parent-live real-Chromium innerText retains raw U+2067/U+2069; companion screenshot l5_card.png renders the command as a single benign-looking echo with python3 /workspace/job.py pulled inside the quoted string."
  },
  {
   "file": "docs/security-audit/run-3/agents/v13/artifacts/bidi_check.out",
   "line": 3,
   "description": "Local sbx reproduction: HTML-escaping the payload leaves U+2067/U+2069 intact while cli._safe converts them to visible escapes."
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "Attacker is a prompt-injected per-sandbox agent token (agt_), the lowest-trust network principal, acting on its own sandbox."
  },
  {
   "kind": "user_interaction",
   "description": "A human reviews and approves the exec via the web UI approval card; the terminal approver (cli.py) escapes the bidi controls and is not affected, and the approver must not notice the reordered rendering."
  },
  {
   "kind": "system_configuration",
   "description": "The command uses a non-allowlisted program (e.g. python3/sh) so policy.decide routes it to approval, and sandbox.preview lists no affected paths, leaving the command text as the sole decision basis."
  }
 ],
 "execution": {
  "attacker_perspective": "A prompt-injected agent wants to run an arbitrary approval-gated program (python3/sh) that the human would refuse if shown the real command, so it lays the command out Trojan-Source style so the web card renders it as a harmless echo.",
  "payloads": [
   "echo 'summary done ⁧' ; python3 /workspace/job.py ; echo '⁩'"
  ],
  "instructions": [
   "As the agent, write /workspace/job.py, then POST /sandboxes/{sid}/tools/exec with args.command set to the payload above (RLI U+2067 inside the first echo's quotes, PDI U+2069 inside the last echo's quotes).",
   "python3 is not in the policy allowlist, so service.call_tool creates a pending approval; the preview adds no affected paths and a note to check the command text.",
   "The human opens the web UI approval card (/ui/approvals); _approvals.html:8 renders <pre>{{ a.args.command }}</pre> with the bidi controls active.",
   "Observe the browser rendering versus the logical command (and versus the terminal approver's escaped rendering)."
  ],
  "observed_result": "Parent-live Chromium (l5_card.png) renders the command as a single line `echo 'summary done python3 /workspace/job.py ; echo ; '` -- the separate `; python3 /workspace/job.py ;` command is visually pulled inside the first echo's quoted string, so the card reads as one benign echo while python3 /workspace/job.py is what actually executes on approval. innerText (l5.out) confirms the raw U+2067/U+2069 survive. My own sbx check (bidi_check.out) confirms HTML escaping leaves the bidi controls intact whereas cli._safe escapes them. Decisive browser rendering was reproduced by the parent (real Chromium), not by me; my local reproduction covers only the escape-survival step."
 },
 "remediation": {
  "strategy": "Neutralise display-reordering and control characters on every container/agent-controlled string shown to a human in the web UI, matching the terminal cli._safe behaviour. Add a Jinja filter that maps C0/C1/DEL and bidi controls (the cli._UNSAFE set) to visible escapes, and apply it to the exec command, preview effect/path cells, and describe() output on the approval and audit templates; optionally also wrap the <pre> in CSS unicode-bidi: isolate/plaintext as defence in depth. A regression test should assert the rendered HTML for a bidi-laden command contains no raw U+202A-E/U+2066-9.",
  "code_changes": [
   {
    "file_name": "agentbox/web.py",
    "fixed_code": "import re as _re\n_UNSAFE = _re.compile(\"[\\x00-\\x1f\\x7f-\\x9f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]\")\n\ndef _safe_display(s):\n    return _UNSAFE.sub(lambda m: f\"\\\\x{ord(m[0]):02x}\" if ord(m[0]) < 0x100 else f\"\\\\u{ord(m[0]):04x}\", str(s))\n\n# in register(): tpl.env.filters[\"safe_display\"] = _safe_display"
   },
   {
    "file_name": "agentbox/templates/_approvals.html",
    "fixed_code": "    <div>실제로 실행될 명령 <span class=\"mut\">(작업 폴더 {{ a.preview.cwd | safe_display }})</span>:</div><pre>{{ a.args.command | safe_display }}</pre>"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "The threat model assumes a prompt-injected agent, and embedding bidi isolates in an exec command is trivial. It requires the human to approve via the web UI (the terminal path escapes the controls) and to not notice the reordered rendering, which bounds likelihood below high."
  },
  "impact": {
   "score": "medium",
   "reason": "Defeats the human exec-approval boundary (the primary control between a prompt-injected agent and arbitrary non-allowlisted exec) via display spoofing, yielding agent-chosen arbitrary in-sandbox code execution (python3/sh) under the human's misdirected approval. Contained by the sandbox isolation (network=none, dropped caps, no-new-privileges, runc); it is not by itself a host, cross-sandbox, or human-token compromise."
  },
  "overall_severity": "medium"
 },
 "confidence": {
  "score": "high",
  "reason": "Source establishes the asymmetry end to end: cli._safe escapes the bidi set (cli.py:34, 196-199) while _approvals.html:8 autoescapes only (base.html:23 adds no isolation), and sandbox.preview lists nothing for python3/sh so the command text is the sole basis. The parent's real Chromium reproduction (l5_card.png / l5.out) demonstrates the concrete visual spoof, and my own sbx check confirms escaping preserves the controls. Both candidate blockers are resolved; the only part I could not run myself is the browser render, which the parent supplied."
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

<!-- AI-AND-LLM.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- Prompt injection alone is not a finding. Require a code-level boundary failure: content reaches another principal's context, invokes authority the requester lacks, discloses data they cannot read, or drives a sink they cannot reach directly.
- Model output, memory, tool descriptions, and MCP responses are untrusted inputs. Point to the code that grants authority, trusts output, writes durable state, or feeds a sink.
- A guardrail prompt is not a security boundary. Count only deterministic checks, resource-scoped authorization, isolation, binding, and constrained credentials.
- State the attacker, affected principal, effective execution identity, resource, exact action, authority used, and observable impact. An intentional direct request to use the requester's existing authority is not a delegation defect merely because a model executes it.
- Authorization and action binding are separate controls. Attacker-controlled content that causes an action under an affected principal's valid authority is an action-binding failure when that principal did not intentionally request or approve the exact action.
- Classify every candidate as `confirmed` only after source evidence and bounded local validation establish the boundary and result. Use `needs_validation` when a required provider, deployment, model, renderer, or identity behavior is not observable locally.
```

<!-- AI-AND-LLM.md#Insecure output rendering -->
**Insecure output rendering**
Model output reaches an executing HTML, Markdown, template, URL, or command sink without the sink's required encoding and policy. For browser rendering, verify auto-loaded resources and CSP or sanitization in `CLIENT-SIDE.md`; renderer behavior outside the repository makes the candidate `needs_validation`.

<!-- AI-AND-LLM.md#Universal moves -->
## Universal moves (apply across the above)

- Draw four maps first: each execution identity, each capability, every writable context or memory source, and each output destination. Then connect the principal at the start to the authority at the end.
- Start at side-effecting tools and work backward through dispatcher, schema, confirmation, model context, retrieval, and ingestion. Start at durable memory reads and trace every writer.
- Compare direct, queued, retry, resume, batch, and delegated paths for the same action. The strongest gate must apply after arguments are final and before every side effect.

<!-- AI-AND-LLM.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Name the crossed boundary and observable result: attacker, affected principal or shared resource, execution identity, target, and unauthorized or unrequested action or disclosure.
2. For confused-deputy authority claims, prove the tool lacks requester-and-resource authorization and that the attacker cannot perform the same action normally. For action-binding claims, instead prove attacker-controlled content caused an action under the affected principal's authority that the principal did not intentionally request or approve. Valid generic authorization does not establish that intent.
3. For memory or retrieval claims, cite both the attacker-controlled write and the later cross-principal read or privileged decision. A shared record without a reachable consumer is not enough.
4. For action binding, establish the intentional request or normalized approved object, if any, and compare it with the object the handler uses. Confirm a locally observable unrequested action, mutation, duplicate, or authority change without extending the test into harmful execution. For schema disagreement, compare the normalized validated object with the handler's object.
5. For MCP identity claims, verify the authenticated connection, request correlation, tool namespace, and effective credential. Mark `needs_validation` if external server identity or deployment routing is required.
6. Return `confirmed` findings only with a complete source trace and meaningful result. Return `needs_validation` for a specific unresolved boundary fact and state the bounded local or owner-observed check needed to resolve it.

<!-- CLIENT-SIDE.md#Core discipline -->
## Core discipline (include in every agent prompt for this domain)

```
- A client-side candidate needs a controllable source and an executing or disclosing sink. Name both and show attacker-influenced data reaching the sink.
- The impact must reach a victim's session, another origin, or shared persistence. Self-injection and disclosure of the attacker's own data are not findings.
- Framework escaping, browser same-origin policy, CSP, COOP/CORP, service-worker scope, and modern noopener defaults are real controls. Verify them before assigning impact.
- Browser storage and caches are shared by origin and may outlive login state. Identify who writes, who reads, and which account, tenant, or worker lifecycle clears each record.
- Use `confirmed` only for complete source evidence plus bounded local browser tests. Use `needs_validation` when renderer, extension permission, deployed header, or browser-policy behavior is required but unavailable.
```

<!-- CLIENT-SIDE.md#DOM-based XSS -->
**DOM-based XSS**
Trace `location` fields, `document.referrer`, `window.name`, message data, storage, and browser-controlled document state into `innerHTML`, `outerHTML`, `document.write`, string-evaluating APIs, executable URLs, jQuery HTML APIs, or framework escape hatches. Interpolation escaped by the framework is not a finding.

<!-- CLIENT-SIDE.md#Universal moves -->
## Universal moves (apply across the above)

- Start from DOM, navigation, worker, message, and storage sinks, then trace backward to browser-only and server-controlled sources. Record the browser policy that should stop the path.
- Test account switch, logout, worker update, offline fallback, and stale-tab state with a local test origin and dummy accounts. Do not use production users, origins, or shared services.
- For XS-Leaks, list only predicates proved by source and local browser behavior. Then identify the response headers or rendering choice that would remove the oracle.

<!-- CLIENT-SIDE.md#Validation rules -->
## Validation rules (apply before reporting ANY finding here)

1. Cite the source, sink, browser policy, affected origin/session, and observable mutation or disclosure.
2. For prototype pollution, prove the recursive write and a security-relevant gadget. For DOM clobbering, prove the markup survives and the shadowed value is used.
3. For service workers and storage, prove lifecycle reachability: an attacker-controlled write or cache entry must reach a different account, tenant, or later authorization state.
4. For messaging, CORS, WebSocket, and XS-Leaks, show exact origin/source validation and the protected state or action exposed. Confirm that CSP, COOP/CORP, cookies, and SameSite policy do not already block it.
5. Return `confirmed` findings only with a complete client path and bounded local evidence. Return `needs_validation` with the precise deployed header, extension permission, browser version, or renderer behavior an owner must verify.

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

- Agent ID `v12`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/agents/v12/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v12 <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (Python 3.12; fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `python <WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-4/tools/sbx.py v12 /usr/bin/sh -c "cd /target && python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
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
