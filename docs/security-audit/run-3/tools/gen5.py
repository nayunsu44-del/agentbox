#!/usr/bin/python3 -I
"""Build Phase 5 (final-record verifier) prompts for run-3.

usage: gen5.py <scratchpad-dir> <verifier-id>...   (verifier ids are p5-<phase-3 id>, e.g. p5-v11)
       gen5.py <scratchpad-dir> p5r-<phase-3 id>...  (re-check of a material Phase 5 replacement: the record is
                                                      taken from agents/p5-<id>/result.json, without its reason)

Each prompt gets only: the structured final record from findings.json (not the hunter write-up or the
Phase 3 verifier's prompt), the Phase 5 checks for its verdict copied from the skill, the source/local
execution boundary, parent-live evidence named by the record or gathered after Phase 3, the architecture
summary, the promotion procedure and the report-schema branches (both verbatim, as in the Phase 3 prompts).
Writes agents/<id>/prompt.md and creates agents/<id>/scratch owned by uid 65534.
"""
import json
import os
import re
import sys

RUN = "/home/user/agentbox/docs/security-audit/run-3"
AUDITED = "8e4db9e"  # agentbox/, images/, deploy/, tests/ byte-identical to 0e4b958 (source_ref)

# Phase 3 verifier id -> fingerprint (one final record each)
FP = {
    "v01": "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare",
    "v02": "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines",
    "v03": "agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe",
    "v05": "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions",
    "v06": "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass",
    "v15": "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process",
    "v08": "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap",
    "v09": "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit",
    "v10": "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover",
    "v11": "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency",
    "v12": "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause",
    "v13": "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized",
    "v14": "agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve",
}

# fixes already committed on the working branch after Phase 3 (for check 6 only, never as refutation)
FIXES = {
    "v02": "3587c9c", "v05": "3587c9c", "v08": "e63922c", "v06": "152b8e4",
}

# parent-live checks run after Phase 3 that bear on a record (HANDOFF "3단계 뒤에 부모가 실측한 것")
LATE = {
    "v06": ["l8_alias.py", "l8_alias.out"],
    "v09": ["l9_agent_pressure.py", "l9_agent_pressure.out", "l9_probe.py", "l9_probe.out"],
    "v10": ["l10_bound.py", "l10_bound.out"],
    "v11": ["l10_bound.py", "l10_bound.out"],
}

PHASE5 = {
    "confirmed": """1. Every repository-relative trace/evidence path, line, scope, and described operation.
2. Real entry interface and exact local input shape.
3. Every condition, parser/policy step, source-visible preventing layer, and observed local result.
4. Affected principal/resource and demonstrated impact.
5. Severity separation: realistic likelihood, demonstrated impact, overall no greater than impact.
6. Remediation strategy and any `code_changes`, including whether the fix enforces the invariant without merely moving trust.""",
    "needs_validation": """1. The source path is real and supports only the `claimed_root_cause` stated.
2. Every listed blocker is decisive and not already answerable locally.
3. The candidate names a boundary and a possible concrete result rather than a generic concern.
4. At least one validation-plan field is present and exact. `local` uses a bounded fixture; `deployment` asks an owner to observe a configuration, identity, route, policy, or runtime fact. Do not invent a plan for an inapplicable context, and never send audit traffic to a deployment.
5. The fingerprint matches prior/current records for the same root cause.""",
}


def section(text, start, stop=None):
    i = text.index(start)
    j = text.index(stop, i) if stop else len(text)
    return text[i:j]


def main():
    sp, ids = sys.argv[1], sys.argv[2:]
    template = open(f"{RUN}/agents/v11/prompt.md", encoding="utf-8").read()
    fences = re.findall(r"```text\n.*?\n```", template, re.S)
    boundary = fences[0].split("\n\n1. ")[0] + "\n```"          # verifier boundary paragraph, verbatim
    promotion = fences[1]                                       # promotion procedure, verbatim
    schema = section(template, "# report-schema.json branches", "\nReturn exactly one JSON object")
    arch = open(f"{RUN}/architecture.md", encoding="utf-8").read()
    records = {r["fingerprint"]: r for r in json.load(open(f"{RUN}/findings.json", encoding="utf-8"))}
    for vid in ids:
        recheck = vid.startswith("p5r-")
        base = vid.removeprefix("p5r-").removeprefix("p5-")
        if recheck:
            rec = json.load(open(f"{RUN}/agents/p5-{base}/result.json", encoding="utf-8"))["record"]
        else:
            rec = records[FP[base]]
        verdict = rec["verdict"]
        named = sorted(set(re.findall(r"agents/parent-live/artifacts/[\w./-]+", json.dumps(rec))))
        late = [f"agents/parent-live/artifacts/{f}" for f in LATE.get(base, [])]
        live = sorted(set(named) | set(late))
        d = f"{RUN}/agents/{vid}/scratch"
        os.makedirs(d, exist_ok=True)
        os.chown(d, 65534, 65534)
        intro = (f"""You are independent re-verifier `{vid}` in a defensive security audit of agentbox.
A Phase 5 verifier proposed the replacement record below; it changes the verdict, root cause, evidence or demonstrated result of an earlier final record, so it may be applied only after an independent check. You did not hunt it, validate it in Phase 3, or propose it. Recheck the current audited source and independently reproduce any decisive local result under the execution boundary (where the decisive result is the parent's live run, re-read the script and output and judge whether they establish it), then return `verified` or another replacement.
""" if recheck else f"""You are Phase 5 final-record verifier `{vid}` in a defensive security audit of agentbox.
You did not hunt this record and did not perform its Phase 3 validation. Check the structured record below with fresh eyes, inside source/local boundaries.
""")
        out = [intro + f"""
# Source under audit

- Read source ONLY from the audited tree `{sp}/src-audited/` (git worktree at commit {AUDITED}; agentbox/, images/, deploy/, tests/ are byte-identical to the run's source_ref 0e4b958). Record paths and line numbers refer to this tree.
- `/home/user/agentbox` is the working branch and already carries later fixes; do not use it to check lines.""" +
            (f"\n- A fix for this record was committed after Phase 3 as `{FIXES[base]}` (`git -C /home/user/agentbox show {FIXES[base]}`). Use it only to judge check 6 (does the proposed remediation enforce the invariant). It is never evidence that the record is wrong for the audited source." if base in FIXES and verdict == "confirmed" else "") +
            (f"\n- A change for this root cause was committed after Phase 3 as `{FIXES[base]}`. It does not change the audited source; ignore it for verification." if base in FIXES and verdict != "confirmed" else ""),
            "\n# Execution boundary (verbatim from the skill)\n", boundary,
            f"\n# Phase 5 checks for a `{verdict}` record (verbatim from the skill)\n",
            "```text\n" + PHASE5[verdict] + "\n```",
            """
A replacement may correct wording or lines, demote, reject, or promote. If evidence below (yours or the parent's) establishes the complete path and a bounded observed result, a promotion to `confirmed` is a full replacement record in the `confirmed` branch; it will be checked again by another fresh verifier before it is applied. If a check fails only on a non-material wording or line issue, say so in `reason` and return the corrected record. Do not invent a stronger result than the evidence shows.

# """ + ("Proposed replacement record" if recheck else "Final record (from findings.json)") + "\n",
            "```json\n" + json.dumps(rec, ensure_ascii=False, indent=1) + "\n```\n",
            "Artifacts referenced by the record are under /home/user/agentbox/docs/security-audit/run-3/ (paths relative to it). Read them; do not modify them.\n"]
        if live:
            out.append("""# Parent-live evidence (run by the parent, not by a hunter or verifier)

The parent ran these bounded checks against the real Docker-backed control plane and desktop image (disposable containers, loopback only, dummy tokens) or a real Chromium on loopback. You cannot run Docker or a browser; treat them as owner-observed local evidence: re-read every script, confirm it exercises the claimed path against the audited source, and judge whether its output establishes the claim. Say in the record if the decisive reproduction is the parent's rather than yours.
""" + ("Checks marked (after Phase 3) were run after this record was written and are not yet reflected in it.\n" if late else "") + "\n" +
                       "\n".join(f"- {p}" + (" (after Phase 3)" if p in late and p not in named else "") for p in live) + "\n")
        out += ["# Architecture facts\n", arch,
                f"""
# Execution paths

- Agent ID `{vid}`. Write ONLY in `{RUN}/agents/{vid}/scratch/`. Never edit target files, the ledger, findings, other agents' directories, or anything under /home/user/agentbox outside that scratch directory. Do not run git commands that change state.
- Run target code only via `{sp}/sbx5 {vid} <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Never run target code outside sbx5.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative; <=256 KiB each) and reference it as `agents/{vid}/artifacts/<file>`.
""",
                promotion, "\n", schema,
                """
# Output

Return exactly one JSON object with no prose and no markdown fence, one of:
{"decision": "verified", "fingerprint": "<the record's fingerprint>"}
{"decision": "replace", "reason": "<what failed and why>", "record": {...}, "artifacts_to_promote": [...]}
A replacement record must match its `confirmed`, `needs_validation`, or `rejected` branch exactly (additionalProperties: false) and keep the same fingerprint unless you identified a genuinely different root cause. `artifacts_to_promote` is optional. Overall severity cannot exceed demonstrated impact; only confirmed records carry severity.
"""]
        open(f"{RUN}/agents/{vid}/prompt.md", "w", encoding="utf-8").write("\n".join(out))
        print(vid, verdict, "live:", len(live), "chars:", sum(map(len, out)))


if __name__ == "__main__":
    main()
