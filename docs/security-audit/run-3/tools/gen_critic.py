#!/usr/bin/python3 -I
"""Build a coverage-critic prompt from agents/critic-2/prompt.md (run-3).

usage: gen_critic.py <critic-id> <post-wave|final-clean> <budget note> <scratchpad-dir>

Kept verbatim: architecture, prior-run gap summary and the skill's critic task. Replaced: the header (which
critic and which wave), the ledger pointer, the current candidate/record list and the wave-3 uncovered list.
"""
import json
import os
import sys

RUN = "/home/user/agentbox/docs/security-audit/run-3"


def main():
    cid, kind, note = sys.argv[1:4]
    t = open(f"{RUN}/agents/critic-2/prompt.md", encoding="utf-8").read()
    head = t[:t.index("\n")]
    arch = t[t.index("# architecture.md (verbatim)"):t.index("# Full coverage ledger")]
    prior = t[t.index("# Prior-run gap summary"):t.index("# Your task (verbatim from the skill)")]
    task = t[t.index("# Your task (verbatim from the skill)"):t.index("Notes: blocked units")]
    notes = t[t.index("Notes: blocked units"):t.index("Budget note:")]
    ledger = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
    findings = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
    recs = [{"fingerprint": r["fingerprint"], "state": f"final record: {r['verdict']}", "title": r["title"]} for r in findings]
    for h in ("h-preview", "h-queue", "h-autostart"):
        for c in json.load(open(f"{RUN}/agents/{h}/result.json", encoding="utf-8"))["candidates"]:
            recs.append({"fingerprint": c["fingerprint"], "state": f"wave-3 candidate ({c['proposed_verdict']}), awaiting Phase 3", "title": c["title"]})
    recs.append({"fingerprint": "agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion",
                 "state": "parent-observed lead, Phase 3 verifier v16 running", "title": "Background processes started by an approval-free exec outlive the exec's timeout and can pin the sandbox at its pids limit"})
    who = {"post-wave": "the post-wave coverage critic after wave 3",
           "final-clean": "the distinct final-clean coverage critic (standard profile); the post-wave critic after wave 3 has run and its accepted work, if any, is recorded in the ledger"}[kind]
    out = head.replace("`critic-2`", f"`{cid}`").replace("the post-wave coverage critic (after wave 2)", who).replace(
        "(target /home/user/agentbox, read-only)",
        f"(audited source, read-only: {sys.argv[4]}/src-audited, a worktree at 8e4db9e identical to 0e4b958 for agentbox/, images/, deploy/, tests/; cite its lines)")
    out += "\n\n" + arch + f"""# Full coverage ledger

Read it at {RUN}/coverage-ledger.json ({len(ledger)} units; every unit is terminal: covered or candidate, each with its assignment block map, status, checks, reviewed paths and linked fingerprints; x_hardening holds hunter hardening notes, attempts holds archived reassignments). Wave 3 assigned the three units critic-2 proposed (approval card impact/capture, approval queue and captures, /home/desktop autostart persistence).

# Current records and candidates

{json.dumps(recs, ensure_ascii=False, indent=1)}

# Hunter-reported `uncovered` boundaries from wave 3

[]

{prior}{task}{notes}Budget note: {note}
"""
    os.makedirs(f"{RUN}/agents/{cid}", exist_ok=True)
    open(f"{RUN}/agents/{cid}/prompt.md", "w", encoding="utf-8").write(out)
    print(cid, len(out))


if __name__ == "__main__":
    main()
