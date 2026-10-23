#!/usr/bin/env python3
"""Build a coverage-critic prompt (run-4).

usage: gen_critic.py <critic-id> <post-wave|final-clean> "<budget note>"

Kept verbatim from the skill: architecture.md, the coverage-critic task and the exact JSON
contract. Added: the live ledger summary, the current candidate and record states, the
hunter-reported uncovered boundaries and the budget note. The critic reads source only; it
never writes or runs the target.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, SRC, SK, make_scratch  # noqa: E402

PRIOR_GAPS = """- run-3 confirmed records were all fixed afterwards and the refactor (PRs #11-#14) moved
  the code, so every one of them is a revalidation unit in this ledger, not an exclusion.
- run-3 needs_validation records v01 (same_origin scheme), v09 (burst open), v10 (gui_lock
  under a stuck X), v14 (framing), v15 (gui_strays window ownership) are current work.
- Three critic-3 units deferred in run-3 (GUI-burst state races, disk/SQLite pressure,
  pre-auth work) were folded into this ledger as units.
- Two run-3 rejected claims (runc alias, backgrounded-children pid exhaustion) suppress only
  those exact claims; reporting them again needs changed evidence."""


def main():
    cid, kind, note = sys.argv[1], sys.argv[2], sys.argv[3]
    L = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
    fp_path = f"{RUN}/findings.json"
    findings = json.load(open(fp_path, encoding="utf-8")) if os.path.exists(fp_path) else []
    cands = []
    for u in L:
        for fp in u.get("result_fingerprints", []):
            if fp not in [c["fingerprint"] for c in cands]:
                cands.append({"fingerprint": fp, "state": f"ledger unit {u['coverage_id']}: {u['status']}",
                              "unit": u["coverage_id"]})
    recs = [{"fingerprint": r["fingerprint"], "state": f"final record: {r['verdict']}", "title": r["title"]}
            for r in findings]
    uncovered = []
    for d in sorted(os.listdir(f"{RUN}/agents")):
        rp = f"{RUN}/agents/{d}/result.json"
        if not os.path.exists(rp):
            continue
        try:
            res = json.load(open(rp, encoding="utf-8"))
        except ValueError:
            continue
        for item in res.get("uncovered", []) or []:
            uncovered.append({"agent": d, "uncovered": item})
    task = open(f"{SK}/HUNTING.md", encoding="utf-8").read()
    i = task.index("## Coverage-critic waves")
    task = task[i + len("## Coverage-critic waves"):].strip()
    task = task[:task.index("The run profile bounds this loop.")].strip()
    arch = open(f"{RUN}/architecture.md", encoding="utf-8").read().strip()
    who = {"post-wave": "the post-wave coverage critic immediately after the hunter wave",
           "final-clean": "the distinct final-clean coverage critic; the post-wave critic has already run and its accepted work is recorded in the ledger"}[kind]
    scratch = make_scratch(cid)
    out = f"""You are `{cid}`, {who}, in run-4 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `{SRC}/` — a git worktree of `main` at `9805d91`. Your only writable directory is `{scratch}/`, and you need not write anything.

# architecture.md (verbatim)

{arch}

# Full coverage ledger

Read it at {RUN}/coverage-ledger.json ({len(L)} units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

# Current candidate fingerprints and states

{fence}json
{json.dumps(recs + cands, ensure_ascii=False, indent=1)}
{fence}

# Hunter-reported `uncovered` boundaries

{fence}json
{json.dumps(uncovered, ensure_ascii=False, indent=1)}
{fence}

# Prior-ledger gap summary

{PRIOR_GAPS}

# Your task (verbatim from the skill)

{fence}text
{task}
{fence}

Budget note: {note}

Return exactly one JSON object and nothing else:
{fence}json
{{
  "missing_units": [
    {{
      "surface": "...",
      "boundary": "...",
      "subsystem": "...",
      "attack_class": "...",
      "starting_paths": ["repo/relative/path"],
      "selected_companion_blocks": ["FILE.md#section"],
      "excluded_blocks": [{{"block": "FILE.md#section", "reason": "..."}}],
      "reason": "source-backed coverage gap"
    }}
  ],
  "reassign_ids": ["existing-id-that-did-not-close"],
  "resolved_prior_leads": ["fingerprint"],
  "stop": false
}}
{fence}
"""
    os.makedirs(f"{RUN}/agents/{cid}", exist_ok=True)
    open(f"{RUN}/agents/{cid}/prompt.md", "w", encoding="utf-8").write(out)
    print(cid, kind, len(L), "units", len(recs) + len(cands), "states", len(out), "chars")


if __name__ == "__main__":
    main()
