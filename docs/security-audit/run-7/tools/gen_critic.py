#!/usr/bin/env python3
"""Build a coverage-critic prompt (run-7).

usage: gen_critic.py <critic-id> <post-wave|final-clean> "<budget note>"
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, SRC, SK, make_scratch, write_prompt  # noqa: E402

fence = chr(96) * 3

PRIOR_GAPS = """- run-7 is a focused follow-up audit at 3580df0 of the delta 530b29e..3580df0. run-6 closed all 11
  units with nothing deferred. The run-7 ledger holds seven new units: completeness of the 7dbda9e fixes
  for run-6 F1-F3/N1-N3, behaviour preservation of the 5bb3c17 refactor, and five IF-1 units (name
  classification, policy target vs write target, read-result boundary, human-facing sinks, source scan).
- Every other unit from run-4..run-6 was covered at 9805d91, 346df29 or 530b29e and its code is unchanged
  by the delta; proposing them again needs a concrete changed-code or cross-unit interaction reason.
- An owner-run single-pass IF-1 review at ccaf367 found 7 confirmed, 3 info, 5 needs_validation; a0a186c
  fixed the 7 confirmed and 2 needs_validation. Fixed root causes are not to be re-proposed.
- README known limitations (name-only detection, exec glob reads, GUI approval bypass N-1, LLM-provider
  data path, audit external anchor) are out of scope without a new angle."""


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
    if os.path.isdir(f"{RUN}/agents"):
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
    out = f"""You are `{cid}`, {who}, in run-7 of a defensive security audit of agentbox.

You propose COVERAGE, not findings. Read source; do not write target files and do not run the target (there is no sandbox for this role). Audited source, read-only: `{SRC}/` — a git worktree of `main` at `3580df0`. Your only writable directory is `{scratch}/`, and you need not write anything.

# architecture.md (verbatim)

{arch}

# Full coverage ledger

Read it at `{RUN}/coverage-ledger.json` ({len(L)} units). Each unit carries its assignment block map (`surface`, `boundary`, `subsystem`, `attack_class`, `starting_paths`, `selected_companion_blocks`, `excluded_blocks`, `x_hunter`), live status, `reviewed_paths`, `local_checks`, `result_fingerprints`, `unresolved` and `x_hardening`.

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

Return exactly one JSON object and nothing else (no prose, no code fence):
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
    write_prompt(cid, out)
    print(cid, kind, len(L), "units", len(recs) + len(cands), "states", len(out), "chars")


if __name__ == "__main__":
    main()
