#!/usr/bin/env python3
"""Build a Phase 3 candidate-verifier prompt (run-5).

usage: gen3.py <verifier-id> <candidate-json-file> [--live <artifact-relative-path> ...]

<candidate-json-file> holds one candidate object exactly as the hunter returned it inside
its result's "candidates" array (the parent extracts it).

Every block the skill marks verbatim is copied unchanged from the skill: the
candidate-verifier prompt block, the artifact promotion procedure, the confirmed /
needs_validation / rejected branches of report-schema.json, and the companion validation
blocks selected by the linked coverage unit. The linked unit's own checks and the parent's
live evidence are added so the verifier can refute from current source and observation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
fence = chr(96) * 3

from common import RUN, SRC, SBX, SBX_CMD, PY, SK, block, fenced, schema_branch, ledger, save_ledger, make_scratch  # noqa: E402

PRIOR = json.load(open(f"{RUN}/../run-4/findings.json", encoding="utf-8"))
PRIOR_BY_FP = {r["fingerprint"]: r for r in PRIOR}


def main():
    args = sys.argv[1:]
    vid = args.pop(0)
    cand_path = args.pop(0)
    live = []
    while args:
        a = args.pop(0)
        if a == "--live":
            live.append(args.pop(0))
    cand = json.load(open(cand_path, encoding="utf-8"))
    fp = cand["fingerprint"]
    L = ledger()
    units = [u for u in L if fp in u.get("result_fingerprints", [])]
    assert units, f"no ledger unit carries {fp}"
    if not any(u["status"] == "candidate" for u in units):
        print(f"note: unit(s) for {fp} are not in candidate state: {[u['status'] for u in units]}")
    vbody = fenced("VALIDATION-AND-REPORTING.md", "#### Candidate-verifier prompt")
    promo = fenced("VALIDATION-AND-REPORTING.md", "Copy this promotion procedure verbatim into every candidate-verifier prompt:")
    arch = open(f"{RUN}/architecture.md", encoding="utf-8").read().strip()
    arch_facts = "\n".join(ln for ln in arch.splitlines() if ln.strip())[:12000]
    refs = []
    for u in units:
        r = ([u["attack_class"]] if u["attack_class"].startswith("ATTACK-CLASSES.md#") else []) + u["selected_companion_blocks"]
        for x in r:
            if x not in refs:
                refs.append(x)
    sel = "\n\n".join(f"<!-- {r} -->\n{block(r)}" for r in refs) if refs else "- none"
    checks = [{"coverage_id": u["coverage_id"], "surface": u["surface"], "boundary": u["boundary"],
               "local_checks": u["local_checks"]} for u in units]
    prior = PRIOR_BY_FP.get(fp)
    prior_txt = "- none"
    if prior:
        prior_txt = json.dumps(prior, ensure_ascii=False, indent=1)
    live_txt = ("\n".join(f"- `agents/parent-live/artifacts/{f}`" for f in live) if live
                else "- none (no parent-live observation was taken for this candidate)")
    scratch = make_scratch(vid)
    out = f"""You are candidate verifier `{vid}` in run-5 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `{SRC}/` — a git worktree of `main` at commit `346df29` (after fix PRs #16-#23). Every path and line you cite must exist in THAT tree. The working branch (`docs/security-audit/run-5`) carries audit output only; `/home/user/agentbox` from earlier runs carries later or earlier code and must not be used for line numbers.

# Candidate (proposed by a hunter; you did not write it)

{fence}json
{json.dumps(cand, ensure_ascii=False, indent=1)}
{fence}

# Linked coverage-unit checks

{fence}json
{json.dumps(checks, ensure_ascii=False, indent=1)}
{fence}

# Prior-run record with the same fingerprint (run-4 wording)

{fence}json
{prior_txt}
{fence}

# Parent-live evidence

{live_txt}

# Architecture facts (summary; re-check every line you rely on)

{arch_facts}

# Relevant companion blocks (verbatim)

{sel}

# Verifier instructions (verbatim)

{fence}text
{vbody}
{fence}

# Artifact promotion procedure (verbatim)

{fence}text
{promo}
{fence}

# Execution boundary and paths

- Agent ID `{vid}`. Write ONLY in `{scratch}/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `{SBX_CMD} {vid} <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `{PY}` (fastapi, docker SDK, jinja2, pyyaml, mcp, pyte importable).
- Unit tests need cwd=/target: `{SBX_CMD} {vid} /usr/bin/sh -c "cd /target && {PY} -m pytest -p no:cacheprovider --capture=sys -q tests/test_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish.
- Your final message must be ONLY the JSON object `{{"decision": ..., "record": {{...}}}}` plus that optional field. No prose, no code fence.

# report-schema.json branches (verbatim)

## `confirmed`

{fence}json
{schema_branch("confirmed")}
{fence}

## `needs_validation`

{fence}json
{schema_branch("needs_validation")}
{fence}

## `rejected`

{fence}json
{schema_branch("rejected")}
{fence}
"""
    os.makedirs(f"{RUN}/agents/{vid}", exist_ok=True)
    open(f"{RUN}/agents/{vid}/prompt.md", "w", encoding="utf-8").write(out)
    print(vid, fp, len(units), "units", len(refs), "blocks", len(out), "chars")


if __name__ == "__main__":
    main()
