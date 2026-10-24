#!/usr/bin/env python3
"""Build a Phase 5 record-verifier prompt (run-6).

usage: gen5.py <verifier-id> <record-json-file>
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
fence = chr(96) * 3

from common import RUN, SRC, SBX, PY, SK, block, schema_branch, ledger, make_scratch, write_prompt  # noqa: E402


def phase5_block():
    t = open(f"{SK}/VALIDATION-AND-REPORTING.md", encoding="utf-8").read()
    i = t.index("### Phase 5: Verify the final records with fresh eyes")
    j = t.index("### Phase 6:")
    body = t[i:j].strip()
    return body


def main():
    vid, path = sys.argv[1], sys.argv[2]
    rec = json.load(open(path, encoding="utf-8"))
    fp = rec["fingerprint"]
    L = ledger()
    units = [u for u in L if fp in u.get("result_fingerprints", [])]
    refs = []
    for u in units:
        r = ([u["attack_class"]] if u["attack_class"].startswith("ATTACK-CLASSES.md#") else []) + u["selected_companion_blocks"]
        for x in r:
            if x not in refs:
                refs.append(x)
    sel = "\n\n".join(f"<!-- {r} -->\n{block(r)}" for r in refs) if refs else "- none"
    arch = open(f"{RUN}/architecture.md", encoding="utf-8").read().strip()[:12000]
    scratch = make_scratch(vid)
    out = f"""You are final record verifier `{vid}` in run-6 of a defensive security audit of agentbox. You did not hunt this candidate and you did not perform its Phase 3 validation. You check the STRUCTURED RECORD below, not anyone's write-up.

# Audited source and version

Read-only audited source: `{SRC}/` — a git worktree of `main` at commit `530b29e`. Every path and line must exist in THAT tree (except `agents/...` artifacts which live under `{RUN}/agents/...`).

# Record under verification

{fence}json
{json.dumps(rec, ensure_ascii=False, indent=1)}
{fence}

# Phase 5 procedure (verbatim)

{fence}text
{phase5_block()}
{fence}

# Architecture facts (summary; re-check every line you rely on)

{arch}

# Relevant companion blocks (verbatim)

{sel}

# Execution boundary and paths

- Agent ID `{vid}`. Write ONLY in `{scratch}/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "{SBX}" {vid} <cmd...>`: audited source read-only at /target (on PYTHONPATH), scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `{PY}`.
- Unit tests need cwd=/target: `python "{SBX}" {vid} /usr/bin/sh -c "cd /target && {PY} -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field (scratch-relative, <=256 KiB each). The parent promotes it after you finish.
- Your final message must be ONLY one JSON object: `{{"decision":"verified","fingerprint":"{fp}"}}` or `{{"decision":"replace","reason":"...","record":{{...}}}}`. No prose, no code fence.

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
    write_prompt(vid, out)
    print(vid, fp, rec["verdict"], len(out), "chars")


if __name__ == "__main__":
    main()
