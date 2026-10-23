#!/usr/bin/python3 -I
"""Build a Phase 3 candidate-verifier prompt for a candidate written to agents/<id>/candidate.json (run-3).

usage: gen3.py <scratchpad-dir> <verifier-id> <linked unit surface prefix> <related-records note> [<parent-live artifact>...]

The companion blocks are the linked unit's attack class (if in ATTACK-CLASSES.md) and selected_companion_blocks,
copied verbatim from the skill (same extraction as gen_hunt.py).

Template: agents/v11/prompt.md (the verifier prompt block, promotion procedure, architecture, the
RESOURCE-EXHAUSTION companion blocks and the schema branches stay verbatim). Replaced: header, candidate,
linked coverage-unit checks, parent-live evidence list and the execution paths (audited worktree + sbx5).
"""
import json
import os
import sys

RUN = "/home/user/agentbox/docs/security-audit/run-3"


def cut(text, start, stop):
    i = text.index(start)
    j = text.index(stop, i)
    return text[:i], text[j:]


def main():
    sp, vid, prefix, related, live = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gen_hunt import block
    t = open(f"{RUN}/agents/v11/prompt.md", encoding="utf-8").read()
    cand = json.load(open(f"{RUN}/agents/{vid}/candidate.json", encoding="utf-8"))
    unit = next(u for u in json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8")) if u["surface"].startswith(prefix))
    t = t.replace(t[:t.index("\n")], f"You are candidate verifier `{vid}` in a defensive security audit of agentbox "
                  f"(audited source, read-only: `{sp}/src-audited/`, a worktree at commit 8e4db9e; agentbox/ identical to 0e4b958).")
    a, b = cut(t, "# Candidate (proposed by a hunter; you did not write it)", "# Linked coverage-unit checks")
    by = cand.pop("x_proposed_by", "the parent from a live observation")
    t = a + (f"# Candidate (proposed by {by}; you did not write it)\n\n"
             "```json\n" + json.dumps(cand, ensure_ascii=False, indent=1) + "\n```\n\n\n") + b
    a, b = cut(t, "# Linked coverage-unit checks", "Artifacts are under ")
    checks = [{"coverage_id": unit["coverage_id"], "local_checks": unit["local_checks"]}]
    t = a + "# Linked coverage-unit checks\n\n" + json.dumps(checks, ensure_ascii=False, indent=1) + "\n\n" + b
    a, b = cut(t, "# Parent-live evidence", "# Architecture facts")
    pl = t[t.index("# Parent-live evidence"):t.index("- agents/parent-live/")]
    t = a + (pl + "\n".join(f"- agents/parent-live/artifacts/{f}" for f in live) + "\n\n" if live else "") + b
    a, b = cut(t, "# Relevant companion blocks (verbatim)", "# Execution boundary and paths")
    refs = ([unit["attack_class"]] if unit["attack_class"].startswith("ATTACK-CLASSES.md#") else []) + unit["selected_companion_blocks"]
    sk = f"{sp}/skill/skills/security-audit"
    t = a + "# Relevant companion blocks (verbatim)\n\n" + "\n\n".join(f"<!-- {r} -->\n{block(sk, r)}" for r in refs) + "\n\n" + b
    a, b = cut(t, "# Execution boundary and paths", "# report-schema.json branches")
    scratch = f"{RUN}/agents/{vid}/scratch"
    t = a + f"""# Execution boundary and paths

- Agent ID `{vid}`. Write ONLY in `{scratch}/`. Never edit target files, the ledger, findings, or other agents' directories.
- Read source only from `{sp}/src-audited/` and cite its lines. `/home/user/agentbox` carries later fixes; do not use it for lines.
- Run target code only via `{sp}/sbx5 {vid} <cmd...>` (audited source at /target read-only on PYTHONPATH, scratch at /scratch, no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 120 s). Use `/usr/bin/python3.13`. Shell utilities such as bash, timeout and sleep are available inside it.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field next to `decision` and `record` (scratch-relative; <=256 KiB each); reference it as `agents/{vid}/artifacts/<file>`.
- No prior record has this fingerprint. {related}

""" + b
    os.makedirs(scratch, exist_ok=True)
    os.chown(scratch, 65534, 65534)
    open(f"{RUN}/agents/{vid}/prompt.md", "w", encoding="utf-8").write(t)
    print(vid, len(t))


if __name__ == "__main__":
    main()
