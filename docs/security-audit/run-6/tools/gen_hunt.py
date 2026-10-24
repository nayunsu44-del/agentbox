#!/usr/bin/env python3
"""Build run-6 hunter prompts (HUNTING.md "Required hunter prompt", parts 1-9 in order).

usage: gen_hunt.py <hunter-id> [<hunter-id> ...]     (assigns units whose x_hunter matches)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, SRC, SBX, PY, SK, block, fenced, schema_branch, ledger, save_ledger, make_scratch, write_prompt  # noqa: E402

PRIOR4 = json.load(open(f"{RUN}/../run-4/findings.json", encoding="utf-8"))
PRIOR5 = json.load(open(f"{RUN}/../run-5/findings.json", encoding="utf-8"))
PRIOR_BY_FP = {r["fingerprint"]: ("run-4", r) for r in PRIOR4}
PRIOR_BY_FP.update({r["fingerprint"]: ("run-5", r) for r in PRIOR5})
EXTRA = json.load(open(f"{RUN}/tools/hunter_notes.json", encoding="utf-8")) if os.path.exists(f"{RUN}/tools/hunter_notes.json") else {}


def structured_result():
    t = open(f"{SK}/HUNTING.md", encoding="utf-8").read()
    i = t.index("## Structured hunter result")
    j = t.index("## Parent consolidation and ledger update")
    return t[i:j].strip()


def main():
    arch = open(f"{RUN}/architecture.md", encoding="utf-8").read().strip()
    L = ledger()
    method = fenced("HUNTING.md", "#### Core hunting method")
    promo = fenced("HUNTING.md", "#### Promotion procedure")
    rules = fenced("HUNTING.md", "#### Core validation rules")
    for hid in sys.argv[1:]:
        mine = [u for u in L if u["x_hunter"] == hid]
        assert mine and all(u["status"] == "planned" for u in mine), hid
        scratch = make_scratch(hid)
        for u in mine:
            u["status"], u["agent_id"] = "in_progress", hid
        units = [{k: u[k] for k in ("coverage_id", "surface", "boundary", "subsystem", "attack_class", "starting_paths",
                                     "ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks", "prior_status")}
                 for u in mine]
        refs = []
        for u in mine:
            for r in ([u["ordinary_attack_class_block"]] if u["ordinary_attack_class_block"] else []) + \
                     ([u["attack_class"]] if "#" in u["attack_class"] and u["attack_class"].split("#")[0].endswith(".md") else []) + \
                     u["selected_companion_blocks"]:
                if r not in refs:
                    refs.append(r)
        sel = "\n\n".join(f"<!-- {r} -->\n{block(r)}" for r in refs)
        excl = []
        for u in mine:
            for e in u["excluded_blocks"]:
                line = f"- `{e['block']}`: {e['reason']}"
                if line not in excl:
                    excl.append(line)
        prior_lines = []
        for u in mine:
            for fp in u["x_prior_fingerprints"]:
                hit = PRIOR_BY_FP.get(fp)
                if hit:
                    src_run, r = hit
                    sev = r.get("severity", {}).get("overall_severity", "")
                    rc = r.get("root_cause") or r.get("claimed_root_cause")
                    extra = f" Rejection reason: {r['reason']}" if r["verdict"] == "rejected" else ""
                    prior_lines.append(f"- `{fp}` — {src_run} {r['verdict']} {sev}: {r['title']}\n  Root cause ({src_run} wording): {rc}{extra}")
        prior_lines = list(dict.fromkeys(prior_lines))
        peers = "\n".join(f"- `{u['coverage_id']}` (owner {u['x_hunter']})" for u in L if u["x_hunter"] != hid)
        notes = EXTRA.get(hid, "")
        out = f"""You are hunter `{hid}` in run-6 of a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage units, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

# architecture.md (verbatim)

{arch}

# Assigned coverage units

{json.dumps(units, ensure_ascii=False, indent=1)}

## Prior-run records linked to these units (changed source: revalidate, do not assume)

Since run-5 (audited at 346df29), every run-5 confirmed record and the N1 needs_validation record were fixed in PRs #24 and #25; the source you read is the fixed tree at `530b29e`. Run-4 needs_validation N1 (`same_origin` scheme) and N3 (container output reader caps) were not fixed and are in scope. For each prior confirmed record below, check whether the current source still allows the same root cause, including variants the fix did not cover; if it does, return a candidate with the SAME fingerprint. For a prior needs_validation record, settle it from current source and bounded local evidence if you can (candidate with the same fingerprint as confirmed, needs_validation, or record in your unit check why it no longer holds). A prior rejected claim may be re-reported only with changed evidence.

{chr(10).join(prior_lines) if prior_lines else "- none"}
{notes}
# Selected attack-class blocks (verbatim)

{sel}

# Excluded blocks

{chr(10).join(excl) if excl else "- none"}

# Core hunting method (verbatim)

```text
{method}
```

```text
{promo}
```

# Core validation rules (verbatim)

```text
{rules}
```

# Exclusions and peer-owned units

Carried same-source prior confirmed exclusions: none (no unit is same-source).

Peer-owned coverage IDs (do not investigate these; report a different boundary you notice under `uncovered`):
{peers}

# Your paths, sandbox and result contract

- Agent ID: `{hid}`. Audited source (read-only): `{SRC}/` (git worktree of main at 530b29e). Read it with read_file or read-only shell commands and cite repository-relative paths and line numbers of THAT tree. Never edit target files, the ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `{scratch}/`. Retained artifacts: `{RUN}/agents/{hid}/artifacts/` are parent-owned; never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, unit tests, harnesses): `python "{SBX}" {hid} <cmd...>`. Inside: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment (HOME=TMPDIR=/scratch, PATH, PYTHONPATH=/target). Use `{PY}` (Python 3.12; fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest are importable). Write `{scratch}/h.py`, then run `python "{SBX}" {hid} /usr/bin/sh -c "{PY} /scratch/h.py > /scratch/h.out 2>&1"`. Unit tests (cwd must be /target; pass --capture=sys): `python "{SBX}" {hid} /usr/bin/sh -c "cd /target && {PY} -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- Never run agentbox code outside the sandbox. Never use the Docker daemon, start servers outside the sandbox, or contact the network. A claim that needs the real Docker-backed control plane or the desktop image at runtime goes in as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan: the parent will reproduce it live (dummy principals, loopback, disposable container) during Phase 3. Use `proposed_verdict: "confirmed"` only if your sandboxed check alone demonstrates the boundary result.
- Promotion allowlist: add a top-level `"artifacts_to_promote": ["h.out", ...]` array to your JSON listing every scratch-relative file you want retained (regular files, max 256 KiB each, 1 MiB total). The parent promotes them after you finish; cite them in checks as `agents/{hid}/artifacts/<file>`. Without a local check use `method: "source"` and `artifact: null`.
- Contract check: for EVERY unit in `"units"`, `unit["reviewed_paths"]` MUST equal the exact sorted set union of `c["reviewed_paths"]` across all `c` in `unit["checks"]`.
- Time box: aim to finish within roughly 30 tool calls. Stop each line of investigation as soon as the invariant is settled.
- Your final message must be ONLY the JSON object (no prose, no code fence).

{structured_result()}

## report-schema.json `confirmed` branch (verbatim)

```json
{schema_branch("confirmed")}
```

## report-schema.json `needs_validation` branch (verbatim)

```json
{schema_branch("needs_validation")}
```
"""
        write_prompt(hid, out)
        print(hid, len(mine), "units", len(refs), "blocks", len(out), "chars")
    save_ledger(L)


if __name__ == "__main__":
    main()
