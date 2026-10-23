#!/usr/bin/env python3
"""Parent-side intake of one hunter's structured result (run-5, Windows host).

usage: ingest_hunt.py <hunter-id> <file-with-the-final-message>

Ported from run-4/tools/ingest_hunt.py onto run-5/tools/common.py. The DSH subagent
returns its result over the parent channel, so the parent first writes that text to a
file and the intake reads it from there; nothing else about the contract changed.

1. requires exactly one JSON object in the file
2. checks that every assigned unit appears exactly once and that each disposition carries
   the evidence the ledger requires (covered/candidate/blocked)
3. promotes the allowlisted artifacts with tools/promote.py, then writes the unit's live
   fields (status, reviewed_paths, local_checks, result_fingerprints, unresolved, x_hardening)
4. stores the raw result as agents/<id>/result.json; candidates stay there for Phase 3
Discarded results are never repaired.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, final_message  # noqa: E402


def fail(why):
    print("DISCARD:", why)
    sys.exit(1)


def main():
    hid, out = sys.argv[1:3]
    raw = final_message(out)
    if not raw:
        fail("no final message")
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    try:
        obj = json.loads(text.strip())
    except json.JSONDecodeError as e:
        fail(f"not exactly one JSON object ({e})")
    if not isinstance(obj, dict) or set(obj) - {"units", "candidates", "hardening", "uncovered", "artifacts_to_promote"}:
        fail(f"bad top-level keys {sorted(obj) if isinstance(obj, dict) else type(obj)}")
    ledger = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
    mine = {u["coverage_id"]: u for u in ledger if u["agent_id"] == hid and u["status"] == "in_progress"}
    units = obj.get("units", [])
    if sorted(u.get("coverage_id") for u in units) != sorted(mine):
        fail("units do not match the assigned coverage IDs")
    cand_fps = {c.get("fingerprint") for c in obj.get("candidates", [])}
    for u in units:
        d = u.get("disposition")
        if d not in ("covered", "candidate", "blocked"):
            fail(f"bad disposition {d!r}")
        if not u.get("reviewed_paths") or not u.get("checks"):
            fail(f"{d} unit needs reviewed_paths and checks")
        fps, unres = u.get("candidate_fingerprints", []), u.get("unresolved", [])
        if d == "candidate" and (not fps or not set(fps) <= cand_fps):
            fail("candidate unit needs fingerprints that appear in candidates")
        if d != "candidate" and fps:
            fail(f"{d} unit carries fingerprints")
        if d == "covered" and unres:
            fail("covered unit carries unresolved facts")
        if d == "blocked" and not unres:
            fail("blocked unit needs unresolved facts")
        paths = sorted({p for c in u["checks"] for p in c.get("reviewed_paths", [])})
        if paths != sorted(set(u["reviewed_paths"])):
            fail("unit reviewed_paths is not the union of its checks' paths")
    arts = obj.get("artifacts_to_promote", []) or []
    if arts:
        r = subprocess.run([sys.executable, "-I", f"{RUN}/tools/promote.py", hid, *arts], capture_output=True, text=True, encoding="utf-8")
        print((r.stdout + r.stderr).strip())
    promoted = {f"agents/{hid}/artifacts/{a}" for a in arts if os.path.isfile(f"{RUN}/agents/{hid}/artifacts/{a}")}
    for u in units:
        for c in u["checks"]:
            if c.get("method") == "local" and c.get("artifact") not in promoted:
                print(f"note: local check artifact {c.get('artifact')!r} not promoted; recorded as source check")
                c["method"], c["artifact"] = "source", None
        live = mine[u["coverage_id"]]
        live["status"] = u["disposition"]
        live["reviewed_paths"] = sorted(set(u["reviewed_paths"]))
        live["local_checks"] = u["checks"]
        live["result_fingerprints"] = u.get("candidate_fingerprints", [])
        live["unresolved"] = u.get("unresolved", [])
        live["x_hardening"] = obj.get("hardening", [])
    with open(f"{RUN}/coverage-ledger.json", "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.makedirs(f"{RUN}/agents/{hid}", exist_ok=True)
    with open(f"{RUN}/agents/{hid}/result.json", "w", encoding="utf-8") as f:
        f.write(text.strip() + "\n")
    print(f"OK {hid}: units={[(u['coverage_id'][:44], u['disposition']) for u in units]} "
          f"candidates={[(c.get('fingerprint'), c.get('proposed_verdict')) for c in obj.get('candidates', [])]} "
          f"uncovered={len(obj.get('uncovered', []))} hardening={len(obj.get('hardening', []))}")


if __name__ == "__main__":
    main()
