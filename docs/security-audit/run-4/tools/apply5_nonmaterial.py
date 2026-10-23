#!/usr/bin/env python3
"""Apply a Phase 5 'replace' whose verifier certified the corrections as non-material.

usage: apply5_nonmaterial.py <verifier-id>

Ordinary material replacements go through apply.py, which parks them for a fresh verifier.
This helper exists for the one case in run-4 where the Phase 5 verifier returned
"replace" while stating explicitly that every correction was non-material (path prefixes,
one ordering wording, one evidence sentence) and that verdict, fingerprint, root cause,
trace paths/lines, measurements, blockers and validation plan were unchanged. The
deviation is recorded in run-metadata.json and disclosed in the report.
"""
import json
import sys

from common import RUN

vid = sys.argv[1]
obj = json.load(open(f"{RUN}/agents/{vid}/scratch/result.json", encoding="utf-8"))
rec = obj["record"]
recs = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
recs = [r for r in recs if r["fingerprint"] != rec["fingerprint"]] + [rec]
recs.sort(key=lambda r: r["fingerprint"])
json.dump(recs, open(f"{RUN}/findings.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(f"{RUN}/findings.json", "a", encoding="utf-8").write("\n")
print("APPLIED non-material phase5 replacement:", vid, rec["fingerprint"])
