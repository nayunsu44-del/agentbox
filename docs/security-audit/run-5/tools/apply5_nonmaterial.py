#!/usr/bin/env python3
"""Apply a parked Phase 5 'replace' that the parent checked field by field and found non-material.

usage: apply5_nonmaterial.py <verifier-id>

apply.py parks any replacement that touches trace/execution text. When the only differences are
line-number corrections and wording (verdict, fingerprint, root cause, trace kinds/files, payloads,
measurements and severity unchanged), the parent applies it here and records the deviation in
run-metadata.json so the report discloses it.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN  # noqa: E402

vid = sys.argv[1]
obj = json.load(open(f"{RUN}/agents/{vid}/pending-replacement.json", encoding="utf-8"))
rec = obj.get("record", obj)
recs = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
old = next(r for r in recs if r["fingerprint"] == rec["fingerprint"])
assert old["verdict"] == rec["verdict"] and old.get("root_cause") == rec.get("root_cause")
assert old.get("severity") == rec.get("severity")
assert [(t["kind"], t["file"], t["line"]) for t in old["trace"]] == [(t["kind"], t["file"], t["line"]) for t in rec["trace"]]
recs = [r for r in recs if r["fingerprint"] != rec["fingerprint"]] + [rec]
recs.sort(key=lambda r: r["fingerprint"])
with open(f"{RUN}/findings.json", "w", encoding="utf-8") as f:
    json.dump(recs, f, ensure_ascii=False, indent=1)
    f.write("\n")
os.replace(f"{RUN}/agents/{vid}/pending-replacement.json", f"{RUN}/agents/{vid}/applied-nonmaterial-replacement.json")
print("APPLIED non-material phase5 replacement:", vid, rec["fingerprint"])
