#!/usr/bin/env python3
"""Apply the result of a fresh re-verifier for a parked material Phase 5 replacement.

usage: apply_reverify.py <reverifier-id> <parked-phase5-id>

The re-verifier checked the parked replacement independently. 'verified' applies the parked record; 'replace' applies
the re-verifier's own corrected record, which it certified as wording/line corrections of the parked one (same
verdict, fingerprint, root cause and observed result). Anything else is refused.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from apply import parse  # noqa: E402
from common import RUN  # noqa: E402

rv, p5 = sys.argv[1], sys.argv[2]
obj = parse(f"{RUN}/agents/{rv}/final.txt")
parked = json.load(open(f"{RUN}/agents/{p5}/pending-replacement.json", encoding="utf-8"))
parked = parked.get("record", parked)
if obj["decision"] == "verified":
    rec = parked
elif obj["decision"] == "replace":
    rec = obj["record"]
    assert rec["verdict"] == parked["verdict"] and rec["fingerprint"] == parked["fingerprint"]
else:
    raise SystemExit(f"refused: {obj['decision']}")
recs = [r for r in json.load(open(f"{RUN}/findings.json", encoding="utf-8")) if r["fingerprint"] != rec["fingerprint"]]
recs.append(rec)
recs.sort(key=lambda r: r["fingerprint"])
with open(f"{RUN}/findings.json", "w", encoding="utf-8") as f:
    json.dump(recs, f, ensure_ascii=False, indent=1)
    f.write("\n")
os.replace(f"{RUN}/agents/{p5}/pending-replacement.json", f"{RUN}/agents/{p5}/applied-after-{rv}.json")
print("APPLIED re-verified record", rec["fingerprint"], obj["decision"])
