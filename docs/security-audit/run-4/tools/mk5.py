#!/usr/bin/env python3
"""Build one Phase 5 record-verifier prompt per final record in findings.json.

usage: mk5.py
Writes agents/r01..rNN/{record.json,prompt.md}. Verifier ids are r01.. so they never
collide with the Phase 3 verifier ids v01...
"""
import json
import os
import subprocess
import sys

from common import RUN

recs = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
for i, rec in enumerate(sorted(recs, key=lambda r: r["fingerprint"]), 1):
    rid = f"r{i:02d}"
    d = f"{RUN}/agents/{rid}"
    os.makedirs(d, exist_ok=True)
    path = f"{d}/record.json"
    json.dump(rec, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    r = subprocess.run([sys.executable, f"{RUN}/tools/gen5.py", rid, path], capture_output=True, text=True, encoding="utf-8")
    print(rid, rec["verdict"], rec["fingerprint"][:60], "|", (r.stdout or r.stderr).strip()[:80])
print("records", len(recs))
