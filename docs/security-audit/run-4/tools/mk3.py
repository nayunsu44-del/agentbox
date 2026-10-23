#!/usr/bin/env python3
"""Collect deduplicated candidates from the hunter results and build Phase 3 verifier prompts.

usage: mk3.py            (idempotent: reuses an existing agents/<vid>/candidate.json)

Writes agents/<vid>/candidate.json (the candidate exactly as the hunter returned it) and
agents/<vid>/prompt.md through gen3.py, one verifier per unique fingerprint.
"""
import json
import os
import subprocess
import sys

from common import RUN

seen = {}
for d in sorted(os.listdir(f"{RUN}/agents")):
    rp = f"{RUN}/agents/{d}/result.json"
    if not os.path.exists(rp):
        continue
    try:
        res = json.load(open(rp, encoding="utf-8"))
    except ValueError:
        continue
    for c in res.get("candidates", []) or []:
        fp = c.get("fingerprint")
        if fp and fp not in seen:
            c = dict(c)
            c["x_proposed_by"] = d
            seen[fp] = c

for i, (fp, cand) in enumerate(sorted(seen.items()), 1):
    vid = f"v{i:02d}"
    d = f"{RUN}/agents/{vid}"
    os.makedirs(d, exist_ok=True)
    path = f"{d}/candidate.json"
    json.dump(cand, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    r = subprocess.run([sys.executable, f"{RUN}/tools/gen3.py", vid, path], capture_output=True, text=True, encoding="utf-8")
    print(vid, fp, "|", (r.stdout or r.stderr).strip()[:120])
print("candidates", len(seen))
