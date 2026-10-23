#!/usr/bin/env python3
"""Map a transcribed hunter result onto the ledger's coverage IDs and normalise unit paths.

usage: fix_ids.py <hunter-id> <raw.json>

report: units[i].reviewed_paths is recomputed as the union of the unit's check paths, which
is the contract the intake enforces. Refuses on a count mismatch.
"""
import json
import sys

sys.path.insert(0, "./tools")
from common import ledger

hid, path = sys.argv[1], sys.argv[2]
obj = json.load(open(path, encoding="utf-8"))
mine = sorted((u for u in ledger() if u.get("agent_id") == hid and u["status"] == "in_progress"),
              key=lambda u: u["coverage_id"])
if len(obj["units"]) != len(mine):
    sys.exit(f"count mismatch: {len(obj['units'])} in result, {len(mine)} assigned to {hid}")
for u, real in zip(obj["units"], mine):
    u["coverage_id"] = real["coverage_id"]
    u["reviewed_paths"] = sorted({p for c in u["checks"] for p in c.get("reviewed_paths", [])})
json.dump(obj, open(path, "w", encoding="utf-8"), ensure_ascii=False)
print(hid, "mapped", len(mine))
