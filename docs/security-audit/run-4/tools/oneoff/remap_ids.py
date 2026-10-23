#!/usr/bin/env python3
"""Map a transcribed hunter result onto its exact ledger coverage IDs by position.

usage: remap_ids.py <hunter-id> <raw.json>

The parent sometimes retypes a hunter result from the agent's closing message; the
URL-encoded coverage IDs are long and easy to mistype. This rewrites units[i].coverage_id
to the ledger's i-th unit for that hunter (ordered by coverage_id) and refuses unless the
counts match and every ledger unit is still in_progress for that hunter.
"""
import json
import sys

sys.path.insert(0, "./tools")
from common import RUN, ledger

hid, path = sys.argv[1], sys.argv[2]
obj = json.load(open(path, encoding="utf-8"))
mine = sorted((u for u in ledger() if u.get("agent_id") == hid and u["status"] == "in_progress"),
              key=lambda u: u["coverage_id"])
units = obj["units"]
if len(units) != len(mine):
    sys.exit(f"count mismatch: {len(units)} in result, {len(mine)} assigned to {hid}")
for u, real in zip(units, mine):
    u["coverage_id"] = real["coverage_id"]
json.dump(obj, open(path, "w", encoding="utf-8"), ensure_ascii=False)
print(hid, "->", [u["coverage_id"][:28] for u in units])
