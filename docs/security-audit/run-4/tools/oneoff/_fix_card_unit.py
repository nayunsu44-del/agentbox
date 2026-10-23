import json
from common import RUN
FP = "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets"
p = f"{RUN}/coverage-ledger.json"
L = json.load(open(p, encoding="utf-8"))
hits = [u for u in L if "approval%20card" in u["coverage_id"]]
assert len(hits) == 1, [u["coverage_id"][:40] for u in hits]
u = hits[0]
u["status"] = "candidate"
u["result_fingerprints"] = [FP]
json.dump(L, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(p, "a", encoding="utf-8").write("\n")
print("fixed", u["coverage_id"][:40], u["status"])
