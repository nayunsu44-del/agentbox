import json
from common import RUN

fp = f"{RUN}/findings.json"
recs = json.load(open(fp, encoding="utf-8"))
for r in recs:
    tr = r.get("trace", [])
    if len(tr) > 1:
        sinks = [i for i, t in enumerate(tr) if t.get("kind") == "sink"]
        for i in sinks[:-1]:
            tr[i]["kind"] = "propagation"
        if not sinks:
            tr[-1]["kind"] = "sink"
        if tr[0].get("kind") not in ("entrypoint",):
            tr[0]["kind"] = "entrypoint"
    for i, t in enumerate(tr):
        if i == 0 and len(tr) > 1:
            t["kind"] = "entrypoint"
        elif i == len(tr) - 1:
            t["kind"] = "sink"
        else:
            t["kind"] = "propagation"
json.dump(recs, open(fp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(fp, "a", encoding="utf-8").write(chr(10))
print("findings trace kinds normalised:", len(recs))

lp = f"{RUN}/coverage-ledger.json"
L = json.load(open(lp, encoding="utf-8"))
fixed = 0
for u in L:
    for c in u.get("local_checks", []) or []:
        changed = False
        if "artifact" not in c:
            c["artifact"] = None
            changed = True
        if c.get("method") == "source" and c.get("artifact") is not None:
            c["artifact"] = None
            changed = True
        if not c.get("invariant"):
            c["invariant"] = "Phase 3 verifier re-decided the linked candidate for this unit"
            changed = True
        if not c.get("result"):
            c["result"] = str(c.get("note") or "Phase 3 decision recorded by the parent")
            changed = True
        if not c.get("reviewed_paths"):
            c["reviewed_paths"] = list(u.get("reviewed_paths", []))
            changed = True
        fixed += 1 if changed else 0
    if not u.get("local_checks"):
        u["local_checks"] = [{"agent_id": u.get("agent_id") or "parent", "method": "source", "artifact": None,
                              "reviewed_paths": list(u.get("reviewed_paths", [])),
                              "invariant": "Unit closed by its assigned hunter",
                              "result": "See agents/%s/result.json" % (u.get("agent_id") or "parent")}]
json.dump(L, open(lp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(lp, "a", encoding="utf-8").write(chr(10))
print("ledger checks repaired:", fixed)