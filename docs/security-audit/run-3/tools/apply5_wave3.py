#!/usr/bin/python3 -I
"""Apply Phase 5 for the wave-3 records v17-v19 (run-3): all three verifiers returned `verified`, so findings.json
is unchanged and only the ledger's x_decisions/x_phase5/unresolved and run-metadata.json are updated.

usage: apply5_wave3.py
"""
import json

RUN = "/home/user/agentbox/docs/security-audit/run-3"
IDS = ["v17", "v18", "v19"]


def load(name):
    return json.load(open(f"{RUN}/{name}", encoding="utf-8"))


def dump(name, obj):
    with open(f"{RUN}/{name}", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def main():
    findings = {r["fingerprint"]: r for r in load("findings.json")}
    ledger = load("coverage-ledger.json")
    by_fp = {fp: u for u in ledger for fp in u["result_fingerprints"]}
    for vid in IDS:
        res = load(f"agents/p5-{vid}/result.json")
        assert res["decision"] == "verified", vid
        fp = res["fingerprint"]
        assert findings[fp]["verdict"] == "confirmed"
        u = by_fp[fp]
        u["x_decisions"][fp] = "confirmed"
        u["x_phase5"][fp] = f"verified [p5-{vid}]"
        u["unresolved"] = []
    dump("coverage-ledger.json", ledger)
    meta = load("run-metadata.json")
    meta["agents_spent_so_far"]["phase5_record_verifiers_sonnet_wave3"] = len(IDS)
    meta["agents_spent_total"] = sum(meta["agents_spent_so_far"].values())
    dump("run-metadata.json", meta)
    print("spent", meta["agents_spent_total"])


if __name__ == "__main__":
    main()
