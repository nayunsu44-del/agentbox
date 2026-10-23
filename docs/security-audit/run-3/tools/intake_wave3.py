#!/usr/bin/python3 -I
"""Apply the resumed wave-3 results (run-3): Phase 3 records v17-v19 into findings.json, critic-3's proposed
units into the ledger (deferred for budget), and the agent count into run-metadata.json.

usage: AUDIT_SCRATCHPAD=<dir> intake_wave3.py <critic-3 agent-output-file>

Phase 3 records are copied unchanged from agents/<id>/result.json (Phase 5 then checks them as final records).
critic-3's raw final message is stored as agents/critic-3/result.json. Its missing units get the same shape as
critic-2's deferred units: status deferred, no owner, the critic's reason in `unresolved`.
"""
import json
import os
import sys
from urllib.parse import quote

RUN = "/home/user/agentbox/docs/security-audit/run-3"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest5 import final_message  # noqa: E402

PHASE3 = ["v17", "v18", "v19"]
BUDGET_NOTE = ("budget_cannot_reserve_critics_and_validation: proposed by post-wave-3 critic (critic-3); "
               "with 74 of 80 agents spent, the remaining budget covers Phase 5 for v17-v19 only")


def load(name):
    return json.load(open(f"{RUN}/{name}", encoding="utf-8"))


def dump(name, obj):
    with open(f"{RUN}/{name}", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def main():
    raw = final_message(sys.argv[1]).strip()
    critic = json.loads(raw)
    assert set(critic) == {"missing_units", "reassign_ids", "reassign_reasons", "resolved_prior_leads", "stop"}
    with open(f"{RUN}/agents/critic-3/result.json", "w", encoding="utf-8") as f:
        f.write(raw + "\n")

    findings = load("findings.json")
    have = {r["fingerprint"] for r in findings}
    for vid in PHASE3:
        rec = load(f"agents/{vid}/result.json")["record"]
        assert rec["fingerprint"] not in have, rec["fingerprint"]
        findings.append(rec)
    findings.sort(key=lambda r: r["fingerprint"])
    dump("findings.json", findings)

    ledger = load("coverage-ledger.json")
    by_fp = {fp: u for u in ledger for fp in u["result_fingerprints"]}
    for vid in PHASE3:
        rec = load(f"agents/{vid}/result.json")["record"]
        u = by_fp[rec["fingerprint"]]
        note = f"phase3 {rec['verdict']} ({rec['severity']['overall_severity']}) by {vid}, awaiting Phase 5"
        u["x_decisions"][rec["fingerprint"]] = note
        u["x_phase5"][rec["fingerprint"]] = "pending"
        u["unresolved"] = [f"phase5_pending: {vid} Phase 3 {rec['verdict']}; Phase 5 record verifier p5-{vid}"]
    for m in critic["missing_units"]:
        refs = {k: m[k] for k in ("surface", "boundary", "subsystem", "attack_class")}
        ledger.append({
            "coverage_id": "::".join(quote(refs[k], safe="") for k in ("surface", "boundary", "subsystem", "attack_class")),
            "canonical_refs": refs, **refs,
            "starting_paths": m["starting_paths"], "ordinary_attack_class_block": None,
            "selected_companion_blocks": m["selected_companion_blocks"], "excluded_blocks": m["excluded_blocks"],
            "prior_status": "new", "attempts": [], "wave": 4, "status": "deferred", "agent_id": None,
            "reviewed_paths": [], "local_checks": [], "result_fingerprints": [],
            "unresolved": [f"{BUDGET_NOTE}. Critic's reason: {m['reason']}"],
            "x_source": "critic-3 missing_units",
        })
    ledger.sort(key=lambda u: u["coverage_id"])  # the validator requires lexicographic order
    dump("coverage-ledger.json", ledger)

    meta = load("run-metadata.json")
    spent = meta["agents_spent_so_far"]
    spent["phase3_v18_v19_sonnet_resumed"] = 2
    spent["post_wave3_critic_sonnet_resumed"] = 2   # first resumed run lost to a container restart
    meta["agents_spent_total"] = sum(spent.values())
    meta["x_critic3"] = {"missing_units": len(critic["missing_units"]), "stop": critic["stop"],
                         "resolved_prior_leads": critic["resolved_prior_leads"]}
    dump("run-metadata.json", meta)
    print("findings", len(findings), "ledger", len(ledger), "spent", meta["agents_spent_total"])


if __name__ == "__main__":
    main()
