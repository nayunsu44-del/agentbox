#!/usr/bin/env python3
"""Record the final-clean critic's proposed units as deferred (the owner's cap of 30 is spent).

Canonical refs are capped at 1024 characters; a longer critic field is cut at a sentence boundary and kept in full
in x_critic_<field>. Critic-named companion blocks are kept only when they exist in the skill.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, block, ledger, save_ledger  # noqa: E402
from seed5 import unit  # noqa: E402


def fit(text, cap=1000):
    if len(text) <= cap:
        return text
    cut = text[:cap].rsplit(". ", 1)[0]
    return cut + "."


def exists(ref):
    try:
        block(ref)
        return True
    except (KeyError, ValueError, OSError):
        return False


C = json.load(open(f"{RUN}/agents/critic-2/result.json", encoding="utf-8"))["missing_units"]
L = ledger()
for i, c in enumerate(C, 1):
    comp = [b for b in c["selected_companion_blocks"] if exists(b)]
    u = unit(fit(c["surface"]), fit(c["boundary"]), fit(c["subsystem"]), fit(c["attack_class"]), c["starting_paths"],
             comp, [(e["block"], e["reason"]) for e in c["excluded_blocks"]], None,
             source=f"Proposed by final-clean critic critic-2 (agents/critic-2/result.json, unit {i} of {len(C)}, "
                    "critic's order = its value ranking).")
    u.update(wave=3, status="deferred",
             unresolved=["Deferred: proposed by the final-clean critic critic-2 after the owner's budget cap of 30 was "
                         "spent (budget_cannot_reserve_critics_and_validation). Next run. Critic reason: " + c["reason"]])
    for k in ("surface", "boundary"):
        if fit(c[k]) != c[k]:
            u[f"x_critic_{k}"] = c[k]
    assert u["coverage_id"] not in {x["coverage_id"] for x in L}
    L.append(u)
save_ledger(L)
print(len(L), "units")
