#!/usr/bin/env python3
"""Fold critic-1's three proposed units into the run-5 ledger.

Two become planned hunter units (lifecycle races around the F6 lock; CPU cost of long agent commands in policy
and preview). The third (AuditLog._lock contention, login throttle, extract_novnc) is recorded deferred: the
budget cap of 30 cannot cover a third hunter plus its validation, and its desktop-WS part is already a
confirmed record. Critic-named companion blocks that do not exist in the skill are mapped to existing ones.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, ledger, save_ledger  # noqa: E402
from seed5 import unit  # noqa: E402

C = json.load(open(f"{RUN}/agents/critic-1/result.json", encoding="utf-8"))["missing_units"]
MAP = {"DATA-ISOLATION-AND-LIFECYCLE.md#Snapshots and restore": "DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state",
       "DATA-ISOLATION-AND-LIFECYCLE.md#Delete and retention": "DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use",
       "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Algorithmic complexity":
           "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation"}
HUNTERS = ["h-lifecycle", "h-policy-cpu", None]
# Canonical refs are capped at 1024 characters; long critic boundaries are condensed here and kept in full in
# x_critic_boundary.
SHORT = {
    "h-lifecycle": "Agent and human actions versus sandbox lifecycle state after the F6 fix (PR #18): _lifecycle "
                   "(service.py:500-505) serialises only pause/resume/snapshot/restore/delete, while call_tool, decide, "
                   "_snapshot, import_file, takeover and GUI bursts never take it. Invariant: after restore or delete "
                   "returns, no agent or approved action writes to, snapshots or records results for the old container "
                   "or a deleted sandbox; no snapshot row or image is orphaned or bound to the wrong container_id; and a "
                   "lifecycle call cannot be starved or deadlocked by tool calls, takeover or burst close holding "
                   "_snap_locks, gui_lock or concurrency slots (and _life_locks does not grow without bound).",
    "h-policy-cpu": "Agent to control-plane availability: pure-Python policy and preview parsing (Policy.decide, "
                    "_split_segments, shlex passes, _raw_hits, preview glob/walk) of an agent command up to the 8 MiB "
                    "body cap, with no per-command length cap, holds the GIL shared with the event loop and human "
                    "threads (hunter measurement: 4.96 s for a 128 KiB command, 4 concurrent per sandbox). Invariant: no "
                    "agent-supplied argument makes evaluation cost more than a small bounded amount of CPU, memory or "
                    "container exec time before rejection or queueing, and the human API stays responsive.",
    None: "Agent and unauthenticated clients to human availability and audit evidence: AuditLog.recent/verify scan the "
          "agent-grown table under the same _lock append needs (fail-closed log_human returns 503 while it is held), "
          "verify loads the whole table, the F8 login throttle shares one global window, and F5 extract_novnc holds a "
          "global lock across docker create. Invariant: no agent or unauthenticated sequence holds these locks long "
          "enough to refuse human actions, exhaust memory, or hide credential-guessing evidence.",
}
L = ledger()
for c, hid in zip(C, HUNTERS):
    comp = [MAP.get(b, b) for b in c["selected_companion_blocks"]]
    u = unit(c["surface"], SHORT[hid], c["subsystem"], c["attack_class"], c["starting_paths"], comp,
             [(e["block"], e["reason"]) for e in c["excluded_blocks"]], hid,
             source="Proposed by post-wave critic critic-1 (agents/critic-1/result.json); companion block names mapped "
                    "to existing skill blocks where the critic named a non-existent one.")
    u["wave"] = 2
    u["x_critic_boundary"] = c["boundary"]
    if hid is None:
        u["status"] = "deferred"
        u["unresolved"] = ["Deferred: proposed by post-wave critic critic-1. The owner's budget cap of 30 cannot cover a "
                           "third new hunter plus its validation (budget_cannot_reserve_critics_and_validation). The "
                           "desktop-WebSocket part of this lock contention is already the confirmed record "
                           "agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop."]
    assert u["coverage_id"] not in {x["coverage_id"] for x in L}
    L.append(u)
save_ledger(L)
print(len(L), "units")
