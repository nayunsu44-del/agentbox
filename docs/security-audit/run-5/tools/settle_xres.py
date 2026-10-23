#!/usr/bin/env python3
"""Close the h-xres unit's two unresolved runtime facts with parent-live evidence (outside the agent budget).

The hunter left the unit blocked on two facts only the real desktop image can show. The parent ran
agents/parent-live/parent_live_xres.py; its output agents/parent-live/artifacts/xres.json settles both, so the
unit gets two parent-live checks and becomes covered (the hunter's own checks are kept unchanged).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ledger, save_ledger  # noqa: E402

L = ledger()
(u,) = [u for u in L if u["x_hunter"] == "h-xres"]
assert u["status"] == "blocked" and len(u["unresolved"]) == 2
art = "agents/parent-live/artifacts/xres.json"
u["local_checks"] += [
    {"agent_id": "parent-live", "reviewed_paths": ["agentbox/sandbox_desktop.py"], "method": "local", "artifact": art,
     "invariant": "In the real agentbox-desktop:0.1 image the _WINDOW_OWNERS pipeline loads libX11/libXRes, Xvfb answers "
                  "XResQueryClientIds, and the returned pids are the container-namespace pids of the processes that own "
                  "Xfce windows.",
     "result": "Holds. desktop_processes returned window owners 96 xfwm4, 121 xfce4-panel, 137 xfdesktop, 148 and 152 "
               "(panel plugin wrappers), all uid 1001 in the container's ps; xdotool's client-declared _NET_WM_PID for "
               "the same windows names the same pids."},
    {"agent_id": "parent-live", "reviewed_paths": ["agentbox/gui_bursts.py", "agentbox/gui_state.py"],
     "method": "local", "artifact": art,
     "invariant": "A uid-1001 process without a window started in a new session during an agent GUI burst is stopped "
                  "when the burst closes.",
     "result": "Holds. After an agent click (200) opened a burst, a setsid sleep 601 (pid 265) started as the desktop "
               "user was stopped at the idle close (gui_processes_stopped reason idle, pid 265) and was gone from ps."},
]
u["reviewed_paths"] = sorted({p for c in u["local_checks"] for p in c["reviewed_paths"]})
u["unresolved"] = []
u["status"] = "covered"
u["x_parent_live"] = "agents/parent-live/parent_live_xres.py -> " + art
save_ledger(L)
print("h-xres unit covered")
