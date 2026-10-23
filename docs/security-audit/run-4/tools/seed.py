#!/usr/bin/python3 -I
"""Seed the run-4 coverage ledger from the run-3 ledger and the current (post-refactor) source.

usage: seed.py

Every run-3 unit becomes current work: all relevant source changed (fixes c1f88da..d915713 and the
refactor PRs #11-#14), so no unit is carried as same-source. Assignment block maps (attack class,
selected companion blocks, exclusions) are kept from run-3; canonical surface/boundary/subsystem refs
and starting paths are rewritten to the current source objects. One new unit covers the lifecycle
consolidation from refactor PR 1. x_prior_unit links each unit to its run-3 coverage_id.
"""
import json
import unicodedata
import urllib.parse

ROOT = "/home/user/agentbox/docs/security-audit"
RUN = f"{ROOT}/run-4"

# run-3 unit index -> (surface, boundary, subsystem, starting_paths, prior_status, hunter)
CUR = {
 0: ("agentbox/gui_bursts.py#GuiBursts state shared by tool-pool threads (call_tool, decide) and human threads (expire_stale polls, takeover, handback, end_desktop, lifecycle methods)",
     "agentbox/gui_bursts.py#GuiBursts open/close/close_idle/end/reset_timers ordering + per-sandbox burst locks + _busy_lock",
     "agentbox/gui_bursts.py + agentbox/service.py#_snapshot/_run_tool/takeover/_handback_locked/end_desktop/decide",
     ["agentbox/gui_bursts.py", "agentbox/service.py", "agentbox/desktop.py", "agentbox/api.py", "agentbox/web.py"], "prior_deferred", "h-gui-race"),
 1: ("GUI-burst writes outside /workspace by uid 1001 (/home/desktop, /tmp, /dev/shm, /run/user, XDG dirs) that persist through snapshot, restore or restart",
     "images/desktop/agentbox-desktop-start#/home/desktop reset at start + agentbox/gui_state.py#workspace manifest scope",
     "images/desktop + agentbox/sandbox.py#restore/start + agentbox/gui_bursts.py",
     ["images/desktop/agentbox-desktop-start", "images/desktop/Dockerfile", "agentbox/sandbox.py", "agentbox/gui_bursts.py", "agentbox/gui_state.py"], "prior_confirmed_changed_source", "h-container"),
 2: None,  # filled below (prior_deferred)
 3: None,
 4: ("agentbox/api.py#POST /sandboxes/{sid}/tools/{tool} -> REQUIRE_APPROVAL on desktop templates",
     "agentbox/service.py#_call_tool approval creation: per-sandbox pending cap + capture PNG lifecycle (drop_captures on decide/expire/delete)",
     "agentbox/service.py + agentbox/approvals.py",
     ["agentbox/service.py", "agentbox/approvals.py", "agentbox/api.py", "agentbox/web.py"], "prior_confirmed_changed_source", "h-queue"),
 5: ("agent-controlled audit content (tool args, file names, process args) and timeline readers (GET /audit, /ui/audit, agentbox audit)",
     "agentbox/audit.py#hash chain + append-only triggers + list ordering/limit",
     "agentbox/audit.py + agentbox/web.py#audit + agentbox/cli.py#cmd_audit",
     ["agentbox/audit.py", "agentbox/web.py", "agentbox/cli.py", "agentbox/api.py"], "prior_confirmed_changed_source", "h-audit"),
 6: ("agentbox/agent.py#LLM loop + agentbox/mcp_server.py tools",
     "agentbox/agent.py#prompt-injection to tool action and operator terminal output (approval is the only control)",
     "agentbox/agent.py + agentbox/mcp_server.py + agentbox/cli.py#cmd_agent",
     ["agentbox/agent.py", "agentbox/mcp_server.py", "agentbox/cli.py", "agentbox/display.py"], "prior_confirmed_changed_source", "h-wild"),
 7: ("agentbox/api.py#GET /sandboxes/{sid}/desktop + takeover/handback + state + /login + /logout",
     "agentbox/desktop.py#ticket redeem + session scope + session revocation on human-token rotation + lease",
     "agentbox/desktop.py + agentbox/api.py + agentbox/web.py",
     ["agentbox/desktop.py", "agentbox/api.py", "agentbox/web.py", "agentbox/config.py"], "prior_confirmed_changed_source", "h-session"),
 8: ("agentbox/api.py#POST /approvals/{aid} + agentbox/web.py#POST /ui/approvals/{aid}/{decision} + agentbox/cli.py#cmd_approve",
     "agentbox/service.py#decide executes the agent's original args after human approval",
     "agentbox/service.py + agentbox/approvals.py",
     ["agentbox/service.py", "agentbox/approvals.py", "agentbox/api.py", "agentbox/web.py", "agentbox/cli.py"], "prior_covered_changed_source", "h-policy"),
 9: ("agentbox/api.py#POST /sandboxes source_dir + agentbox/web.py#POST /ui/sandboxes",
     "agentbox/sandbox.py#create source_dir overlap check (filesystem identity) + NonRecursive bind",
     "agentbox/sandbox.py#create",
     ["agentbox/sandbox.py", "agentbox/api.py", "agentbox/web.py", "agentbox/config.py"], "prior_confirmed_changed_source", "h-files"),
 10: ("agentbox/api.py#POST /sandboxes/{sid}/desktop/takeover + handback + POST /sandboxes/{sid}/restore + DELETE /sandboxes/{sid} (end_desktop)",
     "agentbox/service.py#desktop.gui_lock held across timed _x GUI execs + takeover/handback 30 s bound + takeover-pending gate",
     "agentbox/service.py + agentbox/sandbox_desktop.py + agentbox/desktop.py",
     ["agentbox/service.py", "agentbox/sandbox_desktop.py", "agentbox/desktop.py", "agentbox/gui_bursts.py", "agentbox/api.py"], "prior_needs_validation", "h-gui-race"),
 11: ("agentbox/api.py#POST /sandboxes/{sid}/tools/{click,type,key,screenshot}",
     "agentbox/gui_bursts.py#GUI burst snapshot + fail-closed baseline + gui_changes + stray kill (N-1 partial mitigation)",
     "agentbox/gui_bursts.py + agentbox/service.py#_run_tool",
     ["agentbox/gui_bursts.py", "agentbox/service.py", "agentbox/sandbox.py", "agentbox/sandbox_desktop.py"], "prior_needs_validation", "h-gui-burst"),
 12: ("agentbox/api.py#POST /sandboxes/{sid}/tools/{tool} + every expire_stale caller",
     "agentbox/api.py#tool_pool + agentbox/service.py#call_tool tool_concurrency + agentbox/gui_bursts.py#burst close pool",
     "agentbox/service.py + agentbox/gui_bursts.py + agentbox/api.py",
     ["agentbox/service.py", "agentbox/gui_bursts.py", "agentbox/api.py", "agentbox/web.py"], "prior_confirmed_changed_source", "h-pool"),
 13: ("agentbox/api.py#POST /sandboxes/{sid}/tools/{write_file,delete_file,GUI} + snapshot routes",
     "agentbox/service.py#snapshot quota + _snap_locks + GUI burst snapshots",
     "agentbox/service.py + agentbox/sandbox.py#snapshot",
     ["agentbox/service.py", "agentbox/sandbox.py", "agentbox/gui_bursts.py"], "prior_covered_changed_source", "h-pool"),
 14: ("agentbox/api.py#POST /sandboxes/{sid}/tools/exec",
     "agentbox/policy.py#Policy.decide read-only-exec allowlist",
     "agentbox/policy.py + agentbox/sandbox.py#exec",
     ["agentbox/policy.py", "agentbox/sandbox.py", "agentbox/default_policy.yaml"], "prior_covered_changed_source", "h-policy"),
 15: ("agentbox/api.py#WebSocket /sandboxes/{sid}/desktop/ws -> agentbox/desktop_ws.py#relay",
     "agentbox/api.py#cookie session + same_origin + lease on WebSocket + agentbox/desktop_ws.py#session re-check",
     "agentbox/desktop_ws.py + agentbox/api.py",
     ["agentbox/desktop_ws.py", "agentbox/api.py", "agentbox/desktop.py", "agentbox/sandbox_desktop.py"], "prior_covered_changed_source", "h-session"),
 16: ("agentbox/api.py#all JSON and browser routes",
     "agentbox/api.py#principal + human_only + screen_human + desktop_human",
     "agentbox/api.py + agentbox/web.py",
     ["agentbox/api.py", "agentbox/web.py", "agentbox/desktop.py"], "prior_covered_changed_source", "h-preauth"),
 17: ("agentbox/api.py#tools read_file/write_file/delete_file/list_dir + POST files + GET outbox",
     "agentbox/sandbox.py#safe_path + _workspace_path + clean_name + FIFO guard",
     "agentbox/sandbox.py",
     ["agentbox/sandbox.py", "agentbox/sandbox_common.py", "agentbox/api.py", "agentbox/web.py"], "prior_covered_changed_source", "h-files"),
 18: ("agentbox/cli.py#cmd_serve + agentbox/api.py#create_app factory + deploy/*",
     "agentbox/cli.py#bind_problem + runtime_problem + sandbox.py runtime selection",
     "agentbox/cli.py + deploy",
     ["agentbox/cli.py", "agentbox/api.py", "agentbox/config.py", "deploy"], "prior_covered_changed_source", "h-lifecycle"),
 19: ("agentbox/web.py#/ui pages + agentbox/desktop.py#page rendered in a frame",
     "agentbox/api.py#X-Frame-Options + CSP frame-ancestors 'self' on cookie-authenticated pages + SameSite=Strict + same_origin",
     "agentbox/api.py + agentbox/web.py + agentbox/desktop.py",
     ["agentbox/api.py", "agentbox/web.py", "agentbox/desktop.py"], "prior_needs_validation", "h-webui"),
 20: ("agentbox/web.py#/ui/* + /login + /logout",
     "agentbox/api.py#same_origin + SameSite=Strict HttpOnly cookie",
     "agentbox/api.py + agentbox/web.py",
     ["agentbox/api.py", "agentbox/web.py", "agentbox/desktop.py"], "prior_needs_validation", "h-webui"),
 21: ("approval card impact table and request-time screen capture for gated exec/GUI calls",
     "agentbox/preview.py#preview + split_segments + expand/walk callbacks: system-computed 'affected' list",
     "agentbox/preview.py + agentbox/sandbox.py#preview + agentbox/service.py#_preview/_capture",
     ["agentbox/preview.py", "agentbox/sandbox.py", "agentbox/service.py", "agentbox/templates"], "prior_confirmed_changed_source", "h-policy"),
 22: ("code running inside the sandbox container (uid 1000 agent, uid 1001 desktop)",
     "agentbox/sandbox.py#container hardening flags + root-run docker execs (sandbox.py, sandbox_desktop.py)",
     "agentbox/sandbox.py + agentbox/sandbox_desktop.py + images/desktop",
     ["agentbox/sandbox.py", "agentbox/sandbox_desktop.py", "images/desktop"], "prior_covered_changed_source", "h-container"),
 23: ("container output and agent request bodies (tool args, uploads)",
     "agentbox/sandbox.py#_Head exec cap + read/outbox/manifest/screenshot caps + agentbox/service.py#_logged_args cap",
     "agentbox/sandbox.py + agentbox/sandbox_common.py + agentbox/service.py",
     ["agentbox/sandbox.py", "agentbox/sandbox_common.py", "agentbox/sandbox_desktop.py", "agentbox/service.py", "agentbox/gui_state.py"], "prior_confirmed_changed_source", "h-queue"),
 24: ("container output: ps, xdotool getwindowpid, find -printf manifest",
     "agentbox/gui_state.py#_parse_ps + gui_strays + _parse_manifest + diff_manifest",
     "agentbox/gui_state.py + agentbox/sandbox_desktop.py#desktop_processes/kill_processes",
     ["agentbox/gui_state.py", "agentbox/sandbox_desktop.py", "agentbox/sandbox.py", "agentbox/gui_bursts.py"], "prior_needs_validation", "h-gui-burst"),
 25: ("container-controlled strings rendered to humans (outbox names, gui_changes paths, ps args, exec output, errors, approval cards)",
     "agentbox/display.py#escape_controls + agentbox/web.py#describe/_shown/finalize + Jinja autoescape + agentbox/cli.py#_safe",
     "agentbox/display.py + agentbox/web.py + agentbox/cli.py + agentbox/templates",
     ["agentbox/display.py", "agentbox/web.py", "agentbox/cli.py", "agentbox/templates"], "prior_confirmed_changed_source", "h-webui"),
 26: ("every audit append (tool args, results, errors, GUI records)",
     "agentbox/audit.py#mask_text + _mask",
     "agentbox/audit.py",
     ["agentbox/audit.py", "agentbox/service.py", "agentbox/gui_bursts.py"], "prior_covered_changed_source", "h-audit"),
 27: ("whole-repo#basic exposures", "whole-repo#obvious controls (secrets, debug, cookies, CORS, redirects, errors)", "whole-repo",
     ["agentbox", "deploy", "images"], "prior_covered_changed_source", "h-preauth"),
 28: ("whole-repo#undocumented/edge surfaces", "whole-repo#feature interactions not covered by other units", "whole-repo",
     ["agentbox", "images", "deploy"], "prior_confirmed_changed_source", "h-wild"),
}


def enc(s):
    assert s == unicodedata.normalize("NFC", s) and s == s.strip() and s
    return urllib.parse.quote(s.encode("utf-8"), safe="-._~")


def cid(c):
    parts = [c["surface"], c["boundary"], c["subsystem"], c["attack_class"]]
    return "::".join(enc(p) for p in parts)


def main():
    old = json.load(open(f"{ROOT}/run-3/coverage-ledger.json", encoding="utf-8"))
    out = []
    for i, u in enumerate(old):
        cur = CUR.get(i)
        if cur is None:  # deferred critic-3 units keep their wording; paths rewritten to current files
            c = dict(u["canonical_refs"])
            sp = sorted(set(p for p in u["starting_paths"]) | ({"agentbox/gui_bursts.py"} if i == 2 else {"agentbox/desktop_ws.py"}))
            hunter = {2: "h-audit", 3: "h-preauth"}[i]
            prior = "prior_deferred"
            label = u
        else:
            s, b, sub, sp, prior, hunter = cur
            c = {"surface": s, "boundary": b, "subsystem": sub, "attack_class": u["canonical_refs"]["attack_class"]}
            label = {"surface": s, "boundary": b, "subsystem": sub, "attack_class": u["attack_class"]}
        unit = {
            "coverage_id": cid(c), "canonical_refs": c,
            "surface": label["surface"], "boundary": label["boundary"], "subsystem": label["subsystem"],
            "attack_class": label["attack_class"] if cur else u["attack_class"],
            "starting_paths": sp,
            "ordinary_attack_class_block": u["ordinary_attack_class_block"],
            "selected_companion_blocks": u["selected_companion_blocks"],
            "excluded_blocks": u["excluded_blocks"],
            "prior_status": prior, "attempts": [], "wave": 1, "status": "planned", "agent_id": None,
            "reviewed_paths": [], "local_checks": [], "result_fingerprints": [], "unresolved": [],
            "x_prior_unit": u["coverage_id"], "x_prior_fingerprints": u["result_fingerprints"], "x_hunter": hunter,
        }
        out.append(unit)
    new = {"surface": "agentbox/api.py#POST /sandboxes/{sid}/pause|resume|snapshots|restore + DELETE /sandboxes/{sid} + agentbox/web.py#POST /ui/sandboxes/{sid}/snapshot|restore|delete",
           "boundary": "agentbox/service.py#AgentBox.pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox ordering (audit, end_desktop, bursts, captures, timers) + api/web guard",
           "subsystem": "agentbox/service.py#lifecycle methods (refactor PR 1)",
           "attack_class": "DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use"}
    out.append({
        "coverage_id": cid(new), "canonical_refs": new, **new,
        "starting_paths": ["agentbox/service.py", "agentbox/api.py", "agentbox/web.py", "agentbox/gui_bursts.py", "agentbox/desktop.py", "agentbox/sandbox.py"],
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Business logic",
        "selected_companion_blocks": ["DATA-ISOLATION-AND-LIFECYCLE.md#Core discipline", "DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use",
                                      "DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state", "DATA-ISOLATION-AND-LIFECYCLE.md#Retention and queued-work overrun",
                                      "DATA-ISOLATION-AND-LIFECYCLE.md#Universal moves", "DATA-ISOLATION-AND-LIFECYCLE.md#Validation rules"],
        "excluded_blocks": [{"block": "DATA-ISOLATION-AND-LIFECYCLE.md#Missing tenant or owner enforcement", "reason": "route-level principal checks are unit agentbox/api.py#all JSON and browser routes (Access control)"},
                            {"block": "DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion", "reason": "snapshots are docker images on the same host; no export path in source"}],
        "prior_status": "new", "attempts": [], "wave": 1, "status": "planned", "agent_id": None,
        "reviewed_paths": [], "local_checks": [], "result_fingerprints": [], "unresolved": [],
        "x_prior_unit": None, "x_prior_fingerprints": [], "x_hunter": "h-lifecycle"})
    ids = [u["coverage_id"] for u in out]
    assert len(ids) == len(set(ids)), "duplicate coverage_id"
    out.sort(key=lambda u: u["coverage_id"])
    with open(f"{RUN}/coverage-ledger.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
        f.write("\n")
    from collections import Counter
    print(len(out), "units;", dict(Counter(u["prior_status"] for u in out)), dict(Counter(u["x_hunter"] for u in out)))


if __name__ == "__main__":
    main()
