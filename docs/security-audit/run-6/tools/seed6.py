#!/usr/bin/env python3
"""Seed the run-6 coverage ledger (focused follow-up, parent-written).

run-6 holds:
  * all seven units run-5 left `deferred` (top 4: same_origin scheme, container output reader caps,
    approval preview truthfulness, AuditLog._lock contention; plus the remaining 3: Docker data-root
    disk accounting, GUI burst covers() container_id binding, control-character filter sink completeness),
    carried with prior_status prior_deferred and refreshed line references at 530b29e; and
  * four units for code the run-5 fixes changed (PRs #24 and #25): _BodyLimit pre-read credential gate
    and deploy caps, DesktopControl split lock and WS threadpool/retention archive cleanup, GUI burst
    takeover-lease gate in _snapshot/decide, and TOOL_ARG_MAX/preview caps/_relex_changes.
Excluded-block reasons only reference units that exist in this run-6 ledger or self-contained scope facts.
"""
import json
import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, save_ledger  # noqa: E402

R5 = json.load(open(f"{RUN}/../run-5/coverage-ledger.json", encoding="utf-8"))
R5_DEFERRED = [u for u in R5 if u["status"] == "deferred"]

FP_R4_ORIGIN = "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare"
FP_R4_READERS = "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap"
FP_R4_PREVIEW = "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets"
FP_R4_COVERS = "agentbox/service.py:_call_tool:needs-snapshot-gate-before-gui-lock-lets-burstless-gui-input-after-handback"
FP_R4_BIDI = "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized"

FP_R5_PREAUTH = "agentbox/api.py:preauth-request-body-read-before-principal"
FP_R5_APPROVALS = "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention"
FP_R5_WS = "agentbox/desktop_ws.py:relay+agentbox/api.py:desktop_ws:blocking-sqlite-audit-docker-on-event-loop"
FP_R5_POLICY_CPU = "agentbox/policy.py:_words:per-token-shlex-relex-without-command-length-cap"
FP_R5_PREVIEW = "agentbox/preview.py:preview_command:per-operand-container-exec-without-count-or-time-bound"
FP_R5_PRUNE = "agentbox/retention.py:prune:archive-unlinked-after-committed-prune-on-interrupt"
FP_R5_GUI_LEASE = "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease"


def cid(refs):
    enc = lambda v: quote(v, safe="-._~")  # noqa: E731
    return "::".join(enc(refs[k]) for k in ("surface", "boundary", "subsystem", "attack_class"))


def domain(f, *names):
    return [f"{f}#Core discipline", *[f"{f}#{n}" for n in names], f"{f}#Universal moves", f"{f}#Validation rules"]


def unit(surface, boundary, subsystem, attack_class, paths, companions, excluded, hunter, prior_status="new",
         ordinary=None, prior_unit=None, prior_fps=(), source=None):
    refs = {"surface": surface, "boundary": boundary, "subsystem": subsystem, "attack_class": attack_class}
    u = {"coverage_id": cid(refs), "canonical_refs": refs, **refs, "starting_paths": paths,
         "ordinary_attack_class_block": ordinary, "selected_companion_blocks": companions,
         "excluded_blocks": [{"block": b, "reason": r} for b, r in excluded], "prior_status": prior_status,
         "attempts": [], "wave": 1, "status": "planned", "agent_id": None, "reviewed_paths": [],
         "local_checks": [], "result_fingerprints": [], "unresolved": [], "x_hunter": hunter,
         "x_prior_unit": prior_unit, "x_prior_fingerprints": list(prior_fps)}
    if source:
        u["x_source"] = source
    return u


def deferred(match):
    (u,) = [u for u in R5_DEFERRED if u["surface"].startswith(match)]
    return u


def main():
    u_orig = deferred("Browser-origin checks")
    u_read = deferred("Container output readers")
    u_prev = deferred("Approval-preview truthfulness")
    u_lock = deferred("AuditLog._lock")
    u_disk = deferred("Docker data-root growth")
    u_cov = deferred("Container identity binding")
    u_disp = deferred("Completeness of the PR #19")

    L = [
        # ---- 1. Top 4 deferred from run-5 + paired PR #24/#25 changed-code units --------
        unit(
            "Browser-origin checks on cookie-authenticated routes: api.py same_origin (api.py:221-223) used by "
            "screen_principal (api.py:235, every /ui and screen route), the login/ticket handlers (web.py:159,169) "
            "and the desktop WebSocket upgrade (api.py:442); a missing Origin header is accepted",
            u_orig["boundary"],
            u_orig["subsystem"],
            u_orig["attack_class"],
            u_orig["starting_paths"],
            u_orig["selected_companion_blocks"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
              "Pre-read body cost and WebSocket pre-accept work are owned by the h-origin body-limit unit and the "
              "h-locks-ws unit in this ledger; this unit is about the origin/authorisation decision.")],
            "h-origin",
            "prior_deferred",
            prior_unit=u_orig["coverage_id"],
            prior_fps=[FP_R4_ORIGIN],
            source="run-5 critic-2 deferred unit 1 of 6; line refs refreshed to 530b29e.",
        ),
        unit(
            "Pre-read credential gate in _BodyLimit (api.py:85-96, authenticated at api.py:185-199), /login 64 KiB "
            "anonymous body cap (_ANON_BODY_PATHS/_ANON_BODY_MAX, api.py:53-54), Caddy per-route request_body "
            "(@upload vs @other, deploy/Caddyfile:8-15), compose mem_limit (deploy/docker-compose.yml:20), and "
            "uvicorn limit_concurrency (config.py:68, cli.py:126-127)",
            "Pre-authentication body-read and memory amplification after PR #25 (run-5 N1 fix): _BodyLimit checks "
            "has_body (Content-Length > 0 or Transfer-Encoding present), caps /login at 64 KiB, and for every other "
            "body-carrying request runs authenticated(headers) in the threadpool before letting the app read or "
            "decode any bytes, returning 401 when neither a valid Bearer token (human or live agent) nor a valid "
            "session cookie (SimpleCookie D.COOKIE with session_scope) is present. Invariant: an unauthenticated "
            "client cannot make the control plane read, buffer, JSON-parse or multipart-spool more than 64 KiB, or "
            "bypass the credential gate via HTTP framing, header casing/duplication, path variations or cookie parsing.",
            "agentbox/api.py#_BodyLimit/_ANON_BODY_PATHS/authenticated + agentbox/config.py#max_connections + "
            "agentbox/cli.py#cmd_serve + deploy/Caddyfile + deploy/docker-compose.yml",
            "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
            ["agentbox/api.py", "agentbox/web.py", "agentbox/desktop.py", "agentbox/config.py",
             "agentbox/cli.py", "deploy/Caddyfile", "deploy/docker-compose.yml"],
            domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Pre-authentication work imbalance",
                   "Unbounded buffering and cardinality")
            + ["WEB-PROTOCOL-AND-AUTH.md#Request framing and desynchronization"],
            [("CLIENT-SIDE.md#Cross-site WebSocket request use",
              "WebSocket origin checks are owned by the sibling h-origin same_origin unit, and WebSocket threadpool "
              "handling is owned by h-locks-ws.")],
            "h-origin",
            "new",
            prior_fps=[FP_R5_PREAUTH],
            source="PR #25 changed code (run-5 N1 fix at 530b29e).",
        ),
        unit(
            "Container output readers that fully buffer attacker-controlled bytes: sandbox.py exec_run without a "
            "read cap or container-side timeout (list_dir ls -la :442, exists :475, delete :497, outbox_list find "
            "-printf :548, is_dir :537, plus _expand glob :578 and _walk find -print0 :584 which gained _PREVIEW_TIMEOUT "
            "in PR #24) versus the capped _Head exec path (:85,:427)",
            u_read["boundary"],
            u_read["subsystem"],
            u_read["attack_class"],
            u_read["starting_paths"],
            u_read["selected_companion_blocks"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
              "Policy and preview CPU/call-count bounds are owned by the h-preview-argcap unit in this ledger.")],
            "h-readers",
            "prior_deferred",
            prior_unit=u_read["coverage_id"],
            prior_fps=[FP_R4_READERS],
            source="run-5 critic-2 deferred unit 2 of 6; line refs refreshed to 530b29e.",
        ),
        unit(
            u_disk["surface"],
            u_disk["boundary"],
            u_disk["subsystem"],
            u_disk["attack_class"],
            u_disk["starting_paths"],
            u_disk["selected_companion_blocks"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
              "Not an unauthenticated path; pre-auth work is owned by h-origin.")],
            "h-readers",
            "prior_deferred",
            prior_unit=u_disk["coverage_id"],
            source="run-5 critic-2 deferred unit 4 of 6.",
        ),
        unit(
            u_prev["surface"],
            u_prev["boundary"],
            u_prev["subsystem"],
            u_prev["attack_class"],
            u_prev["starting_paths"],
            u_prev["selected_companion_blocks"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
              "Preview call-count, timeout and policy CPU bounds are owned by the sibling h-preview-argcap unit.")],
            "h-preview-argcap",
            "prior_deferred",
            prior_unit=u_prev["coverage_id"],
            prior_fps=[FP_R4_PREVIEW],
            source="run-5 critic-2 deferred unit 3 of 6.",
        ),
        unit(
            "Agent tool-argument length cap and policy/preview/approval bounds (PR #24): TOOL_ARG_MAX (service.py:49, "
            "322-329), policy._relex_changes (policy.py:40-49, 73), preview_command PREVIEW_CALLS_MAX/NOTES_MAX and "
            "operand deduplication (preview.py:70-160), sandbox._PREVIEW_TIMEOUT/_preview_ok (sandbox.py:39, 104-106, "
            "578-594), and pending-approval bound_payload(preview) + pre-create disk_low() recheck (service.py:357-362)",
            "Agent-to-control-plane CPU, container-exec and SQLite amplification across tool calls (PR #24 fixes for "
            "run-5 F1, F5, F6): _call_tool rejects non-content args over 16 KiB (measured on str or json.dumps) with "
            "413 before audit/policy; _words skips re-lexing only when _relex_changes is False; preview_command caps "
            "expand/walk calls at 40 (10 s timeout each) and notes at 50; pending approvals bound preview to 128 KiB "
            "and re-check disk_low before creation. Invariant: no agent tool call can bypass TOOL_ARG_MAX, cause "
            "superlinear or multi-second policy CPU, trigger unbounded preview execs, or write an oversized pending "
            "approval row past disk_low, and _relex_changes does not drop any dangerous command detection.",
            "agentbox/service.py#TOOL_ARG_MAX/_call_tool + agentbox/policy.py#_relex_changes/_words + "
            "agentbox/preview.py#PREVIEW_CALLS_MAX/NOTES_MAX/preview_command + agentbox/sandbox.py#_PREVIEW_TIMEOUT/"
            "_preview_ok/_expand/_walk",
            "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
            ["agentbox/service.py", "agentbox/policy.py", "agentbox/preview.py", "agentbox/sandbox.py",
             "agentbox/approvals.py", "agentbox/audit.py", "tests/test_m5_unit.py"],
            domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Superlinear parsing, matching, or evaluation",
                   "Quota-accounting scope and reset gaps", "Unbounded buffering and cardinality")
            + ["ATTACK-CLASSES.md#Injection"],
            [("AI-AND-LLM.md#Action-confirmation and approval binding",
              "Approval card semantic truthfulness is owned by the sibling h-preview-argcap unit.")],
            "h-preview-argcap",
            "new",
            ordinary="ATTACK-CLASSES.md#Injection",
            prior_fps=[FP_R5_APPROVALS, FP_R5_POLICY_CPU, FP_R5_PREVIEW],
            source="PR #24 changed code (run-5 F1, F5, F6 fixes at 530b29e).",
        ),
        unit(
            u_lock["surface"],
            u_lock["boundary"],
            u_lock["subsystem"],
            u_lock["attack_class"],
            u_lock["starting_paths"],
            u_lock["selected_companion_blocks"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps",
              "Approval-row size caps and Docker disk accounting are owned by h-preview-argcap and h-readers in this ledger.")],
            "h-locks-ws",
            "prior_deferred",
            prior_unit=u_lock["coverage_id"],
            source="run-5 critic-1 wave-2 deferred unit.",
        ),
        unit(
            "DesktopControl lock split (_db_lock vs _lock, desktop.py:90-305), desktop WebSocket threadpool offload "
            "and shielded disconnect logging (api.py:441, desktop_ws.py:19-24, 76, 93-113), and retention.prune "
            "post-COMMIT archive preservation (retention.py:104-145)",
            "Event-loop responsiveness, lock ordering and archive durability (PR #24 fixes for run-5 F3 and F4): "
            "DesktopControl separates _db_lock (SQLite) from _lock (in-memory leases/conns/gui_locks) with lock order "
            "_db_lock -> _lock; desktop_ws and relay run SQLite, Docker vnc_command and audit logging in threadpools "
            "and shield disconnect logging before drop_conn; retention.prune checks audit_anchor before unlinking the "
            "archive on exception. Invariant: no WebSocket or desktop path blocks the asyncio event loop on SQLite or "
            "Docker, no method violates _db_lock -> _lock ordering or exposes inconsistent lease/session state across "
            "the two locks, and no failure after COMMIT in prune deletes a referenced archive.",
            "agentbox/desktop.py#DesktopControl + agentbox/desktop_ws.py#relay + agentbox/api.py#desktop_ws + "
            "agentbox/retention.py#prune",
            "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
            ["agentbox/desktop.py", "agentbox/desktop_ws.py", "agentbox/api.py", "agentbox/retention.py",
             "tests/test_m5_unit.py", "tests/test_retention.py"],
            domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Worker, pool, and priority starvation")
            + ["DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion"],
            [("CLIENT-SIDE.md#Cross-site WebSocket request use",
              "WebSocket same_origin authorisation is owned by the h-origin unit in this ledger.")],
            "h-locks-ws",
            "new",
            prior_fps=[FP_R5_WS, FP_R5_PRUNE],
            source="PR #24 changed code (run-5 F3 and F4 fixes at 530b29e).",
        ),
        unit(
            u_cov["surface"],
            u_cov["boundary"],
            u_cov["subsystem"],
            u_cov["attack_class"],
            u_cov["starting_paths"],
            u_cov["selected_companion_blocks"],
            [("DATA-ISOLATION-AND-LIFECYCLE.md#Stale authorization and derived copy use",
              "Delete/snapshot-image orphaning was refuted in run-5; this unit focuses on GUI burst container_id binding.")],
            "h-gui-burst",
            "prior_deferred",
            prior_unit=u_cov["coverage_id"],
            prior_fps=[FP_R4_COVERS],
            source="run-5 critic-2 deferred unit 5 of 6.",
        ),
        unit(
            "GUI burst opening and approval execution against human takeover leases (PR #24): AgentBox._snapshot "
            "burst open under gui_lock with _check_control and reset_timers (service.py:265-284), call_tool "
            "_human_blocked handler (service.py:396-397, 411-419), and decide pre-snapshot lease/_takeover_pending "
            "gate (service.py:498-514)",
            "Agent GUI burst isolation from human takeover sessions (PR #24 fix for run-5 F2): _snapshot acquires "
            "gui_lock and calls _check_control before mark_snapshot/bursts.open, resetting burst timers and raising "
            "HumanControl after recording the snapshot if a lease or takeover is pending; decide refuses approved "
            "GUI_INPUT before _snapshot when a lease is active or takeover is pending. Invariant: no agent GUI burst "
            "can be opened or remain open while a human takeover lease is held or pending, no human-started process "
            "is killed by close_idle/next_burst, and no lock ordering cycle exists between _snap_locks, gui_lock, "
            "and _lifecycle.",
            "agentbox/service.py#_snapshot/call_tool/_call_tool/_human_blocked/decide/takeover + "
            "agentbox/gui_bursts.py#needs_snapshot/open/close/reset_timers/covers",
            "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy",
            ["agentbox/service.py", "agentbox/gui_bursts.py", "agentbox/gui_state.py", "agentbox/desktop.py",
             "tests/test_m5_unit.py", "tests/test_m2_unit.py"],
            domain("DESKTOP-MOBILE-AND-LOCAL-IPC.md", "Privileged helper as confused deputy")
            + ["AI-AND-LLM.md#Action-confirmation and approval binding"],
            [("CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure",
              "Process kill runs as uid 1001 inside the sandbox container.")],
            "h-gui-burst",
            "new",
            prior_fps=[FP_R5_GUI_LEASE],
            source="PR #24 changed code (run-5 F2 fix at 530b29e).",
        ),
        unit(
            u_disp["surface"],
            u_disp["boundary"],
            u_disp["subsystem"],
            u_disp["attack_class"],
            u_disp["starting_paths"],
            u_disp["selected_companion_blocks"],
            [],
            "h-display",
            "prior_deferred",
            prior_unit=u_disp["coverage_id"],
            prior_fps=[FP_R4_BIDI],
            source="run-5 critic-2 deferred unit 6 of 6.",
        ),
    ]
    for u in L:
        assert len(u["coverage_id"]) <= 65536
    save_ledger(L)
    print(len(L), "units;", sorted({u["x_hunter"] for u in L}))


if __name__ == "__main__":
    main()
