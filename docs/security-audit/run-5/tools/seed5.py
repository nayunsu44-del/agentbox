#!/usr/bin/env python3
"""Seed the run-5 coverage ledger (focused follow-up, parent-written).

run-5 does not re-audit the whole repository. Its ledger holds:
  * the three units run-4 left `deferred` (carried with prior_status prior_deferred, line refs
    refreshed to 346df29), and
  * four units for code the run-4 fixes changed (PRs #16-#22): retention/prune/anchor, disk guard
    and approval compaction, XRes window ownership, body-cap middleware and upload form.
Every other run-4 unit was covered at 9805d91; its code is either unchanged or folded into
these units. The approvals-table unit and the disk-guard unit share one hunter (same code).
"""
import json
import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN, save_ledger  # noqa: E402

R4 = json.load(open(f"{RUN}/../run-4/coverage-ledger.json", encoding="utf-8"))
R4_DEFERRED = [u for u in R4 if u["status"] == "deferred"]

FP_N2 = "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention"
FP_N4 = "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process"
FP_F1 = "agentbox/api.py:preauth-request-body-read-before-principal"
FP_F3 = "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap"
FP_F8 = "agentbox/web.py:unauthenticated-login-failure-audit-growth"


def cid(refs):
    enc = lambda v: quote(v, safe="-._~")  # noqa: E731  same unreserved set as the validator
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
    (u,) = [u for u in R4_DEFERRED if u["surface"].startswith(match)]
    return u


def main():
    gl, ws, ap = (deferred("A GUI burst opened while a human takeover"),
                  deferred("agentbox/api.py#WebSocket"), deferred("approvals table rows"))
    L = [
        # ---- run-4 deferred units -------------------------------------------------------
        unit(gl["surface"],
             "Agent GUI-burst enforcement (stray kill, gui_kept/gui_changes attribution) versus the human desktop "
             "session during a takeover: takeover closes the burst under gui_lock before installing the lease "
             "(service.py:571-589, close at 582), but _snapshot (service.py:261-277) closes and opens a burst without "
             "gui_lock or a lease check, reached from decide (service.py:440) and from call_tool after a "
             "needs_snapshot lease check (gui_bursts.py:55) that precedes a multi-second commit; an opened burst may "
             "survive the lease so close_idle (gui_bursts.py:154) or the next burst kills processes the human started "
             "or charges human edits to the agent.",
             gl["subsystem"], gl["attack_class"], gl["starting_paths"], gl["selected_companion_blocks"],
             [(e["block"], e["reason"]) for e in gl["excluded_blocks"]], "h-gui-lease", "prior_deferred",
             prior_unit=gl["coverage_id"], source="run-4 critic-2 deferred unit; boundary line refs refreshed to 346df29."),
        unit(ws["surface"], ws["boundary"], ws["subsystem"], ws["attack_class"], ws["starting_paths"],
             ws["selected_companion_blocks"], [(e["block"], e["reason"]) for e in ws["excluded_blocks"]],
             "h-ws", "prior_deferred", prior_unit=ws["coverage_id"],
             source="run-4 critic-1 deferred unit (api.py desktop_ws is now at api.py:408-418)."),
        unit(ap["surface"],
             "agentbox/approvals.py#create stores raw agent args and preview for pending rows without audit masking "
             "or a size cap (finish compacts them since PR #20), rows outlive sandbox deletion, and only the host "
             "prune command removes finished rows",
             ap["subsystem"], ap["attack_class"], ap["starting_paths"] + ["agentbox/retention.py"],
             ap["selected_companion_blocks"], [(e["block"], e["reason"]) for e in ap["excluded_blocks"]],
             "h-approvals", "prior_deferred", prior_unit=ap["coverage_id"], prior_fps=[FP_N2],
             source="run-4 critic-1 deferred unit; boundary updated for the PR #20 compaction."),
        # ---- code changed by the run-4 fixes -----------------------------------------------
        unit("agentbox/cli.py#agentbox prune --before --archive [--dry-run] + agentbox verify --archive (host CLI, "
             "direct SQLite) and every later AuditLog.verify()/append over a pruned database",
             "Audit-log tamper evidence across pruning: retention.prune drops and recreates the audit_no_delete "
             "trigger inside BEGIN IMMEDIATE, records an audit_anchor (last id/hash, archive sha256) and an "
             "audit_pruned row; verify() starts at the latest anchor and verify_archives() chains GENESIS -> "
             "archives -> live table. Invariant: a deletion or edit of audit history that the prune command did "
             "not perform is still detected, prune never removes pending/approved approvals or rows at/after the "
             "cutoff, and a failed prune leaves the database and archive consistent.",
             "agentbox/retention.py + agentbox/audit.py#SCHEMA/audit_anchor/latest_anchor/check_chain/read_archive/"
             "insert_record/append/verify/verify_archives + agentbox/cli.py#cmd_prune/cmd_verify",
             "ATTACK-CLASSES.md#Cryptography and secrets",
             ["agentbox/retention.py", "agentbox/audit.py", "agentbox/cli.py", "agentbox/approvals.py",
              "agentbox/service.py", "tests/test_retention.py"],
             domain("DATA-ISOLATION-AND-LIFECYCLE.md", "Export and backup scope expansion",
                    "Soft-delete and tombstone bypass")
             + ["DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU",
                "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Decompression and representation amplification"],
             [("AI-AND-LLM.md#Action-confirmation and approval binding",
               "Approval semantics are owned by the approvals-table unit; this unit only checks which approval rows "
               "prune removes.")],
             "h-retention", ordinary="ATTACK-CLASSES.md#Cryptography and secrets", prior_fps=[FP_N2]),
        unit("Every agent-reachable write to the shared control-plane SQLite file and host disk while "
             "AgentBox.disk_low() is true or near the threshold (tool calls, approval creation/expiry, GUI burst "
             "records, desktop and file routes), plus finished-approval row compaction",
             "Disk-pressure guard and approval compaction (PR #20): call_tool refuses agent calls with 507 when "
             "free space on db_path.parent is below AGENTBOX_MIN_FREE, api.py skips the agent approval_forbidden "
             "row, _finish rewrites finished rows' args/preview to the bounded audit shape, decide maps claim "
             "sqlite3.Error to 503 and expire_stale stops on sqlite3.Error. Invariant: an agent cannot keep "
             "growing the database or host disk past the guard through another route, and the human can still "
             "decide, delete and verify while low; compaction keeps what the approval card and audit need.",
             "agentbox/service.py#call_tool/disk_low/_finish/decide/expire_stale/log_best_effort + "
             "agentbox/approvals.py#finish + agentbox/api.py#call_tool route + agentbox/gui_bursts.py#_finish + "
             "agentbox/config.py#min_free_bytes",
             "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps",
             ["agentbox/service.py", "agentbox/approvals.py", "agentbox/api.py", "agentbox/gui_bursts.py",
              "agentbox/config.py", "agentbox/web.py", "agentbox/templates/_approvals.html"],
             domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Quota-accounting scope and reset gaps",
                    "Unbounded buffering and cardinality", "Retry storm and fail-open amplification",
                    "Unsafe recovery and capacity rollback"),
             [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
               "Unauthenticated request bodies are owned by the body-cap unit (h-bodylimit).")],
             "h-approvals", prior_fps=[FP_N2, FP_F3]),
        unit("GUI burst stray-process decision at burst close: desktop_processes (root ps + XRes window owners "
             "from a python3 -I ctypes script run as the desktop user via docker exec), gui_strays/gui_kept, and "
             "the per-sandbox kept set carried into the next burst baseline",
             "Window ownership used to spare uid-1001 processes from the stray kill now comes from the X server "
             "(XResQueryClientIds client pid via SO_PEERCRED) instead of the client-declared _NET_WM_PID; "
             "kept pids are excluded from the next baseline so they are re-judged. Invariant: a process the agent "
             "started during a burst cannot make itself or another process look window-owning or baseline, and "
             "any failure of the owner query fails toward stopping more processes.",
             "agentbox/sandbox_desktop.py#_WINDOW_OWNERS/desktop_processes + agentbox/gui_state.py#_new_processes/"
             "gui_strays/gui_kept + agentbox/gui_bursts.py#open/_stop_strays/_kept",
             "ATTACK-CLASSES.md#Business logic",
             ["agentbox/sandbox_desktop.py", "agentbox/gui_state.py", "agentbox/gui_bursts.py",
              "images/desktop/Dockerfile", "images/desktop/start.sh"],
             domain("DESKTOP-MOBILE-AND-LOCAL-IPC.md", "Claimed principal versus channel identity",
                    "Privileged helper as confused deputy", "Local file ownership and TOCTOU"),
             [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality",
               "Container-output reader caps are run-4 N3 (needs_validation, not re-hunted).")],
             "h-xres", ordinary="ATTACK-CLASSES.md#Business logic", prior_fps=[FP_N4]),
        unit("Every HTTP request before routing and authentication: _BodyLimit ASGI middleware (Content-Length "
             "and streamed bodies, upload path selection) + POST /sandboxes/{sid}/files multipart form + the /ui "
             "upload form + deploy/Caddyfile request_body",
             "Pre-authentication and per-request body caps (F1 fix, PR #16): JSON/form bodies capped at "
             "AGENTBOX_MAX_BODY, uploads at AGENTBOX_MAX_UPLOAD_BODY selected by method and path regex, multipart "
             "parsed only after screen_human. Invariant: an unauthenticated or agent client cannot make the server "
             "buffer, parse or spool more than the cap (or hang a worker) before auth, through any HTTP framing "
             "(chunked, missing or duplicate Content-Length, path variants, HEAD/other methods, root_path).",
             "agentbox/api.py#_BodyLimit/_UPLOAD_PATH/put_files/build + agentbox/web.py#upload form + "
             "agentbox/config.py#max_body_bytes/max_upload_body_bytes + deploy/Caddyfile",
             "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
             ["agentbox/api.py", "agentbox/web.py", "agentbox/config.py", "deploy/Caddyfile", "agentbox/cli.py"],
             domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Pre-authentication work imbalance",
                    "Unbounded buffering and cardinality", "File descriptor, handle, and temporary-resource leaks")
             + ["WEB-PROTOCOL-AND-AUTH.md#Request framing and desynchronization"],
             [("CLIENT-SIDE.md#Cross-site WebSocket request use",
               "WebSocket scopes bypass the middleware by design; the WebSocket unit (h-ws) owns pre-accept work.")],
             "h-bodylimit", prior_fps=[FP_F1, FP_F8]),
    ]
    for u in L:
        assert len(u["coverage_id"]) <= 65536
    save_ledger(L)
    print(len(L), "units;", sorted({u["x_hunter"] for u in L}))


if __name__ == "__main__":
    main()
