#!/usr/bin/env python3
"""Seed the run-7 coverage ledger (focused follow-up on 530b29e..3580df0, parent-written).

run-6 closed all 11 units (no `deferred`), so there is no prior_deferred unit. run-7 holds seven new
units for the delta: the unaudited run-6 fixes (7dbda9e), the refactor (5bb3c17), and five IF-1 units
(d4e956e, 79d8211, ccaf367, a0a186c). Excluded-block reasons only reference units in this ledger or
self-contained scope facts.
"""
import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import save_ledger  # noqa: E402

# run-6 fingerprints fixed in 7dbda9e (prior confirmed / needs_validation)
FP6_F1 = "agentbox/gui_bursts.py:GuiBursts.covers:container-identity-binding-gap-across-restore"
FP6_F2 = "agentbox/audit.py:AuditLog:table-growth-lock-contention-and-verify-memory"
FP6_F3 = "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets"
FP6_N1 = "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare"
FP6_N2 = "agentbox/sandbox.py:container-output-readers-without-_Head-byte-cap"
FP6_N3 = "agentbox/service.py:disk_low-unmonitored-docker-data-root"
# run-5 fingerprints whose gates the refactor moved
FP5_GUI_LEASE = "agentbox/service.py:_snapshot:gui-burst-opened-under-takeover-lease"
FP5_APPROVALS = "agentbox/audit.py:append:agent-grown-rows-in-shared-sqlite-have-no-aggregate-bound-or-retention"


def cid(refs):
    enc = lambda v: quote(v, safe="-._~")  # noqa: E731
    return "::".join(enc(refs[k]) for k in ("surface", "boundary", "subsystem", "attack_class"))


def domain(f, *names):
    return [f"{f}#Core discipline", *[f"{f}#{n}" for n in names], f"{f}#Universal moves", f"{f}#Validation rules"]


def unit(surface, boundary, subsystem, attack_class, paths, companions, excluded, hunter, prior_status="new",
         ordinary=None, prior_fps=(), source=None):
    refs = {"surface": surface, "boundary": boundary, "subsystem": subsystem, "attack_class": attack_class}
    u = {"coverage_id": cid(refs), "canonical_refs": refs, **refs, "starting_paths": paths,
         "ordinary_attack_class_block": ordinary, "selected_companion_blocks": companions,
         "excluded_blocks": [{"block": b, "reason": r} for b, r in excluded], "prior_status": prior_status,
         "attempts": [], "wave": 1, "status": "planned", "agent_id": None, "reviewed_paths": [],
         "local_checks": [], "result_fingerprints": [], "unresolved": [], "x_hunter": hunter,
         "x_prior_unit": None, "x_prior_fingerprints": list(prior_fps)}
    if source:
        u["x_source"] = source
    return u


def main():
    L = [
        unit(
            "Completeness of the 7dbda9e fixes for run-6 F1-F3 and N1-N3: GuiBursts.covers container_id check and "
            "restore_sandbox bursts.end (gui_bursts.py:72-83, service.py:625-635); idx_audit_sandbox_id and batched "
            "_verify_live outside _lock (audit.py:38, 337-400); _expand ~/{ handling and head -z -n cap plus preview "
            "notes (sandbox.py:600-626, preview.py:88-114); same_origin scheme check and HSTS (api.py:221-235, "
            "web.py:177,187, cli.py:102, deploy/Caddyfile:8); _exec_head, outbox head -c, screenshot link/size checks "
            "(sandbox.py:41, 422-461, 564-574, sandbox_desktop.py:37, 113-123); DockerRootDir and disk_low "
            "(sandbox.py:179-183, service.py:461-485)",
            "Each run-6 fix must close its root cause for all variants without introducing a new defect: no GUI input "
            "runs under a burst whose baseline belongs to another container; verify() cannot hold AuditLog._lock for "
            "long, load the table, loop forever, or report a broken chain as intact; the rm preview does not show a "
            "real target as absent without a warning; a cross-scheme Origin is refused whenever cookies are secure "
            "(including behind the TLS proxy and when secure_cookie is off by configuration); no container reader "
            "buffers unbounded output or follows an attacker link; disk_low sees the filesystem that holds container "
            "layers and snapshot images or fails closed when it cannot.",
            "agentbox/gui_bursts.py#covers/end + agentbox/service.py#restore_sandbox/disk_low + agentbox/audit.py#"
            "_verify_live/verify/verify_archives + agentbox/sandbox.py#_expand/_exec_head/list_dir/outbox_list/"
            "_detect_runtime + agentbox/preview.py#preview_command + agentbox/sandbox_desktop.py#screenshot + "
            "agentbox/api.py#same_origin/secure_cookie + deploy/Caddyfile",
            "ATTACK-CLASSES.md#Business logic",
            ["agentbox/gui_bursts.py", "agentbox/service.py", "agentbox/audit.py", "agentbox/sandbox.py",
             "agentbox/preview.py", "agentbox/sandbox_desktop.py", "agentbox/api.py", "agentbox/web.py",
             "agentbox/cli.py", "deploy/Caddyfile", "deploy/docker-compose.yml", "tests/test_m5_unit.py"],
            domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Unbounded buffering and cardinality",
                   "Reachable fatal error or deadlock")
            + ["WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport", "WEB-PROTOCOL-AND-AUTH.md#Host and forwarded-header trust",
               "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU",
               "AI-AND-LLM.md#Action-confirmation and approval binding"],
            [("CLIENT-SIDE.md#Cross-site WebSocket request use",
              "The WebSocket upgrade shares same_origin, which is in this unit; no separate WebSocket origin unit."),
             ("DATA-ISOLATION-AND-LIFECYCLE.md#Restore reintroduces invalid state",
              "Restore is only in scope for the GUI burst binding in this unit; the refactor unit owns burst gating.")],
            "h-fixes",
            ordinary="ATTACK-CLASSES.md#Business logic",
            prior_fps=[FP6_F1, FP6_F2, FP6_F3, FP6_N1, FP6_N2, FP6_N3],
            source="7dbda9e (run-6 F1-F3 and N1-N3 fixes, unaudited).",
        ),
        unit(
            "Behaviour preservation of the 5bb3c17 refactor: GuiBursts.human_active (gui_bursts.py:55-70) used by "
            "needs_snapshot and decide (service.py:545), _request_approval split out of _call_tool "
            "(service.py:354-449), unchanged _check_control/_gui_locked/_snapshot/call_tool gates (service.py:173-198, "
            "300-352), and the shared test doubles (tests/conftest.py, tests/test_m2_unit.py, tests/test_m5_unit.py)",
            "The refactor claims no behaviour change. Invariant: for every tool and actor, the approval order (pending "
            "cap -> preview -> bound_payload -> disk_low recheck -> capture -> row -> audit) and its failure handling, "
            "the arguments stored, previewed, logged and executed, and the GUI burst decisions (needs_snapshot, "
            "decide refusal under a lease or pending takeover, _snapshot opening only after _check_control under "
            "gui_lock, covers) are identical to 530b29e+7dbda9e, and the run-3..run-6 GUI and argument fixes still "
            "hold; the conftest doubles do not hide a regression the old per-file doubles would have caught.",
            "agentbox/service.py#_call_tool/_request_approval/decide/_snapshot/_check_control + "
            "agentbox/gui_bursts.py#human_active/needs_snapshot + tests/conftest.py",
            "AI-AND-LLM.md#Action-confirmation and approval binding",
            ["agentbox/service.py", "agentbox/gui_bursts.py", "agentbox/desktop.py", "agentbox/approvals.py",
             "agentbox/audit.py", "tests/conftest.py", "tests/test_m2_unit.py", "tests/test_m5_unit.py"],
            domain("AI-AND-LLM.md", "Action-confirmation and approval binding")
            + ["DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged helper as confused deputy",
               "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Pending-action and user-presence confusion",
               "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota-accounting scope and reset gaps"],
            [("SUPPLY-CHAIN-AND-RELEASE.md#Cache, artifact, and workspace trust mixing",
              "Test doubles are reviewed only for whether they mask a behaviour change; CI trust is out of scope.")],
            "h-refactor",
            prior_fps=[FP5_GUI_LEASE, FP5_APPROVALS],
            source="5bb3c17 refactor (claimed no behaviour change).",
        ),
        unit(
            "Instruction-file name classification: instruction_files._norm/_parts/kind (instruction_files.py:26-108) "
            "and every caller (policy.Policy.decide :214-232, service._preview/_run_tool/import_file/export_file/"
            "outbox, IF.scan, paths_in_words)",
            "kind() must classify a name as an instruction file whenever a downstream file system, archive tool, "
            "browser download, or coding agent would treat it as one of _NAMES/_DIRS/.github dirs, and must not flag "
            "ordinary names so often that normal writes go to approval. Check residual bypasses after a0a186c: "
            "combining marks, NFD/NFC/NFKD forms, default-ignorable characters, other case foldings, 8.3 short "
            "names, names a browser rewrites on download (download attribute, Content-Disposition filename*), "
            "trailing characters other than dot/space, and path splitting of backslash and '..'.",
            "agentbox/instruction_files.py#_norm/_parts/kind + agentbox/policy.py#decide + agentbox/api.py#outbox_file",
            "ATTACK-CLASSES.md#Resource and file handling",
            ["agentbox/instruction_files.py", "agentbox/policy.py", "agentbox/service.py", "agentbox/api.py",
             "agentbox/templates/_outbox.html", "tests/test_instruction_files.py"],
            ["ATTACK-CLASSES.md#Resource and file handling", "AI-AND-LLM.md#Core discipline",
             "AI-AND-LLM.md#Indirect injection through retrieved or ingested content",
             "AI-AND-LLM.md#Validation rules",
             "DATA-ISOLATION-AND-LIFECYCLE.md#Export and backup scope expansion"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Superlinear parsing, matching, or evaluation",
              "kind() cost on long paths is bounded by TOOL_ARG_MAX; scan cost is owned by the h-if-scan unit.")],
            "h-if-kind",
            ordinary="ATTACK-CLASSES.md#Resource and file handling",
            source="d4e956e, ccaf367, a0a186c (name normalisation; single-pass review NV items 1-2 fixed).",
        ),
        unit(
            "Policy target versus write target for instruction files: service._resolved/_policy_args/_preview "
            "(service.py:235-289), SandboxManager.resolve (sandbox.py:487-496), write_file tmp+mv and delete_file "
            "(sandbox.py:502-525), Policy.decide match.instruction_files with resolved_path (policy.py:214-232), "
            "default_policy.yaml version 4 rule order, decide() executing stored args (service.py:520-575)",
            "An agent-caused write or delete must not land in an instruction file or instruction directory without "
            "approval. Invariant: the object policy judged (requested path or the single realpath -m at decide time) "
            "is the object mv/rm finally touches, including directory links as the last component, links changed "
            "between decide and execution or during the approval wait (by allowlisted exec, write_file, GUI tools or "
            "concurrent calls), and resolve() failures (timeouts, errors, concurrency) cannot be induced to fall back "
            "to the requested path; user policies mixing instruction_files with other rules evaluate in a safe order.",
            "agentbox/service.py#_resolved/_policy_args/_preview/_call_tool/decide + agentbox/sandbox.py#resolve/"
            "write_file/delete_file + agentbox/policy.py#decide + agentbox/default_policy.yaml",
            "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local file ownership and TOCTOU",
            ["agentbox/service.py", "agentbox/sandbox.py", "agentbox/policy.py", "agentbox/default_policy.yaml",
             "agentbox/instruction_files.py", "tests/test_instruction_files.py",
             "tests/test_instruction_files_acceptance.py"],
            domain("DESKTOP-MOBILE-AND-LOCAL-IPC.md", "Local file ownership and TOCTOU")
            + ["AI-AND-LLM.md#Action-confirmation and approval binding",
               "DATA-ISOLATION-AND-LIFECYCLE.md#Policy and query disagreement",
               "ATTACK-CLASSES.md#Access control"],
            [("AI-AND-LLM.md#Excessive agency and confused-deputy authority",
              "GUI-tool approval bypass is the documented N-1 limitation; only a new angle is in scope here.")],
            "h-if-policy",
            ordinary="ATTACK-CLASSES.md#Access control",
            source="a0a186c (single-pass F2 fix: resolved_path) plus single-pass NV item: F2 in-container write step.",
        ),
        unit(
            "Read-result boundary for instruction files: instruction_files.mark_read/with_notice/notice "
            "(instruction_files.py:111-137), agent.py ToolClient.call_text (:118-126), mcp_server.py read_file and "
            "instructions (:46-52, 119-125), exec notice in service._run_tool (:133-141)",
            "When the agent reads an instruction file, the agent-visible text must carry the notice and an "
            "unforgeable boundary that encloses exactly the file content, identically for MCP and the built-in loop. "
            "Check: tag collision redraw, the truncation marker inside the boundary, content that imitates the "
            "notice or a boundary with a different tag, exec results (notice only, no boundary), reads through a "
            "link or a non-instruction name pointing at an instruction file (mark_read uses the requested path), "
            "list_dir, and whether a user read-blocking rule (README) can be bypassed through a link.",
            "agentbox/instruction_files.py#mark_read/with_notice + agentbox/agent.py#call_text + "
            "agentbox/mcp_server.py#read_file + agentbox/service.py#_run_tool",
            "AI-AND-LLM.md#Indirect injection through retrieved or ingested content",
            ["agentbox/instruction_files.py", "agentbox/agent.py", "agentbox/mcp_server.py", "agentbox/service.py",
             "agentbox/policy.py", "agentbox/sandbox.py", "tests/test_instruction_files.py"],
            domain("AI-AND-LLM.md", "Indirect injection through retrieved or ingested content",
                   "Prompt role and provenance confusion"),
            [("AI-AND-LLM.md#Sensitive context extraction",
              "The LLM-provider data path is a documented limitation and out of scope.")],
            "h-if-notice-sinks",
            source="d4e956e, 79d8211 (notice and random boundary).",
        ),
        unit(
            "Human-facing sinks for attacker-chosen instruction-file names, paths and content: _created.html "
            "(oneline), _outbox.html (badge, data-notify/data-text, href urlencode, download attribute), "
            "_approvals.html full-content <pre> polled every 2 s (index.html:25, sandbox.html:25), sandbox.html upload "
            "JS, web._shown/_oneline/describe(instruction_files_found) (web.py:35-100), cli._safe/cmd_create/"
            "_show_approval (cli.py:33-35, 142-150, 208-217), api.outbox_file Content-Disposition (api.py:398-404)",
            "Every new sink must pass attacker strings through autoescape plus _shown/oneline (web) or _safe (CLI): no "
            "markup or attribute injection, no bidi/invisible reordering, no fake rows or lines, no header injection; "
            "and rendering up to 20 pending full-content approval cards per sandbox (1 MiB each) every 2 s must not "
            "freeze the human UI or the control plane.",
            "agentbox/templates/_created.html + agentbox/templates/_outbox.html + agentbox/templates/_approvals.html + "
            "agentbox/web.py#_shown/_oneline/describe + agentbox/cli.py#_safe/cmd_create/_show_approval + "
            "agentbox/api.py#outbox_file",
            "AI-AND-LLM.md#Insecure output rendering",
            ["agentbox/templates/_created.html", "agentbox/templates/_outbox.html", "agentbox/templates/_approvals.html",
             "agentbox/templates/sandbox.html", "agentbox/templates/index.html", "agentbox/templates/_notify.html",
             "agentbox/web.py", "agentbox/cli.py", "agentbox/display.py", "agentbox/api.py", "agentbox/approvals.py"],
            domain("AI-AND-LLM.md", "Insecure output rendering")
            + ["CLIENT-SIDE.md#DOM-based XSS", "WEB-PROTOCOL-AND-AUTH.md#Response-header injection",
               "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality"],
            [("CLIENT-SIDE.md#Clickjacking", "_NoFraming is unchanged by the delta and was covered in run-4.")],
            "h-if-notice-sinks",
            source="d4e956e, a0a186c (single-pass F1, F4, F6, F7 sink fixes).",
        ),
        unit(
            "Source-folder scan at sandbox creation: instruction_files.scan (instruction_files.py:150-193) called "
            "synchronously in AgentBox.create_sandbox (service.py:577-597), _found_payload/FOUND_PATH_MAX "
            "(service.py:778-786) and bound_payload, web.describe and the create card",
            "The scan must bound the time and memory a create request spends (including a single blocking scandir or "
            "stat on a slow, FUSE or network directory, and per-directory entry buffering), report complete=False "
            "whenever the list may be partial, not hold locks or request threads that block other humans or agents, "
            "and its audit record must keep the count and truthfully mark a truncated list after bound_payload.",
            "agentbox/instruction_files.py#scan + agentbox/service.py#create_sandbox/_found_payload + "
            "agentbox/audit.py#bound_payload + agentbox/web.py#describe",
            "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Worker, pool, and priority starvation",
            ["agentbox/instruction_files.py", "agentbox/service.py", "agentbox/audit.py", "agentbox/web.py",
             "agentbox/api.py", "agentbox/cli.py", "tests/test_instruction_files.py"],
            domain("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", "Worker, pool, and priority starvation",
                   "Unbounded buffering and cardinality")
            + ["DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers"],
            [("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Pre-authentication work imbalance",
              "create_sandbox is a human-only route; pre-auth body handling is unchanged since run-6.")],
            "h-if-scan",
            source="d4e956e, a0a186c (single-pass F3, F5 fixes).",
        ),
    ]
    for u in L:
        assert len(u["coverage_id"]) <= 65536
    save_ledger(L)
    print(len(L), "units;", sorted({u["x_hunter"] for u in L}))


if __name__ == "__main__":
    main()
