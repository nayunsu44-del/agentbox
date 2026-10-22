#!/usr/bin/python3 -I
"""Apply the Phase 5 outcomes to findings.json, the coverage ledger and run-metadata.json (run-3).

usage: apply5.py

Final record per fingerprint (see FINAL below):
  verified          -> findings.json record unchanged
  agents/<id>       -> the replacement record in agents/<id>/result.json; applied only when it was non-material
                       or an independent re-verifier (p5r-*) returned verified (or a non-material correction)
Records are re-sorted by fingerprint. Nothing else in a record is touched.
"""
import json

RUN = "/home/user/agentbox/docs/security-audit/run-3"

# fingerprint -> (Phase 5 verifier, final source, note)
FINAL = {
    "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare":
        ("p5-v01", "p5-v01", "replace (non-material wording: browsers tested, unsupported version cut-offs, apr_ id moved from blockers to description); applied directly"),
    "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines": ("p5-v02", None, "verified"),
    "agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe": ("p5-v03", None, "verified"),
    "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions": ("p5-v05", None, "verified"),
    "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass":
        ("p5-v06", "p5r-v06", "replace (material: promotion needs_validation -> confirmed low, parent-live l8); re-verifier p5r-v06 returned a non-material correction (lines, provenance, own sbx5 guard check, residual of fix 152b8e4), applied"),
    "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process":
        ("p5-v15", "p5-v15", "replace (material: root cause widened to window-presence heuristic); re-verified by p5r-v15 (verified)"),
    "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap":
        ("p5-v08", "p5-v08", "replace (remediation only: proposed fix returned early for write_file); applied directly"),
    "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit":
        ("p5-v09", "p5r-v09", "replace (material: l9 refutes self-release, answers blocker 1); re-verifier p5r-v09 returned a non-material correction (trace line 341 -> 339, provenance note), applied"),
    "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover":
        ("p5-v10", "p5-v10", "replace (material: l10 answers the bound blocker); re-verified by p5r-v10 (verified)"),
    "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency": ("p5-v11", None, "verified"),
    "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause": ("p5-v12", None, "verified"),
    "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized": ("p5-v13", None, "verified"),
    "agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve": ("p5-v14", None, "verified"),
}
# material replacements applied only because a fresh re-verifier returned verified
RECHECKED = {
    "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process": "p5r-v15",
    "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover": "p5r-v10",
}
# material replacements whose fresh re-verifier returned a non-material correction (same verdict and severity)
CORRECTED = {
    "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass": "p5-v06",
    "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit": "p5-v09",
}
REJECTED_NOT_REVERIFIED = "agentbox/cli.py:runtime_problem:runc-alias-io.containerd.runc.v2-bypasses-exposed-runc-guard"

NEW_LEAD = "agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion"
EXEC_UNIT_SURFACE = "agentbox/api.py#POST /sandboxes/{sid}/tools/exec"


def load(p):
    return json.load(open(f"{RUN}/{p}", encoding="utf-8"))


def dump(p, obj):
    with open(f"{RUN}/{p}", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def main():
    findings = load("findings.json")
    by_fp = {r["fingerprint"]: r for r in findings}
    assert set(by_fp) == set(FINAL) | {REJECTED_NOT_REVERIFIED}, "fingerprint set changed"
    for fp, (verifier, src, _) in FINAL.items():
        if src is None:
            assert load(f"agents/{verifier}/result.json") == {"decision": "verified", "fingerprint": fp}
            continue
        res = load(f"agents/{src}/result.json")
        assert res["decision"] == "replace" and res["record"]["fingerprint"] == fp
        if fp in RECHECKED:
            recheck = load(f"agents/{RECHECKED[fp]}/result.json")
            assert recheck == {"decision": "verified", "fingerprint": fp}, f"{fp}: re-verification did not pass"
        if fp in CORRECTED:
            first = load(f"agents/{CORRECTED[fp]}/result.json")["record"]
            assert (first["verdict"], first.get("severity", {}).get("overall_severity")) == \
                (res["record"]["verdict"], res["record"].get("severity", {}).get("overall_severity")), fp
        by_fp[fp] = res["record"]
    out = [by_fp[k] for k in sorted(by_fp)]
    dump("findings.json", out)

    ledger = load("coverage-ledger.json")
    verdict = {r["fingerprint"]: r["verdict"] for r in out}
    for u in ledger:
        fps = u.get("result_fingerprints") or []
        if fps:
            u["x_decisions"] = {fp: verdict[fp] for fp in fps}
            u["x_phase5"] = {fp: (FINAL[fp][2] + f" [{FINAL[fp][0]}]") if fp in FINAL else
                             "rejected in Phase 3; Phase 5 verifies confirmed and needs_validation records only"
                             for fp in fps}
        if u["surface"] == EXEC_UNIT_SURFACE and NEW_LEAD not in fps:
            u["status"] = "candidate"
            u["result_fingerprints"] = [NEW_LEAD]
            u["unresolved"] = ["validation_budget_exhausted: parent-live observation after Phase 3 (l9); no independent "
                               "candidate verifier ran because the owner-approved budget (63) was spent. Not a finding."]
            u["local_checks"].append({
                "agent_id": "parent-live",
                "reviewed_paths": ["agentbox/sandbox.py", "agentbox/default_policy.yaml"],
                "invariant": "An allowed exec cannot leave processes behind that keep the sandbox at its pids limit after the exec returns",
                "method": "local",
                "result": "Parent-live, unvalidated: an approval-free exec of 'tail -f /dev/null & ' x1100 filled pids to 1024/1024; bash failed to fork and exited 254 before timeout fired, so no group kill ran; ~1000 uid-1000 tails stayed and pids stayed at 1022/1024 after the exec returned and after a root docker exec pkill.",
                "artifact": "agents/parent-live/artifacts/l9_agent_pressure.out",
            })
            u["x_decisions"] = {NEW_LEAD: "unvalidated"}
            u["x_phase5"] = {NEW_LEAD: "not run (no Phase 3 validation)"}
    dump("coverage-ledger.json", ledger)


if __name__ == "__main__":
    main()
