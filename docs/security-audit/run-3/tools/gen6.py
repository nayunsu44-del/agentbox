#!/usr/bin/python3 -I
"""Phase 6: derive FINDINGS-DETAIL.md and NEEDS-VALIDATION.md from the final records in findings.json (run-3).

usage: gen6.py

The record text (English) is copied verbatim; only headings, ordering and the fix-status lines are added here,
so the prose cannot disagree with the JSON. REPORT.md is written by hand from the same records.
"""
import json

RUN = "/home/user/agentbox/docs/security-audit/run-3"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# fixes committed on the working branch after Phase 3, with their regression tests
FIX = {
    "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines":
        ("3587c9c", ["tests/test_unit.py::test_audit_recent_is_newest_with_real_total",
                     "tests/test_unit.py::test_cli_audit_pages_past_5000"]),
    "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions":
        ("3587c9c", ["tests/test_m4_acceptance.py::test_human_token_rotation_logs_out_browsers",
                     "tests/test_m4_unit.py::test_human_token_rotation_drops_sessions_and_tickets",
                     "tests/test_m4_unit.py::test_session_db_without_token_column_is_migrated",
                     "tests/test_m4_unit.py::test_token_gen_is_stable_and_distinct"]),
    "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap":
        ("e63922c", ["tests/test_m2_unit.py::test_large_tool_args_are_capped_in_audit"]),
    "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass":
        ("152b8e4", ["tests/test_m4_unit.py::test_overlap_uses_filesystem_identity",
                     "tests/test_m4_unit.py::test_overlap_sees_bind_mount_alias"]),
    "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency":
        ("c1f88da", ["tests/test_m2_unit.py::test_idle_burst_close_does_not_run_on_caller_thread",
                       "tests/test_m2_unit.py::test_gui_execs_have_a_container_side_deadline",
                       "tests/test_m2_acceptance.py::test_frozen_display_does_not_hold_tools_or_takeover"]),
    "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause":
        ("c1f88da", ["tests/test_m2_acceptance.py::test_gui_burst_restarts_after_pause_and_restore",
                       "tests/test_m2_unit.py::test_lifecycle_change_resets_gui_burst_timers",
                       "tests/test_m2_unit.py::test_burst_from_replaced_container_kills_nothing",
                       "tests/test_m2_unit.py::test_failed_burst_close_is_logged_not_dropped_silently"]),
    "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized":
        ("c1f88da", ["tests/test_m3_acceptance.py::test_web_approval_neutralises_bidi_controls"]),
    # needs_validation이지만 판정과 상관없이 먼저 막아 둔 것
    "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover":
        ("c1f88da", ["tests/test_m2_unit.py::test_takeover_waits_bounded_and_stops_new_agent_gui_calls",
                       "tests/test_m2_acceptance.py::test_frozen_display_does_not_hold_tools_or_takeover"]),
    "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit":
        ("c1f88da", ["tests/test_m2_unit.py::test_failed_burst_baseline_is_logged"]),
}

# short ids used in REPORT.md and HANDOFF (Phase 3 verifier ids)
SHORT = {
    "agentbox/api.py:same_origin:scheme-blind-origin-netloc-compare": "v01",
    "agentbox/audit.py:list:oldest-first-limit-truncates-ui-and-cli-timelines": "v02",
    "agentbox/cli.py:cmd_agent:log-prints-container-output-without-safe": "v03",
    "agentbox/desktop.py:ui_sessions:human-token-rotation-does-not-revoke-browser-sessions": "v05",
    "agentbox/sandbox.py:create:source_dir-overlap-guard-case-insensitive-bypass": "v06",
    "agentbox/sandbox.py:gui_strays:client-declared-net-wm-pid-exempts-baseline-session-process": "v15",
    "agentbox/service.py:_logged_args:tool-args-persisted-to-audit-without-size-cap": "v08",
    "agentbox/service.py:_open_gui_burst:silent-fail-open-without-audit": "v09",
    "agentbox/service.py:_run_tool:gui_lock-held-across-untimed-x-exec-blocks-takeover": "v10",
    "agentbox/service.py:close_idle_gui_bursts:cross-sandbox-untimed-exec-outside-tool-concurrency": "v11",
    "agentbox/service.py:gui-burst-state-dropped-on-restore-and-pause": "v12",
    "agentbox/templates/_approvals.html:exec-command-bidi-controls-unneutralized": "v13",
    "agentbox/web.py:register:cookie-ui-frameable-no-frame-ancestors-single-click-approve": "v14",
}

# needs_validation priority (most decisive and agent-reachable first)
NV_ORDER = ["v10", "v09", "v15", "v14", "v01"]


def loc(e):
    return f"`{e['file']}:{e['line']}`"


def trace_md(r):
    out = []
    for i, t in enumerate(r["trace"], 1):
        out.append(f"{i}. **{t['kind']}** {loc(t)} `{t['scope']}` — {t['description']}")
    return "\n".join(out)


def evidence_md(r):
    return "\n".join(f"- {loc(e)} — {e['description']}" for e in r["evidence"])


def detail(r):
    s = r["severity"]
    fp = r["fingerprint"]
    lines = [f"## [{s['overall_severity']}] {SHORT[fp]} — {r['title']}", "",
             f"- fingerprint: `{fp}`",
             f"- 심각도: likelihood {s['likelihood']['score']} · impact {s['impact']['score']} · overall **{s['overall_severity']}**; confidence {r['confidence']['score']}",
             ]
    if fp in FIX:
        c, tests = FIX[fp]
        lines.append(f"- 수정 상태: 이 브랜치에 `{c}`로 수정됨. 회귀 테스트: " + ", ".join(f"`{t}`" for t in tests))
    else:
        lines.append("- 수정 상태: 아직 수정 안 됨")
    lines += ["", "### 설명", "", r["description"], "",
              "### 근본 원인", "", r["root_cause"], "",
              "### 지켜야 할 불변식", "", r["intended_behavior"], "",
              "### 경로 (trace)", "", trace_md(r), "",
              "### 근거 (evidence)", "", evidence_md(r), "",
              "### 공격 주체와 조건", "", r["execution"]["attacker_perspective"], ""]
    lines += [f"- *{c['kind']}*: {c['description']}" for c in r["conditions"]]
    lines += ["", "### 재현 (대상 고유 인터페이스, 범위 제한)", "", "입력:", ""]
    lines += [f"- `{p}`" for p in r["execution"]["payloads"]]
    lines += ["", "절차:", ""]
    lines += [f"{i}. {x}" for i, x in enumerate(r["execution"]["instructions"], 1)]
    lines += ["", "관찰 결과:", "", r["execution"]["observed_result"], "",
              "### 영향과 우선순위 근거", "",
              f"- likelihood ({s['likelihood']['score']}): {s['likelihood']['reason']}",
              f"- impact ({s['impact']['score']}): {s['impact']['reason']}",
              f"- confidence ({r['confidence']['score']}): {r['confidence']['reason']}", "",
              "### 수정 방향", "", r["remediation"]["strategy"], ""]
    for cc in r["remediation"].get("code_changes", []):
        lines += [f"`{cc['file_name']}`:", "", "```python", cc["fixed_code"], "```", ""]
    return "\n".join(lines)


def nv(r, rank):
    fp = r["fingerprint"]
    lines = [f"## {rank}. {SHORT[fp]} — {r['title']}", "",
             f"- fingerprint: `{fp}`", "- 판정: needs_validation (심각도 없음, 확정 취약점 아님)"]
    if fp in FIX:
        lines.append(f"- 참고: 이 근본 원인에 대한 변경 `{FIX[fp][0]}`이 브랜치에 있다. 감사 대상 소스는 바뀌지 않았다.")
    lines += ["", "### 설명", "", r["description"], "",
              "### 주장된 근본 원인", "", r["claimed_root_cause"], "",
              "### 경로 (trace)", "", trace_md(r), "",
              "### 확인된 근거", "", evidence_md(r), "",
              "### 막혀 있는 사실 (blockers)", ""]
    lines += [f"- {b}" for b in r["blockers"]]
    plan = r["validation_plan"]
    lines += ["", "### 해소 계획", ""]
    if plan.get("local"):
        lines += ["**로컬 (범위 제한 fixture):**", "", plan["local"], ""]
    if plan.get("deployment"):
        lines += ["**운영자 관찰 (배포 대상에 감사 트래픽을 보내지 않음):**", "", plan["deployment"], ""]
    return "\n".join(lines)


def main():
    recs = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
    conf = sorted((r for r in recs if r["verdict"] == "confirmed"),
                  key=lambda r: (SEV_ORDER[r["severity"]["overall_severity"]], SHORT[r["fingerprint"]]))
    big = [r for r in conf if r["severity"]["overall_severity"] in ("critical", "high", "medium")]
    head = ["# agentbox 보안 감사 run-3 — 확정 결과 상세 (medium 이상)", "",
            "[`findings.json`](findings.json)의 최종 레코드에서 그대로 만든 문서다(`tools/gen6.py`). 레코드 원문은 영어이고 그대로 옮겼다. "
            "판정·심각도·근거는 JSON과 같으며 이 문서가 바꾸지 않는다. low 2건(v03, v06)은 [`REPORT.md`](REPORT.md)에 요약했다.", "",
            "줄 번호는 감사 대상 소스 `0e4b958`(= `main`의 `8e4db9e`) 기준이다. 이 브랜치에는 이후 수정이 들어가 있어 줄이 다를 수 있다. "
            "`parent-live`라고 적힌 재현은 부모가 이 클라우드 컨테이너의 일회용 Docker에서 가짜 토큰으로 돌린 것이고, 산출물은 `agents/parent-live/artifacts/`에 있다.", ""]
    with open(f"{RUN}/FINDINGS-DETAIL.md", "w", encoding="utf-8") as f:
        f.write("\n".join(head) + "\n" + "\n\n---\n\n".join(detail(r) for r in big) + "\n")
    nvr = {SHORT[r["fingerprint"]]: r for r in recs if r["verdict"] == "needs_validation"}
    assert set(nvr) == set(NV_ORDER)
    head = ["# agentbox 보안 감사 run-3 — 검증이 더 필요한 후보 (NEEDS VALIDATION)", "",
            "[`findings.json`](findings.json)의 `needs_validation` 레코드에서 그대로 만든 문서다(`tools/gen6.py`). 레코드 원문(영어)을 그대로 옮겼다. "
            "**확정 취약점이 아니며 심각도를 매기지 않는다.** 각 항목은 소스에서 경로가 확인됐지만, 결론을 가를 사실 하나가 소스와 로컬 sandbox 밖에 있다. "
            "해소 계획은 일회용 로컬 환경이나 운영자가 자기 설정을 보는 방법만 적었고, 배포된 서비스에 감사 트래픽을 보내는 방법은 적지 않았다.", "",
            "순서는 에이전트(가장 낮은 신뢰 주체)가 혼자 닿을 수 있는지, 막힌 사실이 얼마나 좁은지 기준의 우선순위다.", "",
            "검증되지 않은 후보 1건(`agentbox/sandbox.py:exec:backgrounded-children-survive-early-bash-exit-pid-exhaustion`)은 여기 들어가지 않는다. "
            "독립 검증을 거치지 않았기 때문이다. [`REPORT.md`](REPORT.md) 1절을 본다.", ""]
    with open(f"{RUN}/NEEDS-VALIDATION.md", "w", encoding="utf-8") as f:
        f.write("\n".join(head) + "\n" + "\n\n---\n\n".join(nv(nvr[k], i) for i, k in enumerate(NV_ORDER, 1)) + "\n")
    print("detail:", [SHORT[r["fingerprint"]] for r in big], "nv:", NV_ORDER)


if __name__ == "__main__":
    main()
