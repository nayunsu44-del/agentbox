#!/usr/bin/env python3
"""Render the Korean Phase 6 reports (REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md).

Korean text comes from ko_text.KO (written by the parent from findings.json). Every entry keeps
the English record fields below it as the authoritative original. Counts, statuses and paths are
computed from findings.json, the ledger and run-metadata.json; the narrative sections that are not
derivable from them (method, deviations, review notes) are the constants at the top of this file.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN  # noqa: E402
from ko_text import KO  # noqa: E402

B = chr(96)
F3 = B * 3


def c(s):
    return B + str(s) + B


recs = sorted(json.load(open(f"{RUN}/findings.json", encoding="utf-8")), key=lambda r: r["fingerprint"])
L = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
M = json.load(open(f"{RUN}/run-metadata.json", encoding="utf-8"))
SK = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음", "informational": "정보"}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
KIND = {"entrypoint": "진입점", "propagation": "전파", "sink": "도달점"}
COND = {"authentication_level": "인증 수준", "authorization_role": "권한", "user_interaction": "사용자 상호작용",
        "system_configuration": "시스템 설정", "network_routing": "네트워크 경로", "environmental_dependency": "환경 의존",
        "data_state": "데이터 상태", "timing_dependency": "타이밍", "third_party_dependency": "외부 의존"}

conf = sorted([r for r in recs if r["verdict"] == "confirmed"],
              key=lambda r: (ORDER.get(r["severity"]["overall_severity"], 9), r["fingerprint"]))
nv = [r for r in recs if r["verdict"] == "needs_validation"]
rej = [r for r in recs if r["verdict"] == "rejected"]
cid = {r["fingerprint"]: f"F{i}" for i, r in enumerate(conf, 1)}
cid.update({r["fingerprint"]: f"N{i}" for i, r in enumerate(nv, 1)})
st = collections.Counter(u["status"] for u in L)
sev = collections.Counter(r["severity"]["overall_severity"] for r in conf)
deferred = [u for u in L if u["status"] == "deferred"]


def main_path(r):
    return r["fingerprint"].split(":", 1)[0]


def ko(r, k, default=""):
    return KO.get(r["fingerprint"], {}).get(k, default)


def original(r, fields):
    """English original of the record (authoritative), folded."""
    out = ["<details><summary>레코드 원문 (영어, 기준)</summary>", ""]
    for f in fields:
        v = r.get(f)
        if v in (None, "", [], {}):
            continue
        if f == "trace":
            out.append("**trace**")
            out.append("")
            for t in v:
                out.append("- " + c(f"{t.get('file')}:{t.get('line')}") + f" ({t.get('kind')}, {t.get('scope', '')}) — {t.get('description', '')}")
        elif f == "execution":
            out.append("**execution.attacker_perspective** " + v.get("attacker_perspective", ""))
            out.append("")
            out.append("**execution.instructions**")
            out.append("")
            out.extend(f"{i}. {s}" for i, s in enumerate(v.get("instructions", []), 1))
            out.append("")
            out.append("**execution.observed_result** " + v.get("observed_result", ""))
        elif f == "conditions":
            out.append("**conditions**")
            out.append("")
            out.extend(f"- {x['kind']}: {x['description']}" for x in v)
        elif f == "blockers":
            out.append("**blockers**")
            out.append("")
            out.extend("- " + b for b in v)
        elif f == "validation_plan":
            for k2 in ("local", "deployment"):
                if v.get(k2):
                    out.append(f"**validation_plan.{k2}** " + v[k2])
                    out.append("")
        elif f == "remediation":
            out.append("**remediation.strategy** " + v.get("strategy", ""))
            for ch in v.get("code_changes", []):
                out.append("")
                out.append(c(ch.get("file_name")) + ":")
                out.append("")
                out.append(F3 + "python")
                out.append(ch.get("fixed_code", ""))
                out.append(F3)
        else:
            out.append(f"**{f}** {v}")
        out.append("")
    out.append("</details>")
    out.append("")
    return out


# ------------------------------------------------------------------ REPORT.md
R = ["# agentbox 보안 감사 run-4 보고서", ""]
R.append(f"감사 기준은 {c('main')} 커밋 {c('9805d91')}(리팩토링 PR #11~#14 이후)이다. 작업 브랜치는 {c('ccr-17444317-ygb3a1')}, 프로필은 {c('standard')}이다. "
         f"에이전트 호출 상한 {M['budget']}회 중 **{M['agents_spent_total']}회**를 썼다. 실행 상태는 **{c(M['run_status'])}**"
         + (f"({c(M.get('incomplete_reason'))})" if M.get("incomplete_reason") else "") + "이다.")
R.append("")
R.append("## 1. 요약")
R.append("")
R.append("- 이 run은 **부분 감사**다. 사후 비평이 제안한 경계 %d개를 예산 때문에 헌팅하지 못했다(아래 6절)." % len(deferred))
R.append("- 확정 **%d건**: %s." % (len(conf), ", ".join(f"{SK[k]} {v}건" for k, v in sorted(sev.items(), key=lambda x: ORDER[x[0]]))))
R.append("- 검증 필요 **%d건**, 기각 **%d건**. 레코드는 모두 %d건이다." % (len(nv), len(rej), len(recs)))
R.append("- 장부 %d단위: %s." % (len(L), ", ".join(f"{k} {v}" for k, v in sorted(st.items()))))
PRIOR = {r["fingerprint"]: r for r in json.load(open(f"{RUN}/../run-3/findings.json", encoding="utf-8"))}
VKO = {"confirmed": "확정", "needs_validation": "검증 필요", "rejected": "기각"}
carried = [r for r in recs if r["fingerprint"] in PRIOR]
R.append("- run-3 확정 %d건과 검증 필요 %d건은 소스가 바뀌어(수정과 리팩토링) 모두 재검증 단위로 다시 봤다. 같은 지문으로 이어진 것은 아래와 같다. 나머지 run-3 확정 건은 현재 소스에서 같은 근본 원인이 재현되지 않았다."
         % (sum(r["verdict"] == "confirmed" for r in PRIOR.values()), sum(r["verdict"] == "needs_validation" for r in PRIOR.values())))
for r in carried:
    R.append(f"  - {cid[r['fingerprint']]}: run-3 {VKO[PRIOR[r['fingerprint']]['verdict']]} → run-4 {VKO[r['verdict']]} ({c(r['fingerprint'])})")
R.append("- 확정 건은 **고치지 않았다**. 보고서까지만 만들었고, 수정은 별도 지시로 한다.")
R.append("")
R.append("## 2. 감사 방법과 경계")
R.append("")
R.append("- **실행 환경:** 이 run은 두 호스트에서 돌았다.")
R.append("  - 정찰과 검토 보완은 리눅스 클라우드 컨테이너에서 했다.")
R.append(f"  - 2~6단계 1차는 Windows 11의 DeepSeek 하네스에서 했다. 그쪽에서는 bash {c('sbx')} 대신 {c('tools/sbx.py')}로 같은 격리 조건을 다시 구현했다.")
R.append(f"  - 대상 코드는 모두 {c('sbx')} 컨테이너 안에서만 돌렸다. 조건은 네트워크 없음, 대상 읽기 전용, 스크래치만 쓰기, uid 65534, 512 MiB, 1 CPU, 120초다.")
R.append(f"  - Docker가 필요한 확인은 부모가 일회용 컨테이너에서 가짜 토큰으로 직접 재현했다({c('agents/parent-live/')}).")
R.append("- **모델:**")
R.append("  - 정찰 4회는 Opus였다.")
R.append(f"  - 소유자 지시로 1차 2~6단계의 서브에이전트는 전부 DeepSeek({c('deepseek-ai/DeepSeek-V4.1-Flash')})였다.")
R.append("  - 검토 보완 4회는 DeepSeek를 쓸 수 없는 환경이라 소유자 승인으로 돌렸다. v11 3단계·r14 재검증·최종 비평은 Opus, r13 5단계는 Sonnet이다.")
R.append("- **이전 run 사용:** run-1·2·3의 장부와 findings를 이전 기록으로 넘겼다. run-3에서 기각된 두 주장(runc 별칭, 백그라운드 자식 pid 고갈)은 근거가 바뀌지 않아 다시 보고하지 않았다.")
R.append("")
R.append("## 3. 확정")
R.append("")
R.append("| ID | 심각도 | 제목 | 주 경로 |")
R.append("|---|---|---|---|")
for r in conf:
    R.append(f"| {cid[r['fingerprint']]} | {SK[r['severity']['overall_severity']]} | {ko(r, 'title', r['title'])} | {c(main_path(r))} |")
R.append("")
R.append(f"상세 근거, 재현, 수정 방향은 {c('FINDINGS-DETAIL.md')}에 있다.")
R.append("")
R.append("## 4. 검증 필요")
R.append("")
R.append("| ID | 제목 | 막힌 지점 |")
R.append("|---|---|---|")
for r in nv:
    b = (ko(r, "blockers") or r.get("blockers") or [""])[0]
    R.append(f"| {cid[r['fingerprint']]} | {ko(r, 'title', r['title'])} | {b.replace('|', '/')} |")
R.append("")
R.append(f"로컬·배포 검증 계획은 {c('NEEDS-VALIDATION.md')}에 있다.")
R.append("")
hard = sum(len(u.get("x_hardening", []) or []) for u in L)
R.append("## 5. 하드닝 (취약점 아님)")
R.append("")
R.append(f"헌터가 남긴 하드닝 메모 {hard}건이 장부 단위의 {c('x_hardening')}에 있다(같은 헌터의 메모가 그 헌터 단위마다 반복된다). 여러 헌터가 공통으로 짚은 것은 아래와 같다.")
R.append("- 감사·승인 테이블에 전체 상한과 보존 정책이 없다.")
R.append(f"- {c('display.escape_controls')}의 문자 집합이 빠진 것이 있다.")
R.append(f"- {c('deploy/Caddyfile')}에 요청 크기·속도 제한이 없다.")
R.append(f"- {c('/healthz')}와 {c('/docs')}가 인증 없이 노출된다.")
R.append("")
R.append("## 6. 커버리지와 한계")
R.append("")
R.append(f"- 장부 {len(L)}단위 가운데 헌터가 맡은 30단위는 모두 닫혔다(covered {st.get('covered', 0)}, candidate {st.get('candidate', 0)}).")
R.append(f"- 사후 비평 {c('critic-1')}이 미할당 경계 2개를 제안했다. 예산을 검증에 남겨야 해서 헌터를 붙이지 못했고, 장부에 {c('deferred')}로 넣었다. 다음 run의 1순위다.")
from report_notes import DEFERRED_KO  # noqa: E402
for u in deferred:
    R.append("  - " + DEFERRED_KO.get(u["attack_class"], f"{u['surface']} — {u['boundary']}"))
R.append("- critic-1의 원래 출력은 남아 있지 않다. 단위 내용은 1차 보고서의 요약과 소스로 다시 만들었다. WebSocket 핸들러가 " + c("ws.accept()") + " 전에 동기 SQLite·Docker 호출을 하는 것은 api.py:343-353과 desktop_ws.py:18-23에서 확인했다.")
R.append("@@FINAL_CRITIC@@")
R.append("")
R.append("## 7. 편차와 주의")
R.append("")
R.append("@@DEVIATIONS@@")
R.append("")

# ------------------------------------------------------------------ FINDINGS-DETAIL.md
D = ["# run-4 확정 상세", "",
     f"{c('findings.json')}의 확정 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같다. 항목마다 아래에 영어 레코드 원문을 접어 두었고, 원문이 기준이다. 줄 번호는 감사 기준 {c('9805d91')}을 따른다. 확정 건은 아직 고치지 않았다.", ""]
for r in conf:
    s = r["severity"]
    D.append(f"## {cid[r['fingerprint']]}. [{SK[s['overall_severity']]}] {ko(r, 'title', r['title'])}")
    D.append("")
    D.append("- 지문: " + c(r["fingerprint"]))
    D.append(f"- 심각도: 가능성 {SK[s['likelihood']['score']]} · 영향 {SK[s['impact']['score']]} · 종합 **{SK[s['overall_severity']]}**. 신뢰도: {r['confidence']['score']}")
    D.append("- 경로: " + ", ".join(c(f"{t['file']}:{t['line']}") + f"({KIND.get(t['kind'], t['kind'])})" for t in r["trace"]))
    D.append("")
    D.append("**설명.** " + ko(r, "desc"))
    D.append("")
    D.append("**근본 원인.** " + ko(r, "root"))
    D.append("")
    D.append("**지켜야 할 동작.** " + ko(r, "intended"))
    D.append("")
    D.append("**재현 관측.**")
    D.append("")
    D.append(ko(r, "obs"))
    D.append("")
    D.append("**성립 조건.** " + ", ".join(COND.get(x["kind"], x["kind"]) for x in r.get("conditions", []))
             + ". 조건별 설명은 아래 원문의 `conditions`에 있다.")
    D.append("")
    D.append("**수정 방향.** " + ko(r, "fix"))
    D.append("")
    D.extend(original(r, ["description", "root_cause", "intended_behavior", "trace", "conditions", "execution", "remediation"]))

# ------------------------------------------------------------------ NEEDS-VALIDATION.md
N = ["# run-4 검증 필요 항목", "",
     "소스로는 성립하지만, 이 감사 환경에서 결정적 증거를 만들지 못한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.", ""]
for r in nv:
    N.append(f"## {cid[r['fingerprint']]}. {ko(r, 'title', r['title'])}")
    N.append("")
    N.append("- 지문: " + c(r["fingerprint"]))
    N.append("- 경로: " + ", ".join(c(f"{t['file']}:{t['line']}") + f"({KIND.get(t['kind'], t['kind'])})" for t in r["trace"]))
    N.append("")
    N.append("**설명.** " + ko(r, "desc"))
    N.append("")
    N.append("**주장하는 근본 원인.** " + ko(r, "root"))
    N.append("")
    N.append("**막힌 지점.**")
    N.append("")
    for b in ko(r, "blockers", []):
        N.append("- " + b)
    N.append("")
    N.append("**검증 계획.** " + ko(r, "plan"))
    N.append("")
    N.extend(original(r, ["description", "claimed_root_cause", "trace", "blockers", "validation_plan"]))


def write(final_critic_line, deviations):
    i = R.index("@@FINAL_CRITIC@@")
    R[i] = final_critic_line
    j = R.index("@@DEVIATIONS@@")
    R[j:j + 1] = deviations
    for name, lines in (("REPORT.md", R), ("FINDINGS-DETAIL.md", D), ("NEEDS-VALIDATION.md", N)):
        open(f"{RUN}/{name}", "w", encoding="utf-8").write("\n".join(lines).rstrip("\n") + "\n")
    print("reports written:", len(conf), "confirmed,", len(nv), "needs_validation,", len(rej), "rejected")


if __name__ == "__main__":
    from report_notes import FINAL_CRITIC, DEVIATIONS as DEV  # noqa: E402
    write(FINAL_CRITIC, DEV)
