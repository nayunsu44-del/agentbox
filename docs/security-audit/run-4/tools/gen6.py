#!/usr/bin/env python3
"""Render the Korean Phase 6 reports from findings.json, the ledger and the metadata."""
import collections
import json

from common import RUN

B = chr(96)
def c(s):
    return B + str(s) + B

recs = sorted(json.load(open(f"{RUN}/findings.json", encoding="utf-8")), key=lambda r: r["fingerprint"])
L = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
M = json.load(open(f"{RUN}/run-metadata.json", encoding="utf-8"))
conf = [r for r in recs if r["verdict"] == "confirmed"]
nv = [r for r in recs if r["verdict"] == "needs_validation"]
rej = [r for r in recs if r["verdict"] == "rejected"]
sev = collections.Counter(r.get("severity", {}).get("overall_severity", "?") for r in conf)
st = collections.Counter(u["status"] for u in L)
SK = {"high": "높음", "medium": "중간", "low": "낮음"}

def paths(rec):
    return sorted({i["file"] for i in rec.get("trace", []) if i.get("file")})

R = []
R.append("# agentbox 보안 감사 run-4 보고서")
R.append("")
R.append("감사 기준: " + c("main") + " 커밋 " + c("9805d91") + "(리팩토링 PR #11~#14 이후). 작업 브랜치 " + c("ccr-17444317-ygb3a1") + ", 프로필 " + c("standard") + ", 에이전트 호출 상한 50회 중 46회 사용.")
R.append("")
R.append("## 1. 요약")
R.append("")
R.append("- 확정(confirmed) **%d건**: %s." % (len(conf), ", ".join(SK.get(k, k) + " " + str(v) + "건" for k, v in sorted(sev.items()))))
R.append("- 검증 필요(needs_validation) **%d건**, 기각 **%d건**." % (len(nv), len(rej)))
R.append("- 커버리지 장부 %d단위: %s." % (len(L), ", ".join(k + " " + str(v) for k, v in sorted(st.items()))))
R.append("- run-3 확정 9건을 모두 재검증 단위로 다시 확인했고, 다수가 이미 고쳐져 있음을 확인했다. 이번 run에서 새로 확정된 것은 전부 인증 전 처리·자원 상한·감사 기록 원자성 계열이다.")
R.append("- 확정 건은 **고치지 않았다**(지시대로 보고서까지만). 수정은 별도 지시로 진행한다.")
R.append("")
R.append("## 2. 감사 방법과 경계")
R.append("")
R.append("- 실행 호스트: " + str(M.get("execution_note", ""))[:400])
R.append("- 소유자 지시로 서브에이전트는 전부 DeepSeek(" + c("doph") + "/" + c("doph-2") + ", " + c("deepseek-ai/DeepSeek-V4.1-Flash") + ")로 통일했다. 정찰 4회만 이전 세션의 Opus 결과다.")
R.append("- 대상 코드 실행은 전부 " + c("tools/sbx.py") + "(네트워크 없음, 대상 읽기 전용, 스크래치만 쓰기, uid 65534, 512 MiB, 1 CPU, 120초) 안에서만 했다. Docker가 필요한 확인은 부모가 일회용 컨테이너에서 직접 재현했다(" + c("agents/parent-live/") + ").")
R.append("")
R.append("## 3. 확정 findings")
R.append("")
R.append("| # | 심각도 | 제목 | 대표 경로 |")
R.append("|---|---|---|---|")
order = {"high": 0, "medium": 1, "low": 2}
for i, r in enumerate(sorted(conf, key=lambda x: (order.get(x.get("severity", {}).get("overall_severity"), 3), x["fingerprint"])), 1):
    s = r.get("severity", {})
    p = (paths(r) or [""])[0]
    R.append("| %d | %s | %s | %s |" % (i, SK.get(s.get("overall_severity"), "?"), r["title"], c(p)))
R.append("")
R.append("각 건의 상세 근거·재현 절차·수정안은 " + c("FINDINGS-DETAIL.md") + "에 있다.")
R.append("")
R.append("## 4. 검증 필요 항목")
R.append("")
R.append("| # | 제목 | 막힌 지점 |")
R.append("|---|---|---|")
for i, r in enumerate(nv, 1):
    b = (r.get("blockers") or [""])[0]
    R.append("| %d | %s | %s |" % (i, r["title"], b[:160].replace("|", "/")))
R.append("")
R.append("로컬·배포 검증 계획은 " + c("NEEDS-VALIDATION.md") + "에 있다.")
R.append("")
if rej:
    R.append("## 5. 기각")
    for r in rej:
        R.append("- %s — %s" % (r["title"], str(r.get("reason", ""))[:300]))
    R.append("")
hard = sum(len(u.get("x_hardening", []) or []) for u in L)
R.append("## 5. 하드닝(취약점 아님, 개선 권고)")
R.append("")
R.append("장부에 보존된 헌터 하드닝 노트 %d건과 Phase 3·5 검증자가 덧붙인 항목이 각 " % hard + c("agents/<id>/result.json") + "의 " + c("hardening") + "에 있다. 여러 건에서 공통으로 지적된 것: 감사·승인 테이블의 집계 상한과 보존 정책 부재, " + c("display.escape_controls") + "의 문자 집합 누락, " + c("deploy/Caddyfile") + "에 요청 크기·속도 제한 없음, " + c("/healthz") + "·" + c("/docs") + " 무인증 노출.")
R.append("")
R.append("## 6. 커버리지와 한계")
R.append("")
R.append("- 30개 커버리지 단위를 13명의 헌터가 모두 닫았다(covered %d, candidate %d)." % (st.get("covered", 0), st.get("candidate", 0)))
R.append("- 사후 커버리지 비평(" + c("critic-1") + ")이 **미할당 경계 2건**을 제안했다: (a) 데스크톱 WebSocket 업그레이드 경로에서 async 핸들러가 " + c("ws.accept()") + " 전에 SQLite·Docker SDK를 동기 호출해 이벤트 루프를 막는 문제, (b) 승인 테이블이 마스킹·상한 없이 원본 인자·프리뷰를 보존하고 삭제 후에도 남는 문제.")
R.append("- 남은 예산을 3·5단계 검증에 예약해야 해서 이 2건은 이번 run에서 **deferred**로 기록한다. 따라서 이 run은 그 두 경계에 대해 **명시적 조기 종료**이며, 전체 커버리지 완전 달성으로 주장하지 않는다. 다음 run의 1순위다.")
R.append("- run-3에서 기각된 두 주장(runc 별칭, 백그라운드 자식 pid 고갈)은 변경된 근거가 없어 재보고하지 않았다.")
R.append("")
R.append("## 7. 편차와 주의")
R.append("")
R.append("- Windows 호스트로 옮기면서 bash " + c("sbx") + "와 loop 마운트 스크래치를 쓸 수 없어 " + c("sbx.py") + "/" + c("promote.py") + "를 같은 경계로 다시 구현했다(" + c("run-metadata.json") + "의 " + c("execution_note") + ").")
R.append("- 헌터 4명(h-policy, h-queue, h-gui-race, h-preauth)이 결과 파일을 남기지 않아 부모가 마지막 메시지에서 옮겨 적었고, 장부 coverage_id로 재매핑했다.")
R.append("- v06 검증자는 지시문 파일이 없어 형제 지시문으로 계약을 재구성했고 그 사실을 결과에 적었다.")
R.append("- Phase 5에서 r03·r09가 " + c("replace") + "를 냈지만 스스로 **비물질 수정**이라고 밝혀(경로 접두사·서술 순서·관측 문장 1개) 두 번째 검증자 없이 반영했다. 이 편차를 여기에 공개한다.")
R.append("- v05 검증자는 자기 턴에 들어온 범위 밖 쓰기 지시를 거부했다. 감사 경계가 실제로 작동한 사례로 기록한다.")
R.append("- 스킬의 " + c("validate-findings.cjs") + "·" + c("validate-coverage-ledger.cjs") + "는 Linux 전용 no-follow I/O를 요구해 Windows 호스트에서 직접 실행되지 않는다. 구조 검증은 node:22-alpine 컨테이너에서 돌렸고 두 검사기 모두 통과했다(PASS: 12 findings valid, PASS: 30 coverage units valid).")
R.append("")
open(f"{RUN}/REPORT.md", "w", encoding="utf-8").write(chr(10).join(R) + chr(10))

D = ["# 확정 findings 상세 (run-4)", "", "기준 커밋 " + c("9805d91") + ". 아래는 " + c("findings.json") + "의 " + c("confirmed") + " 레코드를 그대로 옮긴 것이다.", ""]
for i, r in enumerate(sorted(conf, key=lambda x: x["fingerprint"]), 1):
    s = r.get("severity", {})
    D.append("## F%d. %s" % (i, r["title"]))
    D.append("")
    D.append("- 지문: " + c(r["fingerprint"]))
    D.append("- 심각도: **%s** (가능성 %s, 영향 %s)" % (SK.get(s.get("overall_severity"), "?"), SK.get(s.get("likelihood", {}).get("score"), "?"), SK.get(s.get("impact", {}).get("score"), "?")))
    D.append("- 신뢰도: " + str(r.get("confidence", {}).get("score", "?")))
    D.append("- 관련 경로: " + ", ".join(c(p) for p in paths(r)))
    D.append("")
    D.append("**설명.** " + str(r.get("description", "")))
    D.append("")
    D.append("**근본 원인.** " + str(r.get("root_cause", "")))
    D.append("")
    D.append("**의도된 동작.** " + str(r.get("intended_behavior", "")))
    D.append("")
    D.append("**전파 경로.**")
    for t in r.get("trace", []):
        D.append("- " + c(str(t.get("file")) + ":" + str(t.get("line"))) + " (" + str(t.get("kind")) + ", " + str(t.get("scope", "")) + ") — " + str(t.get("description", "")))
    D.append("")
    D.append("**재현과 관측 결과.**")
    D.append("")
    D.append("- 공격자 관점: " + str(r.get("execution", {}).get("attacker_perspective", "")))
    D.append("- 관측: " + str(r.get("execution", {}).get("observed_result", "")))
    D.append("")
    cs = r.get("conditions", [])
    if cs:
        D.append("**조건.**")
        for x in cs:
            D.append("- " + str(x.get("kind")) + ": " + str(x.get("description", "")))
        D.append("")
    rm = r.get("remediation", {})
    D.append("**수정 방향.** " + str(rm.get("strategy", "")))
    D.append("")
    for ch in rm.get("code_changes", []):
        D.append(c("python") + " // " + str(ch.get("file_name")))
        D.append(chr(96) * 3 + "python")
        D.append(str(ch.get("fixed_code", "")))
        D.append(chr(96) * 3)
        D.append("")
open(f"{RUN}/FINDINGS-DETAIL.md", "w", encoding="utf-8").write(chr(10).join(D) + chr(10))

N = ["# 검증 필요 항목 (run-4)", "", "소스로는 성립하지만 이 환경에서 결정적 증거를 만들지 못한 항목이다. 검증 계획은 레코드의 " + c("validation_plan") + "을 그대로 옮겼다.", ""]
for i, r in enumerate(nv, 1):
    N.append("## N%d. %s" % (i, r["title"]))
    N.append("")
    N.append("- 지문: " + c(r["fingerprint"]))
    N.append("- 관련 경로: " + ", ".join(c(p) for p in sorted({x["file"] for x in r.get("trace", []) if x.get("file")})))
    N.append("")
    N.append("**설명.** " + str(r.get("description", "")))
    N.append("")
    N.append("**막힌 지점.**")
    for b in r.get("blockers", []):
        N.append("- " + str(b))
    p = r.get("validation_plan", {})
    N.append("")
    N.append("**로컬 검증 계획.** " + str(p.get("local", "")))
    N.append("")
    N.append("**배포 검증 계획.** " + str(p.get("deployment", "")))
    N.append("")
open(f"{RUN}/NEEDS-VALIDATION.md", "w", encoding="utf-8").write(chr(10).join(N) + chr(10))
print("reports written:", len(conf), "confirmed,", len(nv), "needs_validation")