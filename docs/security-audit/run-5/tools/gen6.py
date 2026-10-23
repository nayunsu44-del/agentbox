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
cid.update({r["fingerprint"]: f"R{i}" for i, r in enumerate(rej, 1)})
cid.update({r["fingerprint"]: f"N{i}" for i, r in enumerate(nv, 1)})
st = collections.Counter(u["status"] for u in L)
sev = collections.Counter(r["severity"]["overall_severity"] for r in conf)
def _rank(u):
    """비평이 낸 순서(critic-2는 x_source의 'unit i of n')."""
    import re as _re
    m = _re.search(r"unit (\d+) of", u.get("x_source", ""))
    return (u["wave"], int(m.group(1)) if m else 0)


deferred = sorted((u for u in L if u["status"] == "deferred"), key=_rank)


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
M_ = M["agents_spent"]
waves = collections.Counter(u["wave"] for u in L if u["status"] == "deferred")
hunted = [u for u in L if u["status"] not in ("deferred", "planned")]
R = ["# agentbox 보안 감사 run-5 보고서", ""]
R.append(f"감사 기준은 {c('main')} 커밋 {c('346df29')}(run-4 수정 PR #16~#23 이후)이다. 작업 브랜치는 {c('ccr-534dd824-2jgcsj')}, 프로필은 {c('standard')}, 호출 상한은 소유자가 정한 **30**이다. "
         "run-4가 보류한 3단위와 run-4 수정이 바꾼 코드 4단위를 보는 **집중 후속 감사**다. LLM 공급자로 가는 데이터 경로는 문서화한 한계라 뺐다.")
R.append("")
R.append("## 1. 요약")
R.append("")
R.append("- 확정 **%d건**: %s. 검증 필요 **%d건**, 기각 **%d건**(레코드 %d건)." % (
    len(conf), ", ".join(f"{SK[k]} {v}건" for k, v in sorted(sev.items(), key=lambda x: ORDER[x[0]])), len(nv), len(rej), len(recs)))
R.append(f"- 장부 {len(L)}단위: 헌팅한 {len(hunted)}단위는 모두 닫혔다({', '.join(f'{k} {v}' for k, v in sorted(st.items()) if k != 'deferred')}). 비평이 낸 {len(deferred)}단위는 예산이 다해 {c('deferred')}로 남겼다.")
R.append(f"- 예산 {M["agents_spent_total"]}/{M["budget"]}회를 썼다(run 뒤 소유자 승인 재검증 1회 포함): 헌터 {M_['hunters']}(Opus), 형식 재시도 {M_['retries']}, 3단계 {M_['phase3']}, 5단계 {M_['phase5']}, 재검증 {M_['reverify']}, 비평 {M_['critics']}(모두 Sonnet). 정찰은 부모가 했다(0회). 실제 Docker가 필요한 확인 7건은 부모가 예산 밖에서 했다({c('agents/parent-live/')}).")
R.append("- run-4 확정 F1~F8의 수정은 이번 단위들이 다시 봤다. 같은 지문으로 이어진 것: F1(인증 전 본문)은 바이트 상한은 지켜지나 JSON 해석 확대가 남아 검증 필요로 다시 올랐다. run-4 N2(감사·승인 행 무제한)는 승인 대기 행 확대로 확정됐다. N4(창 주인 위조)는 실제 이미지에서 고쳐진 것을 확인했다.")
R.append("- **확정 6건은 소유자 지시(2026-10-23 밤)로 같은 PR에서 고쳤다.** 건마다 회귀 테스트가 있고, 새 테스트는 수정 전 코드에서 실패한다(아래 3절). 검증 필요 1건은 고치는 방향을 정해야 해서 손대지 않았다(8절).")
R.append("")
R.append("## 2. 감사 방법과 경계")
R.append("")
R.append(f"- **실행 환경:** 리눅스 클라우드 컨테이너. 대상 코드는 {c('tools/sbx')} 컨테이너 안에서만 돌렸다(네트워크 없음, 대상 읽기 전용, 스크래치만 쓰기, uid 65534, 512MiB, 1 CPU, 120초).")
R.append("- **모델:** 소유자 지시로 헌터만 Opus, 나머지(3단계·5단계·재검증·비평)는 Sonnet.")
R.append(f"- **정찰:** 에이전트를 쓰지 않았다. run-4 구조 요약에 {c('9805d91')} 이후 바뀐 15개 파일의 변경분(현재 줄 번호)을 부모가 덧붙였다({c('architecture.md')} 0절).")
R.append("- **범위 단위:** 보류 3(인수 중 GUI 구간, 화면 웹소켓 accept 전 작업, 승인 테이블), 바뀐 코드 4(정리 명령·기준점, 디스크 보호선·승인 행 줄이기, XRes 창 주인, 본문 상한). 사후 비평(critic-1)이 3단위를 더 냈고 그중 2개(수명 주기 락 범위, 긴 명령의 정책·미리보기 비용)를 헌팅했다.")
R.append("")
R.append("## 3. 확정과 수정")
R.append("")
R.append("| ID | 심각도 | 제목 | 주 경로 | 수정 |")
R.append("|---|---|---|---|---|")
for r in conf:
    R.append(f"| {cid[r['fingerprint']]} | {SK[r['severity']['overall_severity']]} | {ko(r, 'title', r['title'])} | {c(main_path(r))} | {ko(r, 'fix')} |")
R.append("")
R.append(f"상세 근거, 재현, 원문은 {c('FINDINGS-DETAIL.md')}에 있다. 수정 확인: 새 회귀 테스트 {c('tests/test_m5_unit.py')}(9개)와 {c('tests/test_retention.py')} 2개가 수정 전 코드에서 실패하고 수정 뒤 통과한다. 실제 Docker와 데스크톱 이미지를 쓰는 전체 테스트 268개가 로컬에서 통과했다(건너뛴 것 없음). 기존 F3 수용 테스트 하나는 새 인자 상한(413)에 맞게 고쳤다. 리뷰 중에 목록 값으로 상한을 피하는 틈을 찾아 같이 막았다.")
R.append("")
R.append("## 4. 검증 필요")
R.append("")
R.append("| ID | 제목 | 막힌 지점 |")
R.append("|---|---|---|")
for r in nv:
    R.append(f"| {cid[r['fingerprint']]} | {ko(r, 'title', r['title'])} | {(ko(r, 'blockers', ['']) or [''])[0]} |")
R.append("")
R.append(f"검증 계획과 부모 실측은 {c('NEEDS-VALIDATION.md')}에 있다.")
R.append("")
R.append("## 5. 기각")
R.append("")
for r in rej:
    R.append(f"- **{cid[r['fingerprint']]}. {ko(r, 'title', r['title'])}** {ko(r, 'reason')}")
R.append("")
R.append("## 6. 커버리지와 남은 단위")
R.append("")
R.append(f"- 헌팅한 단위: 보류 3, 바뀐 코드 4, critic-1 2. XRes 창 주인 단위는 헌터가 실제 이미지 확인 2건으로 막혔고, 부모 실측({c('agents/parent-live/artifacts/xres.json')})으로 닫았다: XRes가 돌려준 창 주인 pid가 xfwm4·panel·xfdesktop의 실제 pid와 맞고, 구간 중에 띄운 창 없는 작업은 구간이 끝날 때 멈춘다.")
R.append(f"- 보류({c('deferred')}) {len(deferred)}단위. 다음 run의 우선순위다(비평이 매긴 순서):")
for u in deferred:
    who = "critic-1" if u["wave"] == 2 else "critic-2"
    R.append(f"  - [{who}] {u['surface'][:160]}{'…' if len(u['surface']) > 160 else ''}")
R.append("- 최종 비평(critic-2)은 `stop: false`였다. 그래서 깨끗한 커버리지는 주장하지 않는다. critic-2는 run-4 N1(`same_origin` scheme)과 N3(컨테이너 출력 판독기 상한)이 이번 장부에 주인이 없다는 점, 두 단위의 제외 사유가 이번 장부에 없는 'h-session' 단위를 가리킨다는 점을 짚었다(seed가 run-4 제외 문구를 그대로 옮긴 탓).")
R.append("")
R.append("## 7. 편차와 주의")
R.append("")
R.append(f"- **r-prune 5단계 교체를 재검증 없이 반영:** 바뀐 것이 줄 번호 두 곳({c('cli.py:322→323')}, {c('audit.py:353-354→358-359')})과 문구뿐이었다. {c('apply.py')}는 필드 단위로 실질 변경으로 분류해 보류했지만, 부모가 판정·근본 원인·심각도·경로가 그대로임을 확인하고 {c('tools/apply5_nonmaterial.py')}로 반영했다.")
R.append(f"- **rv-policy-cpu 결과를 버림:** 재검증자의 최종 메시지가 JSON이 아니었다(끝의 닫는 중괄호 하나 없음). 고쳐 쓰지 않는 규칙에 따라 버렸고, 다시 받으면 31회째라 상한을 넘는다. 그래서 r-policy-cpu의 교체 레코드는 반영하지 않고 3단계 레코드(확정 낮음)를 유지했다. 버린 원문은 {c('agents/rv-policy-cpu/final.txt')}에 있다. 그 기술적 지적(재귀 조건을 좁히면 탐지가 준다)은 레코드가 아니라 수정 코드에 반영했다. **run 뒤 소유자 승인으로 31번째 호출(rv2-policy-cpu)을 써서 다시 검증했고, 그 결과(같은 판정, 수정 방향 정정)를 반영했다.**")
R.append(f"- 헌터 두 명(h-gui-lease, h-bodylimit)의 결과가 단위 {c('reviewed_paths')}가 검사들의 합집합과 다르다는 형식 검사에 걸렸다. 결과를 고쳐 쓰지 않고 같은 헌터에게 그 부분만 고쳐 다시 보내게 했다(재시도 2회).")
R.append(f"- 사용량 한도(18:10 UTC 해제)로 검증자 5명이 멈췄다가 같은 에이전트로 이어서 끝냈다(새 호출로 세지 않음).")
R.append(f"- v-preview의 증거 하나가 스크래치 경로({c('agents/v-preview/scratch/count.py')})를 가리킨다. 부모가 {c('agents/v-preview/artifacts/count.py')}로 승격해 두었다.")
R.append("")
R.append("## 8. 아침에 판단할 것 (소유자 결정 필요)")
R.append("")
R.append(f"1. **N1 인증 전 JSON 해석(검증 필요).** 고치는 방향을 골라야 한다: (a) 자격 증명(Authorization 헤더나 세션 쿠키)이 없는 요청은 본문을 읽기 전에 401, (b) 자격 증명 없는 요청의 본문 상한을 작게(예: 64KiB), (c) 배포 쪽(compose {c('mem_limit')}, Caddy JSON 경로 상한, uvicorn {c('limit_concurrency')}). 512MiB 제한에서 동시 4건으로 OOM이 재현됐다. **→ 소유자가 (a)+(c)를 골랐고 PR #25로 고쳤다. 같은 조건에서 수정 뒤 최고 RSS 59MB, 서버 생존.**")
R.append(f"2. **도구 인자 길이 상한 16KiB.** (→ 소유자가 실사용 사례를 보고 정하기로 함. 그때까지 유지)  수정에서 에이전트 문자열 인자(write_file 본문 제외)를 16KiB로 묶었다(넘으면 413). 정책 판단이 가장 느린 모양에서도 16KiB면 0.06초다. 긴 exec 스크립트를 쓰는 사용 방식이 있으면 값을 올리거나 413 대신 '너무 길어 분석하지 않음' 승인으로 돌리는 쪽을 고를 수 있다.")
R.append(f"3. **policy-cpu 레코드.** 5단계가 낸 교체 레코드의 재검증 결과가 JSON 형식이 깨져 버렸다. **→ 소유자가 다시 검토하기로 해 31번째 호출로 재검증했고, 교체 레코드(같은 판정, 수정 방향 정정)를 반영했다.**")
R.append(f"4. **보류 {len(deferred)}단위**를 다음 run에서 볼지, 예산을 얼마로 할지. (→ run-6을 다른 세션에서 하기로 함. 계획은 {c('HANDOFF.md')} run-5 절)")
R.append("")

# ------------------------------------------------------------------ FINDINGS-DETAIL.md
D = ["# run-5 확정 상세", "",
     f"{c('findings.json')}의 확정 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같다. 항목마다 아래에 영어 레코드 원문을 접어 두었고, 원문이 기준이다. 줄 번호는 감사 기준 {c('346df29')}을 따른다. 확정 건은 소유자 지시로 같은 PR에서 고쳤다(각 항목의 수정 방향 참조).", ""]
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
N = ["# run-5 검증 필요 항목", "",
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
    if ko(r, "live"):
        N.append("**부모 실측 (에이전트 예산 밖).** 실측 결과는 5단계·재검증을 거쳐 레코드에 들어갔다. 판정은 배포의 메모리 제한을 몰라 검증 필요로 남았다.")
        N.append("")
        N.append(ko(r, "live"))
        N.append("")
    N.extend(original(r, ["description", "claimed_root_cause", "trace", "blockers", "validation_plan"]))


def write():
    for name, lines in (("REPORT.md", R), ("FINDINGS-DETAIL.md", D), ("NEEDS-VALIDATION.md", N)):
        open(f"{RUN}/{name}", "w", encoding="utf-8").write("\n".join(lines).rstrip("\n") + "\n")
    print("reports written:", len(conf), "confirmed,", len(nv), "needs_validation,", len(rej), "rejected")


if __name__ == "__main__":
    write()
