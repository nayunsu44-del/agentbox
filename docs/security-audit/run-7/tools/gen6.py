#!/usr/bin/env python3
"""Render the Korean Phase 6 reports for run-7 (REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md).

Korean text comes from ko_text.KO (written by the parent from findings.json). Every entry keeps
the English record fields below it as the authoritative original. Counts, statuses and paths are
computed from findings.json, the ledger and run-metadata.json.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN  # noqa: E402
from ko_text import KO  # noqa: E402
from report_notes import HARDENING  # noqa: E402

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
COND = {
    "authentication_level": "인증 수준",
    "authorization_role": "권한",
    "user_interaction": "사용자 상호작용",
    "system_configuration": "시스템 설정",
    "network_routing": "네트워크 경로",
    "environmental_dependency": "환경 의존",
    "data_state": "데이터 상태",
    "timing_dependency": "타이밍",
    "third_party_dependency": "외부 의존",
}

conf = sorted(
    [r for r in recs if r["verdict"] == "confirmed"],
    key=lambda r: (ORDER.get(r["severity"]["overall_severity"], 9), r["fingerprint"]),
)
nv = [r for r in recs if r["verdict"] == "needs_validation"]
rej = [r for r in recs if r["verdict"] == "rejected"]
cid = {r["fingerprint"]: f"F{i}" for i, r in enumerate(conf, 1)}
cid.update({r["fingerprint"]: f"R{i}" for i, r in enumerate(rej, 1)})
cid.update({r["fingerprint"]: f"N{i}" for i, r in enumerate(nv, 1)})
st = collections.Counter(u["status"] for u in L)
sev = collections.Counter(r["severity"]["overall_severity"] for r in conf)


def _rank(u):
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
                out.append(
                    "- "
                    + c(f"{t.get('file')}:{t.get('line')}")
                    + f" ({t.get('kind')}, {t.get('scope', '')}) — {t.get('description', '')}"
                )
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
hunted = [u for u in L if u["status"] not in ("deferred", "planned")]
R = ["# agentbox 보안 감사 run-7 보고서", ""]
R.append(
    f"감사 기준은 {c('main')} 커밋 {c('3580df0')}(PR #26 병합 뒤)이고, 대상은 run-6 이후 변경분 {c('530b29e..3580df0')}이다: "
    f"run-6 확정·하드닝 수정 {c('7dbda9e')}, 리팩토링 {c('5bb3c17')}, IF-1 에이전트 지시 파일({c('d4e956e')}·{c('79d8211')}·{c('ccaf367')}·{c('a0a186c')}). "
    f"프로필은 {c('standard')}, 서브에이전트 호출 상한은 소유자가 정한 15였고 critic-1 뒤 소유자 승인으로 **20**으로 올렸다. "
    "보고 전용이며 감사 소스는 고치지 않았다."
)
R.append("")
R.append("## 1. 요약")
R.append("")
sev_str = ", ".join(f"{SK[k]} {v}건" for k, v in sorted(sev.items(), key=lambda x: ORDER[x[0]])) or "없음"
R.append(f"- 확정 **{len(conf)}건**({sev_str}), 검증 필요 **{len(nv)}건**, 기각 **{len(rej)}건**(총 레코드 {len(recs)}건).")
R.append(
    f"- 장부 {len(L)}단위가 모두 닫혔다({', '.join(f'{k} {v}' for k, v in sorted(st.items()))}). "
    "critic-1이 IF-policy 단위를 다시 맡기라고 했고 2차 헌터가 닫았다. 최종 비평 critic-2는 빠진 단위·재할당 없이 `stop: true`를 반환했다."
)
R.append(
    f"- 서브에이전트 {M['agents_spent_total']}/{M['budget']}회: 헌터 {M_['hunters']}(2차 1 포함), 3단계 {M_['phase3']}, 5단계 {M_['phase5']}, 비평 {M_['critics']}, 형식 재시도 {M_['retries']}. "
    f"정찰은 부모가 했다(0회). 실제 Docker가 필요한 확인 5건은 부모가 예산 밖에서 했다({c('agents/parent-live/')})."
)
R.append(
    "- **run-6 수정(7dbda9e):** F1(GUI 구간 컨테이너 묶기), F2(감사 인덱스·나눠 검사), F3(미리보기 경고), N1(스킴 검사·HSTS), N2(출력 상한)는 근본 원인을 막았다. "
    "N3(`disk_low`의 Docker 저장소)은 compose 구성에서 경로를 볼 수 없어 조용히 건너뛰므로 같은 지문으로 검증 필요에 다시 올렸다."
)
R.append("- **리팩토링(5bb3c17):** 승인 요청 순서, 저장·기록·실행 인수, GUI 구간 판정이 그대로임을 diff와 단위 테스트(34개 통과)로 확인했다(`covered`).")
R.append(
    "- **IF-1:** 단발 리뷰가 고친 7건과 검증 필요 2건은 다시 보고하지 않았다. 그 수정의 우회 2건(링크 끝 조각, `resolve()` 실패)과 "
    "단발 F1 수정이 만든 렌더링 비용 1건을 확정했고, 이름 접기 1건은 macOS 확인이 필요해 검증 필요로 남겼다. 읽기 결과 경계와 원본 훑기는 `covered`다."
)
R.append("")
R.append("## 2. 감사 방법과 경계")
R.append("")
R.append(
    "- **실행 환경:** Kiro Web 리눅스 샌드박스. 명령마다 새 샌드박스가 뜨므로, 대상 코드는 호출마다 사설 마운트 네임스페이스에 dockerd를 띄우는 "
    f"{c('tools/sbx.py')}로만 돌렸다(`--network none`, 읽기 전용 `/target`, uid 65534, 512MiB는 RLIMIT_DATA, 1 CPU는 cpuset, 64 pids, 120초)."
)
R.append(
    "- **모델:** 서브에이전트 도구에 모델 선택 인수가 없어 모두 세션 모델(Claude Opus 5.5)로 돌았다. 소유자가 요청한 Sonnet 5.5로는 바꿀 수 없었고, 이를 "
    f"{c('run-metadata.json')}에 적었다."
)
R.append(
    "- **장부(7단위):** run6-fixes, refactor, IF-kind, IF-policy, IF-notice, IF-sinks, IF-scan. run-6 장부에 `deferred`가 없어 이전 보류 단위는 없다."
)
R.append(
    "- **parent-live(예산 밖):** 정찰 단서, 승인 카드 렌더링 비용, compose 구성의 `disk_low`, `resolve()` fail-open, 그리고 IF 수용 테스트 6개(모두 통과)."
)
R.append(
    f"- **진행 중 벗어난 것:** {c('run-metadata.json')}의 `deviations`에 적었다(스킬을 tarball로 받음, 헌터 결과 옮겨 적기, 잘린 3단계 출력 복원, 5단계 한 번에 두 레코드 등)."
)
R.append("")
R.append("## 3. 확정 항목")
R.append("")
R.append("| ID | 심각도 | 제목 | 주 경로 | 권장 수정 방향 |")
R.append("|---|---|---|---|---|")
for r in conf:
    R.append(
        f"| {cid[r['fingerprint']]} | {SK[r['severity']['overall_severity']]} | "
        f"{ko(r, 'title', r['title'])} | {c(main_path(r))} | {ko(r, 'fix')} |"
    )
R.append("")
R.append(f"근거, 실제 컨테이너 재현 결과, 영어 레코드 원문은 {c('FINDINGS-DETAIL.md')}에 있다.")
R.append("")
R.append("## 4. 검증 필요 항목")
R.append("")
R.append("| ID | 제목 | 막힌 지점 |")
R.append("|---|---|---|")
for r in nv:
    R.append(f"| {cid[r['fingerprint']]} | {ko(r, 'title', r['title'])} | {(ko(r, 'blockers', ['']) or [''])[0]} |")
R.append("")
R.append(f"검증 계획과 부모 실측은 {c('NEEDS-VALIDATION.md')}에 있다.")
R.append("")
R.append("## 5. 기각 항목")
R.append("")
R.append("- 이번 run에서 기각된 후보는 없다." if not rej else "\n".join(f"- {cid[r['fingerprint']]}. {r['title']}" for r in rej))
R.append("")
R.append("## 6. 하드닝 메모 (결함으로 보고하지 않음)")
R.append("")
for line in HARDENING:
    R.append("- " + line)
R.append("")
R.append("## 7. 다음 일")
R.append("")
R.append("- 수정 여부와 범위는 소유자가 정한다. F2와 F3는 같은 곳(정책의 지시 파일 판정)을 고치므로 함께 고치는 것이 낫다.")
R.append("- 검증 필요 2건은 배포 구성 확인(compose의 Docker 저장소 위치)과 macOS 확인(U+0130)이 필요하다.")
R.append("")

# ------------------------------------------------------------------ FINDINGS-DETAIL.md
D = [
    "# run-7 확정 상세",
    "",
    f"{c('findings.json')}의 확정(`confirmed`) 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같으며, 항목마다 아래에 영어 레코드 원문(기준)을 접어 두었다. 줄 번호는 감사 기준 {c('3580df0')}을 따른다. 보고 전용이며 수정은 소유자가 정한다.",
    "",
]
for r in conf:
    s = r["severity"]
    D.append(f"## {cid[r['fingerprint']]}. [{SK[s['overall_severity']]}] {ko(r, 'title', r['title'])}")
    D.append("")
    D.append("- 지문: " + c(r["fingerprint"]))
    D.append(
        f"- 심각도: 가능성 {SK[s['likelihood']['score']]} · 영향 {SK[s['impact']['score']]} · 종합 **{SK[s['overall_severity']]}**. 신뢰도: {r['confidence']['score']}"
    )
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
    D.append(
        "**성립 조건.** "
        + ", ".join(COND.get(x["kind"], x["kind"]) for x in r.get("conditions", []))
        + ". 조건별 설명은 아래 원문의 `conditions`에 있다."
    )
    D.append("")
    D.append("**권장 수정 방향.** " + ko(r, "fix"))
    D.append("")
    D.extend(original(r, ["description", "root_cause", "intended_behavior", "trace", "conditions", "execution", "remediation"]))

# ------------------------------------------------------------------ NEEDS-VALIDATION.md
N = [
    "# run-7 검증 필요 항목",
    "",
    "코드의 동작은 샌드박스와 일회용 Docker 컨테이너에서 확인했으나, 실제 영향이 운영 배포 구성(파일 시스템 분리)이나 감사 환경에 없는 OS(macOS)에 좌우되어 `needs_validation`으로 분류한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.",
    "",
]
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
        N.append("**부모 실측 (일회용 컨테이너, 에이전트 예산 밖).**")
        N.append("")
        N.append(ko(r, "live"))
        N.append("")
    N.extend(original(r, ["description", "claimed_root_cause", "trace", "blockers", "validation_plan"]))


def write():
    for name, lines in (("REPORT.md", R), ("FINDINGS-DETAIL.md", D), ("NEEDS-VALIDATION.md", N)):
        with open(f"{RUN}/{name}", "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines).rstrip("\n") + "\n")
    print("reports written:", len(conf), "confirmed,", len(nv), "needs_validation,", len(rej), "rejected")


if __name__ == "__main__":
    write()
