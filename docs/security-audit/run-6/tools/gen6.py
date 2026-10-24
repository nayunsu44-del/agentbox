#!/usr/bin/env python3
"""Render the Korean Phase 6 reports for run-6 (REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md).

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
R = ["# agentbox 보안 감사 run-6 보고서", ""]
R.append(
    f"감사 기준은 {c('main')} 커밋 {c('530b29e')}(run-5 수정 PR #24·#25 반영 이후)이다. "
    f"프로필은 {c('standard')}, 서브에이전트 호출 상한은 소유자가 정한 **30**(모두 {c('flash')} 모델)이다. "
    "run-5에서 보류한 7단위(상위 4단위 + 나머지 3단위)와 PR #24·#25가 바꾼 코드 4단위를 합친 **11단위 전체 후속 감사**다. "
    "1차 보고 뒤 소유자 지시('사용에 영향 없는 건 보고 없이 수정')에 따라 확정 3건(F1~F3)과 검증 필요 하드닝 3건(N1~N3)을 모두 수정하고 회귀 테스트를 추가했다."
)
R.append("")
R.append("## 1. 요약")
R.append("")
sev_str = ", ".join(f"{SK[k]} {v}건" for k, v in sorted(sev.items(), key=lambda x: ORDER[x[0]])) or "없음"
R.append(
    f"- 확정 **{len(conf)}건**({sev_str}), 검증 필요 **{len(nv)}건**, 기각 **{len(rej)}건**(총 레코드 {len(recs)}건)."
)
R.append(
    f"- 장부 {len(L)}단위: 헌팅한 {len(hunted)}단위는 모두 닫혔다"
    f"({', '.join(f'{k} {v}' for k, v in sorted(st.items()) if k != 'deferred')}). "
    + (f"최종 비평(critic-2)이 낸 {len(deferred)}단위는 {c('deferred')}로 기록했다." if deferred else "보류(deferred)로 남은 단위는 없다.")
)
R.append(
    f"- 서브에이전트 예산 {M['agents_spent_total']}/{M['budget']}회를 썼다(모두 {c('flash')}): "
    f"헌터 {M_['hunters']}, 형식 재시도 {M_['retries']}, 3단계 {M_['phase3']}, 5단계 {M_['phase5']}, "
    f"재검증 {M_['reverify']}, 비평 {M_['critics']}. 정찰은 부모가 수행했다(0회). "
    f"실제 Docker 데몬과 데스크톱 이미지가 필요한 확인 5건은 부모가 일회용 컨테이너에서 직접 수행했다({c('agents/parent-live/artifacts/')}, 예산 밖)."
)
R.append(
    "- **PR #24·#25 수정 검증 결과:** PR #24가 고친 3개 영역(DesktopControl 잠금 분리·웹소켓 스레드풀 오프로드·prune 아카이브 보존, "
    "GUI 구간 인수 중 열기 차단, 에이전트 도구 인자 16KiB 상한·`_relex_changes`·미리보기 40회/50메모 상한·대기 승인 행 128KiB 상한)과 "
    "PR #25가 고친 1개 영역(`_BodyLimit` 본문 읽기 전 자격 증명 확인·`/login` 64KiB 상한·배포 설정 상한)은 모두 현재 코드에서 안전하게 지켜짐(`covered`)을 확인했다."
)
R.append(
    "- **PR #19 제어문자 필터(`display.escape_controls`) 완전성:** 웹 템플릿(`finalize=_shown`)과 CLI(`_safe`)의 모든 에이전트·컨테이너 문자열 출력 경로가 "
    "Bidi·제어문자(`Cc`/`Cf`/`Zl`/`Zp`)를 이스케이프하여 run-4의 미해결 리드(`exec-command-bidi-controls-unneutralized`)가 완전히 해소됨(`covered`)을 확인했다."
)
R.append("")
R.append("## 2. 감사 방법과 경계")
R.append("")
R.append(
    f"- **실행 환경:** Windows 호스트 + Docker Desktop WSL2 리눅스 엔진. 모든 서브에이전트 검증 스크립트는 {c('tools/sbx.py')}를 통해 "
    f"격리된 일회용 리눅스 컨테이너({c('agentbox-audit-sbx:1')}, `--network none`, 대상 소스 읽기 전용 `/src`, `/scratch`만 쓰기, uid 65534, 512MiB, 1 CPU, 120초) 안에서만 실행했다."
)
R.append(f"- **모델:** 소유자 지시로 모든 서브에이전트(`invoke_subagent`)는 질문 없이 {c('flash')}로만 호출했다.")
R.append(
    f"- **정찰:** 에이전트 호출 없이 부모가 직접 수행했다. run-5 구조 요약에 {c('346df29..530b29e')}(PR #24·#25)에서 바뀐 13개 소스 파일의 변경분과 현재 줄 번호를 반영했다({c('architecture.md')} 0.1절)."
)
R.append(
    "- **범위 단위(11단위):** run-5 보류 상위 4단위(`same_origin` 스킴 비교, 컨테이너 출력 판독기 상한, 승인 미리보기의 정확성, `AuditLog._lock` 경합) + "
    "PR #24·#25 변경 4단위 + 나머지 보류 3단위(Docker data-root 증가와 `disk_low`, 복원 전후 `GuiBursts.covers` 컨테이너 ID 바인딩, PR #19 제어문자 필터 완전성). "
    "1차 파동 뒤 사후 비평(`critic-1`)이 빠진 단위가 없음을 확인하고 `stop: true`를 반환했다."
)
R.append("")
R.append("## 3. 확정 항목 (모두 수정 완료)")
R.append("")
R.append("| ID | 심각도 | 제목 | 주 경로 | 권장 수정 방향 |")
R.append("|---|---|---|---|---|")
for r in conf:
    R.append(
        f"| {cid[r['fingerprint']]} | {SK[r['severity']['overall_severity']]} | "
        f"{ko(r, 'title', r['title'])} | {c(main_path(r))} | {ko(r, 'fix')} |"
    )
R.append("")
R.append(f"상세 근거, 샌드박스·실제 컨테이너 재현 결과, 영어 레코드 원문은 {c('FINDINGS-DETAIL.md')}에 있다.")
R.append("")
R.append("## 4. 검증 필요 항목")
R.append("")
R.append("| ID | 제목 | 막힌 지점 (배포·환경 의존) |")
R.append("|---|---|---|")
for r in nv:
    R.append(
        f"| {cid[r['fingerprint']]} | {ko(r, 'title', r['title'])} | {(ko(r, 'blockers', ['']) or [''])[0]} |"
    )
R.append("")
R.append(f"검증 계획과 부모의 일회용 Docker 컨테이너 실측은 {c('NEEDS-VALIDATION.md')}에 있다.")
R.append("")
R.append("## 5. 기각 항목")
R.append("")
if rej:
    for r in rej:
        R.append(f"- **{cid[r['fingerprint']]}. {ko(r, 'title', r['title'])}** {ko(r, 'reason')}")
else:
    R.append("- 이번 run에서 기각(`rejected`)된 후보는 없다.")
R.append("")
R.append("## 6. 커버리지와 비평 결과")
R.append("")
R.append(
    f"- 헌팅한 11단위 중 5단위는 보안 불변식이 지켜짐을 확인해 {c('covered')}로 닫았고, "
    f"6단위는 후보를 내어 3단계·5단계 검증을 거쳐 확정 {len(conf)}건({c('confirmed')})과 검증 필요 {len(nv)}건({c('needs_validation')})으로 닫았다."
)
if deferred:
    R.append(f"- 최종 비평(`critic-2`)이 제안한 추가 보류({c('deferred')}) {len(deferred)}단위:")
    for u in deferred:
        R.append(f"  - [critic-2] {u['surface'][:160]}{'…' if len(u['surface']) > 160 else ''}")
else:
    R.append("- 사후 비평(`critic-1`)과 최종 비평(`critic-2`) 모두 빠진 단위 없이 `stop: true`를 반환했다.")
R.append("")
R.append("## 7. 후속 수정 결과 (소유자 지시 반영)")
R.append("")
R.append(
    "정상 사용에 영향을 주지 않는 범위에서 확정 3건(F1~F3)과 검증 필요 하드닝 3건(N1~N3)을 모두 수정하고 "
    "`tests/test_m5_unit.py`에 회귀 테스트 6개를 추가했다:\n"
    "- **F1 (`agentbox/audit.py`):** `SCHEMA`에 `CREATE INDEX IF NOT EXISTS idx_audit_sandbox_id ON audit (sandbox_id, id)`를 추가하고, `verify()`·`verify_archives()`가 `_VERIFY_BATCH = 200`행씩 끊어 읽고 해시 계산은 `self._lock` 밖에서 수행하도록 수정했다.\n"
    "- **F2 (`agentbox/gui_bursts.py`, `agentbox/service.py`):** `GuiBursts.covers(sid)`가 `burst.get('container_id') == self.sandboxes.get(sid)['container_id']`까지 확인하고, `restore_sandbox`가 `sandboxes.restore` 뒤에 `self.bursts.end(sid, 'sandbox_restored')`를 호출해 복원 중 열린 옛 구간을 닫도록 수정했다.\n"
    "- **F3 (`agentbox/preview.py`, `agentbox/sandbox.py`):** `preview_command`가 명령에 `{` 또는 `~`가 있으면 주의 문구를 남기고 매칭이 없을 때 `'삭제 시도 (중괄호·틸드 확장 — 명령 원문 확인)'`으로 표시하며, `_expand`가 앞쪽 `~`/`~/`를 `$HOME`으로 펼치도록 수정했다.\n"
    "- **N1 (`agentbox/api.py`, `agentbox/web.py`, `deploy/Caddyfile`):** `secure_cookie(request)`가 참(`AGENTBOX_SECURE_COOKIE=1` 또는 `https`/`wss` 요청)일 때 `same_origin()`이 `Origin`의 `https` 스킴까지 요구하도록 하고, `deploy/Caddyfile`에 `Strict-Transport-Security` 헤더를 추가했다(로컬 평문 HTTP 개발 환경은 기존대로 동작).\n"
    "- **N2 (`agentbox/sandbox.py`, `agentbox/sandbox_desktop.py`):** `list_dir`가 `_exec_head`(`_timed` + `_Head` 64KiB 스트리밍 상한)를 쓰고, `outbox_list`(`_timed` + `head -c 524288`), `_expand`(`head -z -n`), `screenshot`(`rm -f` + 일반 파일 확인 + `head -c 16MiB`)에 상한을 걸었다.\n"
    "- **N3 (`agentbox/sandbox.py`, `agentbox/service.py`):** `SandboxManager._detect_runtime()`이 `client.info()`의 `DockerRootDir`를 저장하고, `AgentBox.disk_low()`가 접근 가능한 `docker_root`의 남은 공간도 함께 확인하도록 수정했다."
)
R.append("")

# ------------------------------------------------------------------ FINDINGS-DETAIL.md
D = [
    "# run-6 확정 상세",
    "",
    f"{c('findings.json')}의 확정(`confirmed`) 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같으며, 항목마다 아래에 영어 레코드 원문(기준)을 접어 두었다. 줄 번호는 감사 기준 {c('530b29e')}을 따른다. 보고 이후 확정 3건과 검증 필요 3건 모두 수정 완료되었다.",
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
    "# run-6 검증 필요 항목",
    "",
    "코드 상의 동작은 샌드박스와 일회용 Docker 컨테이너에서 확인했으나, 실제 악용 가능성과 영향이 운영 배포 구성(리버스 프록시, 파일시스템 파티션 분리, 호스트 리소스 한도)에 좌우되어 `needs_validation`으로 분류한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.",
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
