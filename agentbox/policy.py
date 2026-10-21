"""정책 판정 (PL-1).

exec 명령에서 '실행될 프로그램 이름'을 뽑아 규칙과 비교한다.
따옴표·역슬래시·경로(/bin/rm)·명령 연결(; && | $( ))·sh -c 안의 문자열까지 펼쳐 본다.
그래도 변수 치환($X)처럼 실행해 봐야 알 수 있는 우회는 못 잡는다.
그래서 정책은 첫 번째 방어선일 뿐이고, 네트워크 차단과 원본 읽기 전용이 최종 방어선이다.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
_ACTIONS = {ALLOW, DENY, REQUIRE_APPROVAL}

_SHELL_PUNCT = set(";&|()<>`$")


@dataclass
class Decision:
    action: str
    rule_id: str | None
    reason: str | None
    matched: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "rule_id": self.rule_id, "reason": self.reason, "matched": self.matched}


def _words(command: str, depth: int = 0) -> list[str]:
    """명령 문자열에서 단어를 뽑는다. 하위 셸 문자열은 재귀로 펼친다."""
    if depth > 4:
        return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        # 따옴표가 안 닫힌 경우 등. 공백 기준으로라도 본다.
        tokens = command.split()
    out: list[str] = []
    for t in tokens:
        if not t:
            continue
        # $( ... ), ` ... ` 안쪽도 단어로 본다.
        cleaned = t.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ")
        for piece in cleaned.split():
            out.append(piece)
        if any(c.isspace() for c in t) or any(c in _SHELL_PUNCT for c in t):
            out.extend(_words(t, depth + 1))
    return out


def command_names(command: str) -> set[str]:
    """명령에 등장하는 프로그램 이름 후보. 경로는 basename으로."""
    names: set[str] = set()
    for w in _words(command):
        w = w.strip("'\"\\;&|()<>")
        if not w:
            continue
        names.add(w.rsplit("/", 1)[-1])
    return names


def _raw_hits(command: str, names: list[str]) -> set[str]:
    """보수적 2차 확인: 원문에서 단어 경계로 등장하는지."""
    hits = set()
    for n in names:
        if re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(n)}(?![A-Za-z0-9_.-])", command):
            hits.add(n)
    return hits


class Policy:
    def __init__(self, data: dict[str, Any], source: str = "<memory>"):
        self.source = source
        self.default = data.get("default", ALLOW)
        if self.default not in _ACTIONS:
            raise ValueError(f"알 수 없는 default 판정: {self.default}")
        self.rules: list[dict[str, Any]] = []
        for r in data.get("rules", []):
            if r.get("action") not in _ACTIONS:
                raise ValueError(f"규칙 {r.get('id')}: 알 수 없는 action {r.get('action')}")
            if not r.get("id"):
                raise ValueError("규칙에 id가 없음")
            self.rules.append(r)

    @classmethod
    def load(cls, path: Path | str) -> "Policy":
        p = Path(path)
        return cls(yaml.safe_load(p.read_text(encoding="utf-8")) or {}, source=str(p))

    def decide(self, tool: str, args: dict[str, Any]) -> Decision:
        for r in self.rules:
            if r.get("tool") not in (None, "*", tool):
                continue
            match = r.get("match") or {}
            wanted = [str(c) for c in match.get("commands", [])]
            if wanted:
                if tool != "exec":
                    continue
                cmd = str(args.get("command", ""))
                hits = (command_names(cmd) & set(wanted)) | _raw_hits(cmd, wanted)
                if not hits:
                    continue
                return Decision(r["action"], r["id"], r.get("reason"), sorted(hits))
            else:
                return Decision(r["action"], r["id"], r.get("reason"), [])
        return Decision(self.default, None, None, [])
