"""정책 판정 (PL-1).

exec 명령에서 '실행될 프로그램 이름'을 뽑아 규칙과 비교한다.
따옴표·역슬래시·경로(/bin/rm)·명령 연결(; && | $( ))·sh -c 안의 문자열까지 펼쳐 본다.
그래도 변수 치환($X)처럼 실행해 봐야 알 수 있는 우회는 못 잡는다.
기본 정책은 그래서 exec를 허용 목록으로 다룬다: 읽기 전용 프로그램만 쓰는 단순 명령만 바로 실행하고
나머지는 모두 사람 승인을 받는다 (`find -delete`, `python -c` 같은 우회를 이름 목록으로 다 막을 수 없으므로).
정책은 첫 번째 방어선일 뿐이고, 네트워크 차단과 원본 읽기 전용이 최종 방어선이다.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import instruction_files

PATH_TOOLS = {"list_dir", "read_file", "write_file", "delete_file"}   # path 인자로 대상을 정하는 도구

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
_ACTIONS = {ALLOW, DENY, REQUIRE_APPROVAL}

_SHELL_PUNCT = set(";&|()<>`$")
_LEX_PUNCT = set(";&|()<>")   # shlex가 단어를 끊는 문자 (_words의 punctuation_chars)


@dataclass
class Decision:
    action: str
    rule_id: str | None
    reason: str | None
    matched: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "rule_id": self.rule_id, "reason": self.reason, "matched": self.matched}


def _relex_changes(t: str) -> bool:
    """t를 다시 렉싱하면 [t]와 다른 결과가 나올 수 있는가. 예전 조건(공백이나 셸 구분 문자가 있으면 다시 렉싱)에서
    결과가 같을 수밖에 없는 경우만 뺀다: 구분자(;&|()<>)만으로 된 토큰, 그리고 공백·구분자·따옴표·역슬래시가
    하나도 없는 토큰(예: 'x$'). 그런 토큰을 깊이 한도까지 되풀이해 렉싱해, 'x;x;x;…' 같은 명령 하나가 수 초씩
    CPU를 썼다 (보안 검수 run-5). sh -c 'a`r""m`'처럼 따옴표가 남은 토큰은 계속 다시 본다."""
    if all(c in _LEX_PUNCT for c in t):
        return False
    if not any(c.isspace() or c in _SHELL_PUNCT for c in t):
        return False
    return any(c.isspace() or c in _LEX_PUNCT or c in "'\"\\" for c in t)


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
        if _relex_changes(t):
            out.extend(_words(t, depth + 1))
    return out


def command_words(command: str) -> list[str]:
    """명령에 등장하는 단어(경로 그대로). 지시 파일을 가리키는지 볼 때 쓴다 (IF-1)."""
    return [w for w in (w.strip("'\"\\;&|()<>") for w in _words(command)) if w]


def command_names(command: str) -> set[str]:
    """명령에 등장하는 프로그램 이름 후보. 경로는 basename으로."""
    names: set[str] = set()
    for w in _words(command):
        w = w.strip("'\"\\;&|()<>")
        if not w:
            continue
        names.add(w.rsplit("/", 1)[-1])
    return names


# 출력을 버리는 리다이렉션은 파일을 바꾸지 않으므로 읽기 전용 판정에서 빼고 본다.
# 단, '/dev/null' 뒤나 'N>&M' 뒤에 파일 이름 글자가 이어지면(예: '>&2evil', '>/dev/nullx')
# 그건 진짜 파일 리다이렉션이므로 벗겨내지 않는다(뒤의 '>' 검사가 승인으로 보내도록).
_DEVNULL = re.compile(r"\d*>>?\s*/dev/null(?![\w./-])|\d*>&\d+(?![\w./-])")

# bash에서 '#'이 주석을 여는 자리(줄 맨 앞, 또는 따옴표 밖 공백·구분자 바로 뒤).
_COMMENT_BOUNDARY = set(" \t\n\r;&|()")


def has_bash_comment(command: str) -> bool:
    """bash가 주석으로 버리는 '#'(따옴표 밖, 단어 시작 위치)이 있으면 True.

    정책 렉서는 commenters=""라 '#'을 평범한 글자로 보지만 bash는 주석으로 버린다.
    이 틈을 막으려고, 따옴표 밖 단어-시작 '#'이 하나라도 있으면 '단순 명령'으로 보지 않는다.
    따옴표·이스케이프는 bash와 같게 따라간다. 따옴표 안이라고 bash보다 오래 판단하면 실제 주석을
    놓쳐 승인을 건너뛴다(예: 따옴표 밖 \\"를 따옴표 시작으로 보면). 애매하면 주석이 있다고 본다.
    - 작은따옴표 안: 이스케이프 없음. ' 만 닫는다.
    - 큰따옴표 안·따옴표 밖: \\ 다음 글자는 글자 그대로라 따옴표를 열거나 닫지 않고 주석도 시작하지 않는다.
    ($'…' 같은 다른 따옴표는 simple_programs가 '$'에서 이미 승인으로 보낸다.)
    """
    quote: str | None = None
    prev = ""   # 따옴표 밖에서 바로 앞 글자 ("" = 문자열 시작)
    escaped = False
    for ch in command:
        if escaped:
            escaped = False
            prev = ch
            continue
        if quote == "'":
            if ch == "'":
                quote = None
            prev = ch
            continue
        if ch == "\\":
            escaped = True
            prev = ch
            continue
        if quote == '"':
            if ch == '"':
                quote = None
            prev = ch
            continue
        if ch in ("'", '"'):
            quote = ch
            prev = ch
            continue
        if ch == "#" and (prev == "" or prev in _COMMENT_BOUNDARY):
            return True
        prev = ch
    return False


def simple_programs(command: str) -> set[str] | None:
    """변수·명령 치환, 파일 쓰기 리다이렉션, 환경 변수 접두가 없는 단순 명령이면 실행될 프로그램 이름들.
    아니면 None. 읽기 전용 허용 목록(only_commands)은 None이면 맞지 않는 것으로 친다."""
    # bash 주석('#')이 있으면 정책 렉서와 bash의 해석이 갈린다. 승인으로 보낸다.
    if has_bash_comment(command):
        return None
    cmd = _DEVNULL.sub(" ", command)
    if any(s in cmd for s in ("$", "`", ">", "<(")):
        return None
    try:
        lex = shlex.shlex(cmd.replace("\n", " ; "), posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        return None
    programs: set[str] = set()
    start, skip = True, False
    for t in tokens:
        if all(c in ";&|()" for c in t):     # ; && || | |& ( ) 등. 다음 단어가 프로그램
            start = True
            continue
        if t == "<":
            skip = True
            continue
        if skip:
            skip = False
            continue
        if start:
            if "=" in t.split("/", 1)[0]:
                return None          # LD_PRELOAD=… cat 같은 접두는 허용 목록 밖
            programs.add(t.rsplit("/", 1)[-1])
            start = False
    return programs


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
            if match.get("instruction_files"):
                # 경로 인자가 에이전트 지시 파일(CLAUDE.md, AGENTS.md, .claude/ 등)을 가리킬 때만 맞는다 (IF-1).
                # resolved_path는 서비스가 컨테이너 안에서 링크를 푼 실제 대상이다. 'cfg -> .claude' 링크를 거쳐
                # cfg/settings.json에 쓰면 요청 경로만으로는 지시 파일이 아니다 (보안 검수 IF-1 단발 F2)
                if tool not in PATH_TOOLS:
                    continue
                hit = next((x for x in (args.get("path"), args.get("resolved_path"))
                            if isinstance(x, str) and instruction_files.kind(x)), None)
                if hit is None:
                    continue
                return Decision(r["action"], r["id"], r.get("reason"), [hit])
            wanted = [str(c) for c in match.get("commands", [])]
            only = [str(c) for c in match.get("only_commands", [])]
            if only:
                # 모든 프로그램이 목록 안에 있는 단순 명령일 때만 맞는다 (읽기 전용 허용 목록)
                if tool != "exec":
                    continue
                progs = simple_programs(str(args.get("command", "")))
                if not progs or not progs <= set(only):
                    continue
                return Decision(r["action"], r["id"], r.get("reason"), sorted(progs))
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
