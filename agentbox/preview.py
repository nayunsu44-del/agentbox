"""승인 화면용 영향 미리보기: 명령을 조각으로 나눠 rm·curl이 건드릴 파일과 주소를 계산한다.

컨테이너를 직접 부르지 않는다. glob 펼치기(expand)와 폴더 훑기(walk)는 함수로 받아서, 도커 없이도 명령 해석을
테스트할 수 있다. sandbox.SandboxManager.preview가 컨테이너 조회를 넘겨 준다.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from typing import Any

from .sandbox_common import SOURCE, WORKSPACE

# ---------------------------------------------------------------------------
# 영향 미리보기: 승인 화면에 보여줄 '시스템이 계산한' 영향 범위
# ---------------------------------------------------------------------------

_WRAPPERS = ("xargs", "sudo", "env", "nohup", "timeout", "nice")


def _short_seg(seg: list[str]) -> str:
    text = " ".join(seg)
    return text if len(text) <= 80 else text[:79] + "…"


def _split_segments(command: str, depth: int = 0) -> list[list[str]]:
    """명령을 ; && || | 단위 argv 조각으로 나눈다. sh -c / bash -c 안쪽은 펼친다."""
    if depth > 3:
        return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        return [command.split()]
    segs: list[list[str]] = [[]]
    for t in tokens:
        if t and all(c in ";&|()<>" for c in t):
            segs.append([])
        else:
            segs[-1].append(t)
    out: list[list[str]] = []
    for s in segs:
        if not s:
            continue
        name = s[0].rsplit("/", 1)[-1]
        if name in ("sh", "bash", "dash", "zsh") and "-c" in s:
            i = s.index("-c")
            if i + 1 < len(s):
                out.extend(_split_segments(s[i + 1], depth + 1))
                continue
        if name in _WRAPPERS and len(s) > 1:
            out.append(s)  # 원래 조각도 남기고
            rest = s[1:]
            while rest and (rest[0].startswith("-") or re.match(r"^\w+=", rest[0]) or rest[0].isdigit()):
                rest = rest[1:]
            if rest:
                out.append(rest)
            continue
        out.append(s)
    return out


# 미리보기가 컨테이너에 보내는 exec(펼치기·훑기) 수와 조각 메모 수의 상한. 넘으면 나머지는 계산하지 않고 그렇다고 알린다.
# 그러지 않으면 'rm -r d d d …'나 'x;x;x;…' 한 번에 exec가 피연산자 수만큼 돌고 메모가 요청의 수십 배로 커진다
# (보안 검수 run-5)
PREVIEW_CALLS_MAX = 40
NOTES_MAX = 50


def preview_command(command: str, limit: int, expand: Callable[[str], list[str]],
                    walk: Callable[[str, int], list[str]]) -> dict[str, Any]:
    affected: list[dict[str, str]] = []
    notes: list[str] = []
    calls = 0
    skipped = 0

    def budget() -> bool:
        """exec를 하나 더 써도 되는가. 표가 이미 찼거나 상한을 다 썼으면 False."""
        nonlocal calls
        if calls >= PREVIEW_CALLS_MAX or len(affected) >= limit:
            return False
        calls += 1
        return True
    if any(s in command for s in ("$", "`", "<(", "eval ")):
        notes.append("변수·명령 치환이 있어 실제로 무엇이 실행될지 자동 계산이 정확하지 않을 수 있음. 명령 원문을 확인할 것.")
    for seg in _split_segments(command):
        if not seg:
            continue
        name = seg[0].rsplit("/", 1)[-1]
        if name == "rm":
            recursive = any(a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a)
                            for a in seg[1:]) or "--recursive" in seg
            operands, opts_done = [], False
            for a in seg[1:]:
                if not opts_done and a == "--":
                    opts_done = True
                    continue
                if not opts_done and a.startswith("-") and a != "-":
                    continue
                operands.append(a)
            for op in dict.fromkeys(operands):   # 같은 피연산자를 되풀이해도 한 번만 본다
                if not budget():
                    skipped += 1
                    continue
                matches = expand(op)
                if not matches:
                    affected.append({"path": op, "effect": "삭제 시도 (현재 존재하지 않음)"})
                for m in matches:
                    if m == SOURCE or m.startswith(SOURCE + "/"):
                        affected.append({"path": m, "effect": "삭제 시도 → 실패 예정 (원본은 읽기 전용)"})
                        continue
                    if recursive and not budget():
                        skipped += 1
                        continue
                    items = walk(m, limit) if recursive else [m]
                    for it in items:
                        affected.append({"path": it, "effect": "삭제"})
        elif name == "curl":
            urls = [a for a in seg[1:] if re.match(r"^[a-z][a-z0-9+.-]*://", a, re.I)]
            uploads = []
            for i, a in enumerate(seg[1:], start=1):
                v = None
                if a.startswith("@"):
                    v = a[1:]
                elif a.startswith("--data") or a in ("-d", "-F", "-T", "--upload-file", "--form"):
                    nxt = seg[i + 1] if i + 1 < len(seg) else ""
                    if "=@" in nxt:
                        v = nxt.split("=@", 1)[1]
                    elif nxt.startswith("@"):
                        v = nxt[1:]
                    elif a in ("-T", "--upload-file"):
                        v = nxt
                if v:
                    if budget():
                        uploads.extend(expand(v) or [v])
                    else:
                        skipped += 1
                        uploads.append(v)
            for u in urls:
                affected.append({"path": u, "effect": "외부 접속 시도 (샌드박스는 network=none이라 실패 예정)"})
            for u in uploads:
                affected.append({"path": u, "effect": "외부로 보낼 파일"})
            if not urls:
                notes.append("curl 대상 주소를 명령에서 찾지 못함.")
        elif name not in _WRAPPERS:  # 감싸는 명령은 안쪽 조각을 따로 본다
            # rm·curl 말고는 영향을 계산하지 않는다. 계산한 줄이 있어도 이 조각의 영향은 표에 없다는 것을
            # 조각마다 알린다 (보안 검수 run-3 v17: 'rm a; mv b /tmp'가 'a 삭제' 한 줄로만 보였다)
            notes.append(f"'{_short_seg(seg)}' 부분의 영향은 자동 계산하지 못함. 명령 원문을 확인할 것.")
    if skipped:
        notes.append(f"삭제·전송 대상 {skipped}개는 미리보기 상한(컨테이너 확인 {PREVIEW_CALLS_MAX}회)을 넘어 계산하지 않음. "
                     "명령 원문을 확인할 것.")
    if len(notes) > NOTES_MAX:
        extra = len(notes) - NOTES_MAX
        notes = notes[:NOTES_MAX] + [f"이 밖에 {extra}개 조각의 영향도 자동 계산하지 못함. 명령 원문을 확인할 것."]
    if len(affected) > limit:
        notes.append(f"영향 항목 {len(affected)}개 중 앞의 {limit}개만 표시.")
        affected = affected[:limit]
    if not affected and not notes:
        notes.append("시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.")
    return {"command": command, "cwd": WORKSPACE, "affected": affected, "notes": notes}
