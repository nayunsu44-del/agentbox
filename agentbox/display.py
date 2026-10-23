"""사람이 보는 화면(터미널, 웹)에 문자열을 찍기 전의 제어 문자 처리.

에이전트·컨테이너가 정한 문자열을 그대로 찍으면 안 된다. 터미널은 C0·DEL·C1 제어 문자를 해석해 커서 이동·줄 지우기를
하고, 양방향(bidi) 재배치 문자가 남으면 터미널도 브라우저도 글자 순서를 바꿔 보여서 화면의 명령이 실제와 다르게 읽힌다
(보안 검수 run-3 v03, v13).
"""

from __future__ import annotations

import re
import unicodedata

# 바꿀 문자: 제어(Cc: C0·DEL·C1), 서식(Cf: 양방향(bidi) 재배치, 폭 없는 문자, 소프트 하이픈 등), 줄·문단 구분자(Zl·Zp).
# 손으로 나열하면 빠지는 문자가 생겨서(U+061C, U+200B 등, 보안 검수 run-4 N5) 유니코드 범주로 고른다.
_ESCAPED = {"Cc", "Cf", "Zl", "Zp"}
# 출력 가능한 ASCII는 범주를 볼 필요가 없다.
_CANDIDATE = re.compile("[^\x20-\x7e]")


def _escape(ch: str, keep_newlines: bool) -> str:
    if keep_newlines and ch in "\n\t":
        return ch
    if unicodedata.category(ch) not in _ESCAPED:
        return ch
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}"


def escape_controls(s: str, keep_newlines: bool) -> str:
    """제어 문자는 \\x1b처럼 보이게 바꾼다. keep_newlines면 줄바꿈과 탭은 그대로 둔다 (웹 UI가 쓴다)."""
    return _CANDIDATE.sub(lambda m: _escape(m[0], keep_newlines), s)
