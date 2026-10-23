"""사람이 보는 화면(터미널, 웹)에 문자열을 찍기 전의 제어 문자 처리.

에이전트·컨테이너가 정한 문자열을 그대로 찍으면 안 된다. 터미널은 C0·DEL·C1 제어 문자를 해석해 커서 이동·줄 지우기를
하고, 양방향(bidi) 재배치 문자가 남으면 터미널도 브라우저도 글자 순서를 바꿔 보여서 화면의 명령이 실제와 다르게 읽힌다
(보안 검수 run-3 v03, v13).
"""

from __future__ import annotations

import re

# C0·DEL·C1 제어 문자와 양방향(bidi) 재배치 문자.
UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# 줄바꿈(\n)과 탭(\t)은 화면에서 그대로 보여도 되니 뺀 것. 웹 UI가 쓴다.
_UNSAFE_KEEP_NEWLINES = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def escape_controls(s: str, keep_newlines: bool) -> str:
    """제어 문자는 \\x1b처럼 보이게 바꾼다. keep_newlines면 줄바꿈과 탭은 그대로 둔다."""
    pat = _UNSAFE_KEEP_NEWLINES if keep_newlines else UNSAFE
    return pat.sub(lambda m: f"\\x{ord(m[0]):02x}" if ord(m[0]) < 0x100 else f"\\u{ord(m[0]):04x}", s)
