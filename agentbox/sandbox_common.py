"""샌드박스 모듈들이 같이 쓰는 작은 정의: 예외, 컨테이너 쪽 시간 제한 argv, 출력 자르기, 작업 경로.

sandbox.py가 데스크톱 도구(sandbox_desktop.py)와 영향 미리보기(preview.py)를 섞어 쓰므로, 그쪽에서 다시
sandbox.py를 import하면 순환이 된다. 그래서 둘이 함께 필요로 하는 것만 여기 두고, 이 모듈은 다른 agentbox 모듈을
import하지 않는다. sandbox.py가 그대로 다시 내보내므로 `from agentbox.sandbox import SandboxError`는 변함없다.
"""

from __future__ import annotations

WORKSPACE = "/workspace"
SOURCE = "/source"
_OUT_LIMIT = 64 * 1024


class SandboxError(RuntimeError):
    pass


def _timed(seconds: int, *argv: str, kill_after: int = 2) -> list[str]:
    """컨테이너 안에서 제한 시간을 거는 argv. 시간이 지나면 TERM, kill_after초 뒤에도 안 끝나면 KILL."""
    return ["timeout", "-k", str(kill_after), str(seconds), *argv]


def _truncate(b: bytes | None, total: int | None = None) -> str:
    """total은 잘라 낸 뒤 b만 들고 있을 때의 원래 길이."""
    if not b:
        return ""
    total = len(b) if total is None else total
    s = b[:_OUT_LIMIT].decode("utf-8", errors="replace")
    if total > _OUT_LIMIT:
        s += f"\n…({total - _OUT_LIMIT} bytes 생략)"
    return s
