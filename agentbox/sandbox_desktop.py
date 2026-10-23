"""데스크톱 템플릿의 GUI 도구 (TL-2): 화면 캡처, 클릭, 키 입력, 화면 보기 연결, 프로세스 목록.

SandboxManager에 섞는 mixin이다. 컨테이너 조회·실행 중 확인(`_container`, `_require_running`, `template_of`)과
`settings`, `client`는 SandboxManager가 준다. GUI 도구와 화면 보기만 desktop 계정(X 쿠키 소유)으로 돌고,
에이전트의 exec는 그 계정이 아니라서 화면에 붙지 못한다.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

from docker.errors import APIError, ImageNotFound, NotFound

from .gui_state import _parse_ps
from .sandbox_common import SandboxError, _timed, _truncate

_NOVNC_LOCK = threading.Lock()
_NOVNC_RETRY = 60   # noVNC 꺼내기에 실패한 뒤 다시 시도하기까지(초)

# 화면(X)과 구간 기록용 exec의 제한 시간(초). X 서버가 멈추면 xdotool·scrot은 끝없이 기다리고, 그동안 gui_lock과
# 부른 스레드가 묶인다. 컨테이너 안에서 끊어야 exec가 돌아온다 (클라이언트 쪽 시간 제한으로는 풀리지 않았다).
_X_TIMEOUT = 15
_TIMED_OUT = (124, 137)   # timeout(1)이 끊었을 때의 종료 코드 (TERM, 안 끝나서 KILL)

# 데스크톱 템플릿 (images/desktop/Dockerfile과 맞춘다)
DESKTOP_USER = "desktop"
DESKTOP_ENV = {"DISPLAY": ":0", "XAUTHORITY": "/home/desktop/.Xauthority", "HOME": "/home/desktop"}
_SHOT = "/home/desktop/.cache/agentbox-shot.png"
_BUTTONS = {"left": "1", "middle": "2", "right": "3"}
_KEY_RE = re.compile(r"^[A-Za-z0-9_+]{1,40}$")


class DesktopTools:
    # ---- TL-2 GUI 도구 (데스크톱 템플릿) --------------------------------
    def _desktop(self, sid: str):
        if not self.template_of(sid).desktop:
            raise SandboxError("데스크톱이 없는 샌드박스 (template=desktop으로 만들 것)")
        return self._require_running(sid)

    @staticmethod
    def _x(c, argv: list[str], timeout: int = _X_TIMEOUT):
        res = c.exec_run(_timed(timeout, *argv),
                         user=DESKTOP_USER, environment=DESKTOP_ENV, demux=True)
        if res.exit_code in _TIMED_OUT:  # 반쯤 받은 결과(창 목록 등)로 판단하지 않게 실패로 돌린다
            raise SandboxError(f"화면(X 서버)이 {timeout}초 안에 응답하지 않음")
        return res

    def desktop_processes(self, sid: str) -> tuple[list[dict[str, Any]], set[int]]:
        """컨테이너의 프로세스 목록과, 보이는 창을 가진 pid (_NET_WM_PID)."""
        c = self._desktop(sid)
        res = c.exec_run(_timed(_X_TIMEOUT, "ps", "-eo", "pid=,ppid=,sid=,uid=,args="))
        if res.exit_code != 0:  # 빈 목록을 기준으로 삼으면 구간이 끝날 때 데스크톱 세션 전체를 낯선 프로세스로 본다
            raise SandboxError(f"프로세스 목록 실패 (exit {res.exit_code})")
        procs = _parse_ps(res.output or b"")
        res = self._x(c, ["sh", "-c", "for w in $(xdotool search --onlyvisible --name . 2>/dev/null); do "
                                      "xdotool getwindowpid $w 2>/dev/null; done"])
        wins = {int(x) for x in (res.output[0] or b"").split() if x.isdigit()}
        return procs, wins

    def kill_processes(self, sid: str, pids: list[int]) -> None:
        if pids:
            self._desktop(sid).exec_run(_timed(_X_TIMEOUT, "kill", "-KILL", "--", *map(str, pids)),
                                        user=DESKTOP_USER)

    def _wait_display(self, c, timeout: float = 45) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._x(c, ["xdotool", "getdisplaygeometry"]).exit_code == 0:
                return
            time.sleep(0.3)
        raise SandboxError("데스크톱(X 서버)이 시작되지 않음")

    def geometry(self, sid: str) -> tuple[int, int]:
        res = self._x(self._desktop(sid), ["xdotool", "getdisplaygeometry"])
        if res.exit_code != 0:
            raise SandboxError("화면 크기를 알 수 없음 (데스크톱이 떠 있지 않음)")
        w, h = (res.output[0] or b"0 0").split()[:2]
        return int(w), int(h)

    def screenshot(self, sid: str) -> dict[str, Any]:
        c = self._desktop(sid)
        res = self._x(c, ["sh", "-c", f'mkdir -p "$(dirname {_SHOT})" && scrot -o -z {_SHOT} && cat {_SHOT}; '
                                      f'r=$?; rm -f {_SHOT}; exit $r'])
        png = res.output[0] or b""
        if res.exit_code != 0 or png[:8] != b"\x89PNG\r\n\x1a\n":
            raise SandboxError(_truncate(res.output[1]) or "스크린샷 실패")
        width, height = struct.unpack(">II", png[16:24])
        return {"png": png, "width": width, "height": height, "sha256": hashlib.sha256(png).hexdigest()}

    def click(self, sid: str, x: int, y: int, button: str = "left", double: bool = False) -> dict[str, Any]:
        c = self._desktop(sid)
        w, h = self.geometry(sid)
        x, y = int(x), int(y)
        if not (0 <= x < w and 0 <= y < h):
            raise SandboxError(f"화면 밖 좌표: ({x}, {y}), 화면 {w}x{h}")
        if button not in _BUTTONS:
            raise SandboxError("button은 left, middle, right 중 하나")
        argv = ["xdotool", "mousemove", str(x), str(y), "click"]
        if double:
            argv += ["--repeat", "2", "--delay", "80"]
        res = self._x(c, argv + [_BUTTONS[button]])
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "클릭 실패")
        return {"x": x, "y": y, "button": button, "double": bool(double)}

    def type_text(self, sid: str, text: str) -> dict[str, Any]:
        c = self._desktop(sid)
        if len(text) > 2000:
            raise SandboxError("한 번에 2000자까지 입력할 수 있음")
        # 글자마다 12ms를 쉬니 긴 글은 그만큼 더 기다린다 (2000자면 115초)
        res = self._x(c, ["xdotool", "type", "--clearmodifiers", "--delay", "12", "--", text],
                      timeout=_X_TIMEOUT + len(text) // 20)
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "입력 실패")
        return {"chars": len(text)}

    def key(self, sid: str, keys: str) -> dict[str, Any]:
        c = self._desktop(sid)
        names = keys.split()
        if not names or len(names) > 20 or not all(_KEY_RE.match(k) for k in names):
            raise SandboxError("keys는 xdotool 키 이름을 공백으로 나눈 것 (예: 'ctrl+s', 'Return', 'alt+F4')")
        res = self._x(c, ["xdotool", "key", "--clearmodifiers", "--"] + names)
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "키 입력 실패")
        return {"keys": names}

    def vnc_command(self, sid: str, view_only: bool) -> list[str]:
        """화면 연결 하나에 쓸 명령. 포트를 열지 않고 x11vnc가 표준 입출력으로 RFB를 말한다."""
        c = self._desktop(sid)
        argv = [self.settings.docker_cli, "exec", "-i", "-u", DESKTOP_USER]
        for k, v in DESKTOP_ENV.items():
            argv += ["-e", f"{k}={v}"]
        # 디스플레이는 DISPLAY 환경 변수로 넘긴다. socat 주소에서 ':'는 구분자라 '-display :0'을 못 쓴다.
        vnc = ["x11vnc", "-inetd", "-q", "-auth", DESKTOP_ENV["XAUTHORITY"],
               "-nopw", "-shared", "-norc", "-noshm", "-nosel", "-noxdamage"]
        if view_only:
            vnc.append("-viewonly")
        # x11vnc -inetd는 fd 0에 쓰기도 한다. docker exec의 표준 입력은 파이프라 쓰기가 실패하므로
        # socat EXEC(기본이 socketpair)로 감싼다. 인자에 공백·':'·','가 없어야 한다.
        return argv + [c.id, "socat", "-", "EXEC:" + " ".join(vnc)]

    def extract_novnc(self, dest: Path) -> bool:
        """noVNC 정적 파일을 데스크톱 이미지에서 꺼낸다. 인터넷 없이 설치하기 위해 따로 받지 않는다.
        인증 없는 정적 파일 요청에서 불리므로 꺼내기는 한 번에 하나만 하고, 실패하면 한동안 다시 하지 않는다.
        그러지 않으면 요청마다 docker create와 전체 tar 추출이 돈다 (보안 검수 run-4 F5)."""
        if (dest / "core" / "rfb.js").exists():
            return True
        with _NOVNC_LOCK:   # 동시 요청은 먼저 온 하나가 꺼내기를 끝낼 때까지 기다렸다가 그 결과를 본다
            if (dest / "core" / "rfb.js").exists():
                return True
            if time.monotonic() - getattr(self, "_novnc_failed_at", float("-inf")) < _NOVNC_RETRY:
                return False
            try:
                ok = self._extract_novnc(dest)
            except Exception:   # 망가진 아카이브 등. 500 대신 '없음'으로 답하고 잠시 뒤 다시 해 본다
                ok = False
            if not ok:
                self._novnc_failed_at = time.monotonic()
            return ok

    def _extract_novnc(self, dest: Path) -> bool:
        # 컨테이너 로그로 tar를 받으면 바이너리가 잘린다. 실행하지 않은 컨테이너에서 복사 API로 꺼낸다.
        try:
            c = self.client.containers.create(self.settings.desktop_image, ["true"], network_mode="none")
        except (ImageNotFound, APIError):
            return False
        try:
            stream, _ = c.get_archive("/usr/share/novnc")
            out = b"".join(stream)
        except (NotFound, APIError):
            return False
        finally:
            c.remove(force=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(out)) as tf:
            # 링크는 건너뛴다 (vnc_auto.html 같은 별칭뿐이고, 밖을 가리키는 링크를 풀지 않기 위해)
            members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
            tf.extractall(dest.parent, members=members, filter="data")
        if dest.name != "novnc":
            (dest.parent / "novnc").rename(dest)
        return (dest / "core" / "rfb.js").exists()
