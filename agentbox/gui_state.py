"""GUI 구간 기록에 쓰는 순수 함수: /workspace 파일 목록(manifest)과 프로세스 목록(ps)을 해석하고 비교한다.

컨테이너를 부르지 않고 바이트·dict만 다루므로 도커 없이 테스트할 수 있다. 부르는 쪽은 sandbox.SandboxManager
(출력을 얻는 쪽)와 gui_bursts.GuiBursts(비교하는 쪽)다.
"""

from __future__ import annotations

from typing import Any

# 데스크톱 템플릿 (images/desktop/Dockerfile과 맞춘다)
DESKTOP_UID = 1001

_MANIFEST_CAP = 8 * 1024 * 1024


def _parse_manifest(raw: bytes) -> tuple[dict[str, tuple[int, str, str]], bool]:
    """`find -printf '%P\\0%s\\0%T@\\0%C@\\0'` 출력(앞 _MANIFEST_CAP 바이트)을 {경로: (크기, mtime, ctime)}으로.
    상한에서 잘렸으면 끝의 불완전한 레코드는 버리고 truncated를 돌려준다."""
    truncated = len(raw) >= _MANIFEST_CAP
    fields = raw.decode("utf-8", errors="replace").split("\0")[:-1]  # 끝의 NUL 없는 조각은 잘린 것
    out: dict[str, tuple[int, str, str]] = {}
    for i in range(0, len(fields) - 3, 4):
        path, size, mtime, ctime = fields[i:i + 4]
        try:
            out[path] = (int(size), mtime, ctime)
        except ValueError:
            continue
    return out, truncated


def diff_manifest(old: dict[str, tuple], new: dict[str, tuple]) -> dict[str, list[str]]:
    return {"added": sorted(new.keys() - old.keys()),
            "modified": sorted(k for k in new.keys() & old.keys() if new[k] != old[k]),
            "deleted": sorted(old.keys() - new.keys())}


def _parse_ps(raw: bytes) -> list[dict[str, Any]]:
    """`ps -eo pid=,ppid=,sid=,uid=,args=` 출력."""
    out = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        try:
            pid, ppid, sid, uid = (int(x) for x in parts[:4])
        except ValueError:
            continue
        out.append({"pid": pid, "ppid": ppid, "sid": sid, "uid": uid, "args": parts[4] if len(parts) > 4 else ""})
    return out


def _new_processes(procs: list[dict[str, Any]], window_pids: set[int],
                   baseline: set[int]) -> tuple[list[int], list[int]]:
    """구간 동안 새로 생긴 화면 계정 프로세스를 (멈출 것, 창이 있어 남길 것)으로 나눈다. gui_strays 참고."""
    by = {p["pid"]: p for p in procs}
    base_sids = {by[pid]["sid"] for pid in baseline if pid in by and by[pid]["uid"] == DESKTOP_UID}

    def ancestors(p: dict[str, Any]):
        seen = set()
        while p["ppid"] in by and p["ppid"] not in seen:
            seen.add(p["ppid"])
            p = by[p["ppid"]]
            yield p

    def exec_root(p: dict[str, Any]) -> bool:   # docker exec로 뜬 것은 부모 pid가 0이다 (PID 1도 0이라 뺀다)
        return p["ppid"] == 0 and p["pid"] != 1

    def from_exec(p: dict[str, Any]) -> bool:
        return exec_root(p) or any(exec_root(a) for a in ancestors(p))

    stray, kept = [], []
    for p in procs:
        if p["uid"] != DESKTOP_UID or p["pid"] in baseline or p["pid"] == 1 or from_exec(p):
            continue
        windowed = p["sid"] in base_sids and (p["pid"] in window_pids or any(
            a["pid"] in window_pids and a["pid"] not in baseline for a in ancestors(p)))
        (kept if windowed else stray).append(p["pid"])
    return sorted(stray), sorted(kept)


def gui_strays(procs: list[dict[str, Any]], window_pids: set[int], baseline: set[int]) -> list[int]:
    """GUI 구간이 끝날 때 멈출 화면 계정 프로세스. baseline은 구간이 시작될 때 있던 pid.
    window_pids는 X 서버가 확인한 창 주인 pid다 (창이 스스로 적는 _NET_WM_PID가 아니다).

    구간 동안 새로 생긴 화면 계정 프로세스 가운데
    - 구간 시작 때 없던 세션에 있는 것 (터미널 안의 셸과 거기서 띄운 일, nohup·setsid로 떼어 낸 일)
    - 같은 세션이라도 자신도, 새로 생긴 조상도 창이 없는 것 (파일 관리자 등에서 실행한 스크립트)
    은 멈춘다. 창이 있는 앱(편집기, 터미널 창)과 그 도우미, 구간 전부터 있던 것(데스크톱 세션, 사람이 연 것),
    컨트롤 플레인이 docker exec로 띄운 것(화면 보기 연결, GUI 도구)은 그대로 둔다.
    """
    return _new_processes(procs, window_pids, baseline)[0]


def gui_kept(procs: list[dict[str, Any]], window_pids: set[int], baseline: set[int]) -> list[int]:
    """구간 동안 새로 생긴 화면 계정 프로세스 가운데 창이 있어 남기는 것. 기록하고, 다음 구간에서도
    기준(baseline)으로 보지 않고 다시 판단한다 (보안 검수 run-4 N4)."""
    return _new_processes(procs, window_pids, baseline)[1]
