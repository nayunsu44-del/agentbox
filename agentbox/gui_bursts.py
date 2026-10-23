"""GUI 구간 기록: 에이전트의 GUI 입력이 시작되면 구간을 열고, 입력이 끊기거나 다른 일이 끼면 닫으면서
그 사이 /workspace에서 바뀐 파일과 남은 프로세스를 감사 로그에 남긴다.

GUI 입력은 터미널·파일 관리자 등으로 정책 밖에서 파일을 바꿀 수 있어서, 막는 대신 복구 지점(스냅샷)과 변경 기록을 남긴다.
인수·반환처럼 사람의 제어와 얽힌 부분은 service.AgentBox에 있다. 여기서는 service를 import하지 않고,
기록 함수와 "인수 대기 중인지" 콜백을 주입받는다.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import wait as wait_futures
from typing import Any

from .desktop import DesktopControl
from .sandbox import SandboxManager, diff_manifest, gui_strays


class GuiBursts:
    def __init__(self, sandboxes: SandboxManager, desktop: DesktopControl,
                 log: Callable[[str | None, str | None, str, dict[str, Any]], None],
                 takeover_pending: Callable[[str], str | None], lock: threading.Lock):
        self.sandboxes = sandboxes
        self.desktop = desktop
        self._log = log
        self._takeover_pending = takeover_pending
        self._lock = lock   # AgentBox._busy_lock과 같은 잠금. 닫는 중인 구간(_closing)과 닫기 잠금 목록을 지킨다
        # GUI 구간 스냅샷용 (time.monotonic). 서버를 다시 켜면 비어서 첫 GUI 입력 때 스냅샷을 뜬다.
        self._gui_input_at: dict[str, float] = {}
        self._gui_snap_at: dict[str, float] = {}
        # 열린 GUI 구간: 시작 스냅샷과 그때의 /workspace 파일 목록. 구간이 끝나면 바뀐 파일을 기록한다.
        self._gui_burst: dict[str, dict[str, Any]] = {}
        self._burst_locks: dict[str, threading.Lock] = {}
        # 입력이 끊긴 구간은 여기서 닫는다. 다른 샌드박스의 도구 스레드나 사람 요청 스레드에서 그 샌드박스의
        # docker exec를 돌리면, 그 컨테이너가 응답하지 않을 때 상관없는 호출이 묶인다 (보안 검수 run-3 v11).
        self._burst_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agentbox-burst")
        self._closing: dict[str, Future] = {}

    def mark_input(self, sid: str) -> None:
        self._gui_input_at[sid] = time.monotonic()

    def forget_input(self, sid: str) -> None:
        self._gui_input_at.pop(sid, None)

    def mark_snapshot(self, sid: str) -> None:
        self._gui_snap_at[sid] = time.monotonic()

    def needs_snapshot(self, sid: str) -> bool:
        """GUI 입력은 터미널·파일 관리자 등으로 정책 밖에서 /workspace를 바꿀 수 있다. 막을 수는 없으니
        AP-2의 복구 지점만이라도 남긴다: GUI 구간이 시작될 때와, 구간이 길면 interval마다."""
        s = self.sandboxes.settings
        if s.gui_snapshot_interval <= 0:
            return False
        if (self.desktop.lease(sid) and not self.desktop.is_stale(sid)) or self._takeover_pending(sid):
            return False  # 사람이 조작 중이라 어차피 423
        now = time.monotonic()
        last_input, last_snap = self._gui_input_at.get(sid), self._gui_snap_at.get(sid)
        return (last_input is None or now - last_input > s.gui_snapshot_idle
                or last_snap is None or now - last_snap > s.gui_snapshot_interval)

    def open(self, sid: str, snapshot_id: str) -> bool:
        try:
            # 구간은 지금 컨테이너의 것이다. 복원으로 컨테이너가 바뀌면 옛 pid·파일 목록으로 새 데스크톱을 판단하지 않는다
            container_id = self.sandboxes.get(sid)["container_id"]
            manifest, truncated = self.sandboxes.workspace_manifest(sid)
            procs, _ = self.sandboxes.desktop_processes(sid)
        except Exception as e:  # 기록용이라 실패해도 도구 호출은 막지 않는다. 다만 구간 기록이 없다는 것은 남긴다
            self._log(sid, None, "gui_burst_open_failed", {"snapshot_id": snapshot_id,
                                                           "error": (str(e) or type(e).__name__)[:300]})
            return False
        self._gui_burst[sid] = {"snapshot_id": snapshot_id, "manifest": manifest, "truncated": truncated,
                                "pids": {p["pid"] for p in procs}, "container_id": container_id}
        return True

    def _stop_strays(self, sid: str, burst: dict[str, Any], reason: str) -> str | None:
        """구간에서 GUI로 띄운 백그라운드 일을 멈춘다. 그대로 두면 구간이 끝난 뒤에도 정책 밖에서 파일을 바꾼다.
        멈추지 못했으면 그 까닭을 돌려준다."""
        try:
            procs, wins = self.sandboxes.desktop_processes(sid)
            pids = gui_strays(procs, wins, burst["pids"])
            self.sandboxes.kill_processes(sid, pids)
        except Exception as e:
            return str(e) or type(e).__name__
        if pids:
            args = {p["pid"]: p["args"][:200] for p in procs}
            self._log(sid, None, "gui_processes_stopped", {
                "snapshot_id": burst["snapshot_id"], "reason": reason,
                "processes": [{"pid": pid, "args": args.get(pid, "")} for pid in pids[:50]], "count": len(pids)})
        return None

    def close_failed(self, sid: str, burst: dict[str, Any], reason: str, error: str) -> None:
        """조용히 버리지 않는다: 사람이 그 구간 시작 스냅샷을 보고 판단할 수 있게 남긴다."""
        self._log(sid, None, "gui_burst_close_failed",
                  {"snapshot_id": burst["snapshot_id"], "reason": reason, "error": error[:300]})

    def close(self, sid: str, reason: str, only: dict[str, Any] | None = None) -> None:
        """GUI 구간 동안 /workspace에서 바뀐 파일을 감사 로그에 남긴다. 정책 밖에서 바뀐 것을 사람이 보고,
        필요하면 구간 시작 스냅샷으로 되돌릴 수 있게. 같은 샌드박스의 닫기는 하나씩 한다: 되돌리기 전에 닫을 때
        백그라운드 닫기가 아직 돌고 있으면 그것이 끝날 때까지 기다린다. only를 주면 그 구간일 때만 닫는다."""
        with self._lock:
            lock = self._burst_locks.setdefault(sid, threading.Lock())
        with lock:
            burst = self._gui_burst.get(sid)
            if not burst or (only is not None and burst is not only):
                return
            del self._gui_burst[sid]
            self._finish(sid, burst, reason)

    def _finish(self, sid: str, burst: dict[str, Any], reason: str) -> None:
        try:
            replaced = self.sandboxes.get(sid)["container_id"] != burst.get("container_id")
        except Exception as e:
            return self.close_failed(sid, burst, reason, str(e))
        if replaced:
            return self.close_failed(sid, burst, reason, "컨테이너가 바뀌어 비교하지 않음 (복원)")
        failed = self._stop_strays(sid, burst, reason)
        try:
            manifest, truncated = self.sandboxes.workspace_manifest(sid)
        except Exception as e:
            return self.close_failed(sid, burst, reason, failed or str(e))
        if failed:
            self.close_failed(sid, burst, reason, failed)
        diff = diff_manifest(burst["manifest"], manifest)
        if not any(diff.values()):
            return
        self._log(sid, None, "gui_changes", {
            "snapshot_id": burst["snapshot_id"], "reason": reason,
            "counts": {k: len(v) for k, v in diff.items()},
            **{k: v[:100] for k, v in diff.items()},
            "truncated": burst["truncated"] or truncated or any(len(v) > 100 for v in diff.values()),
        })

    def close_idle(self, wait: float = 0) -> None:
        """입력이 끊긴 GUI 구간을 닫는다. 조회·도구 호출 때 부른다 (승인 기한 처리와 같은 방식).
        닫기는 전용 스레드에서 돈다. wait초까지는 끝나기를 기다린다 (감사 로그 조회가 방금 닫힌 구간을 보이게)."""
        idle = self.sandboxes.settings.gui_snapshot_idle
        now = time.monotonic()
        with self._lock:
            for sid, burst in list(self._gui_burst.items()):
                if now - self._gui_input_at.get(sid, 0.0) > idle and sid not in self._closing:
                    self._closing[sid] = self._burst_pool.submit(self._close_idle, sid, burst)
            pending = list(self._closing.values())
        if wait > 0 and pending:
            wait_futures(pending, timeout=wait)

    def _close_idle(self, sid: str, burst: dict[str, Any]) -> None:
        try:
            self.close(sid, "idle", only=burst)  # 그새 다음 구간이 열렸으면 그것은 두고 간다
        finally:
            with self._lock:
                self._closing.pop(sid, None)

    def end(self, sid: str, reason: str) -> None:
        """컨테이너가 멈추거나 바뀌기 전에 열린 구간을 닫고, 다음 GUI 입력이 새 구간(스냅샷)을 열게 한다.
        일시정지·재개·복원·삭제 때 부른다. 그러지 않으면 바로 뒤의 GUI 입력이 스냅샷도 구간도 없이 돈다
        (보안 검수 run-3 v12)."""
        self.close(sid, reason)
        self.reset_timers(sid)

    def reset_timers(self, sid: str) -> None:
        self._gui_input_at.pop(sid, None)
        self._gui_snap_at.pop(sid, None)

    def shutdown(self) -> None:
        self._burst_pool.shutdown(wait=False, cancel_futures=True)
