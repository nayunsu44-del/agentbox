"""도구 호출의 흐름: 기록 → 판정 → (승인 대기 | 실행) → 기록.

규칙: 감사 기록이 실패하면 실행하지 않는다 (AU-2).
승인된 위험 명령은 실행 직전에 스냅샷을 만든다 (AP-2). 파일 삭제·덮어쓰기는 승인 없이 허용돼도 스냅샷을 먼저 뜬다.
승인 요청은 approval_timeout초(기본 300) 안에 결정이 없으면 거부로 끝난다 (AP-1).
사람이 화면을 인수한 동안 GUI 도구는 실행하지 않고 423을 돌려준다 (UX-2).
승인 요청에는 시스템이 직접 찍은 화면 캡처를 붙인다 (UX-5, 데스크톱 템플릿만).
사람이 넣고(UX-3) 받는(UX-4) 파일은 sha256과 함께 기록한 뒤에 옮긴다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import approvals as A
from .approvals import ApprovalStore
from .audit import AuditLog, AuditWriteError, bound_payload
from .desktop import DesktopControl, Lease
from .gui_bursts import GuiBursts
from .policy import ALLOW, DENY, REQUIRE_APPROVAL, Decision, Policy
from .sandbox import WORKSPACE, SandboxError, SandboxManager, clean_name, safe_path

FILE_TOOLS = {"list_dir", "read_file", "exec", "write_file", "delete_file"}
GUI_TOOLS = {"screenshot", "click", "type", "key"}
GUI_INPUT = GUI_TOOLS - {"screenshot"}
SNAPSHOT_TOOLS = {"write_file", "delete_file"} | GUI_INPUT   # 허용 경로에서 스냅샷을 뜰 수 있는 도구
TOOLS = FILE_TOOLS | GUI_TOOLS
LOGGED_ARGS_MAX = 64 * 1024    # 감사 로그에 원문 그대로 남기는 도구 인자 크기 (JSON 바이트)
LOGGED_ARGS_HEAD = 16 * 1024   # 넘으면 남기는 앞부분
# 인수·반환이 실행 중인 GUI 도구를 기다리는 최대 시간(초). 넘으면 503으로 돌려주고 사람이 다시 누른다.
# 기다리는 동안과 그 뒤 한동안은 에이전트의 GUI 도구를 새로 돌리지 않아, 다시 누르면 잡을 수 있다.
GUI_LOCK_WAIT = 30
AUDIT_BURST_WAIT = 5   # 감사 로그 조회가 방금 닫기 시작한 구간 기록을 기다리는 최대 시간(초)
# 샌드박스 하나가 동시에 걸어 둘 수 있는 승인 요청 수. 요청마다 화면 캡처 PNG가 호스트에 남는다 (보안 검수 run-3 v18).
PENDING_APPROVALS_MAX = 20


_NO_SESSION: Any = ...   # "session을 넘기지 않음". None(세션 없는 사람 토큰)과 다르다


def _with_session(payload: dict[str, Any], session: str | None) -> dict[str, Any]:
    return payload if session is _NO_SESSION else {**payload, "session": session}


@dataclass
class ToolOutcome:
    status: int          # HTTP 상태: 200 실행됨, 202 승인 대기, 403 차단, 423 사람이 화면 조작 중
    body: dict[str, Any]


class ServiceError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class HumanControl(Exception):
    def __init__(self, lease: Lease):
        super().__init__(f"사람이 화면을 조작 중 ({lease.session}, {lease.since}부터)")
        self.lease = lease


class AgentBox:
    def __init__(self, audit: AuditLog, policy: Policy, sandboxes: SandboxManager, approvals: ApprovalStore,
                 desktop: DesktopControl | None = None, approval_timeout: int = 300,
                 captures: Path | None = None):
        self.audit = audit
        self.policy = policy
        self.sandboxes = sandboxes
        self.approvals = approvals
        self.desktop = desktop or DesktopControl()
        self.approval_timeout = approval_timeout
        self.captures = captures
        self._busy: dict[str, int] = {}
        self._snap_locks: dict[str, threading.Lock] = {}
        # 일시정지·재개·스냅샷·복원·삭제는 샌드박스마다 하나씩. 겹치면 복원이 막 지운 행을 되살리고
        # 삭제가 폐기한 에이전트 토큰을 다시 살린다 (보안 검수 run-4 F6)
        self._life_locks: dict[str, threading.Lock] = {}
        # 인수를 기다리는 중: sid -> (세션, 이때까지 에이전트 GUI 도구를 새로 돌리지 않음)
        self._takeover_wanted: dict[str, tuple[str, float]] = {}
        self._busy_lock = threading.Lock()
        self._low_disk = False   # 지난번 disk_low() 판단. 바뀔 때만 기록한다
        self.bursts = GuiBursts(sandboxes, self.desktop, self.log_best_effort, self._takeover_pending, self._busy_lock)

    def capture_path(self, aid: str) -> Path | None:
        if not self.captures or not aid.replace("_", "").isalnum():
            return None
        p = self.captures / f"{aid}.png"
        return p if p.is_file() else None

    def _drop_capture(self, aid: str) -> None:
        """캡처는 사람이 결정할 때 보는 것이다. 결정·만료·삭제되면 지운다 (감사 로그에는 sha256이 남는다)."""
        p = self.capture_path(aid)
        if p:
            try:
                p.unlink()
            except OSError:
                pass

    def drop_captures(self, sid: str) -> None:
        """샌드박스를 지울 때 그 샌드박스의 승인 캡처를 모두 지운다."""
        for apr in self.approvals.list(sandbox_id=sid):
            self._drop_capture(apr["id"])

    def _capture(self, sid: str) -> tuple[bytes, dict[str, Any]] | None:
        """승인 요청 시점의 화면. 실패해도 승인 요청은 그대로 낸다."""
        if not self.captures or not self.sandboxes.template_of(sid).desktop:
            return None
        try:
            shot = self.sandboxes.screenshot(sid)
        except SandboxError:
            return None
        png = shot.pop("png")
        return png, shot

    # ---- 내부 -----------------------------------------------------------
    def _run_tool(self, sid: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        sb = self.sandboxes
        if tool == "exec":
            return sb.exec(sid, str(args.get("command", "")))
        if tool == "list_dir":
            return sb.list_dir(sid, str(args.get("path", "/workspace")))
        if tool == "read_file":
            return sb.read_file(sid, str(args.get("path", "")))
        if tool == "write_file":
            return sb.write_file(sid, str(args.get("path", "")), str(args.get("content", "")))
        if tool == "delete_file":
            return sb.delete_file(sid, str(args.get("path", "")))
        if tool in GUI_TOOLS:
            with self.desktop.gui_lock(sid):
                self._check_control(sid)
                if tool in GUI_INPUT:
                    if not self.bursts.covers(sid):
                        # 잠금을 기다리는 사이 사람이 인수했다가 돌려줘 구간이 닫혔다. 스냅샷·기록 없이 실행하지 않는다.
                        # 입력 시각을 남기지 않으니 다시 부르면 새 스냅샷과 구간을 연다 (보안 검수 run-4 F2)
                        raise SandboxError("기다리는 동안 화면 제어가 바뀌어 GUI 구간이 닫혔음. 이 입력은 실행하지 않음. "
                                           "다시 호출할 것")
                    self.bursts.mark_input(sid)
                if tool == "screenshot":
                    shot = sb.screenshot(sid)
                    png = shot.pop("png")
                    return {**shot, "bytes": len(png), "png_base64": base64.b64encode(png).decode()}
                if tool == "click":
                    return sb.click(sid, _int(args, "x"), _int(args, "y"), str(args.get("button", "left")),
                                    bool(args.get("double", False)))
                if tool == "type":
                    return sb.type_text(sid, str(args.get("text", "")))
                return sb.key(sid, str(args.get("keys", "")))
        raise ServiceError(404, f"알 수 없는 도구: {tool}")

    def _check_control(self, sid: str) -> None:
        """gui_lock을 잡은 채로 부른다."""
        if self.desktop.is_stale(sid):
            self._handback_locked(sid, None, "idle_timeout")
        lease = self.desktop.lease(sid)
        if lease:
            raise HumanControl(lease)
        wanted = self._takeover_pending(sid)
        if wanted:
            raise HumanControl(Lease(sid, wanted))

    def _takeover_pending(self, sid: str) -> str | None:
        """인수를 기다리는 세션. 그동안 에이전트가 GUI 도구를 이어 불러 gui_lock을 계속 차지하지 못하게 한다."""
        with self._busy_lock:
            got = self._takeover_wanted.get(sid)
        return got[0] if got and got[1] > time.monotonic() else None

    @contextmanager
    def _gui_locked(self, sid: str, what: str):
        lock = self.desktop.gui_lock(sid)
        if not lock.acquire(timeout=GUI_LOCK_WAIT):
            raise ServiceError(503, f"에이전트의 GUI 도구가 {GUI_LOCK_WAIT}초 안에 끝나지 않아 {what}하지 못함. "
                                    "다시 시도할 것")
        try:
            yield
        finally:
            lock.release()

    @staticmethod
    def _logged_args(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """감사 로그에는 쓸 파일 내용 대신 크기와 해시를 남긴다. 나머지 인자도 LOGGED_ARGS_MAX를 넘으면
        앞부분과 크기·해시만 남긴다. 감사 로그는 지울 수 없어서, 에이전트가 큰 인자로 키우면 되돌릴 수 없다."""
        if tool == "write_file" and "content" in args:
            data = str(args.get("content", "")).encode("utf-8")
            args = {k: v for k, v in args.items() if k != "content"} | {
                "content_bytes": len(data), "content_sha256": hashlib.sha256(data).hexdigest()}
        blob = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        if len(blob) <= LOGGED_ARGS_MAX:
            return args
        kept = {k: args[k] for k in ("content_bytes", "content_sha256") if k in args}
        return kept | {"args_truncated": True, "args_bytes": len(blob),
                       "args_sha256": hashlib.sha256(blob).hexdigest(),
                       "args_head": blob[:LOGGED_ARGS_HEAD].decode("utf-8", errors="replace")}

    @staticmethod
    def _summary(tool: str, result: dict[str, Any]) -> dict[str, Any]:
        """감사 로그에는 결과 전체 대신 요약을 남긴다 (파일 내용이 로그로 새지 않게)."""
        if tool == "exec":
            return {k: result.get(k) for k in ("exit_code", "timed_out")} | {
                "stdout_head": (result.get("stdout") or "")[:500],
                "stderr_head": (result.get("stderr") or "")[:500],
            }
        if tool == "read_file":
            return {"path": result.get("path"), "bytes": len(result.get("content") or ""),
                    "truncated": result.get("truncated")}
        if tool == "screenshot":
            return {k: result.get(k) for k in ("width", "height", "bytes", "sha256")}
        if tool in ("write_file", "delete_file", "list_dir"):
            return {k: v for k, v in result.items() if k in ("path", "bytes", "sha256", "deleted")}
        return result

    def _preview(self, sid: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "exec":
            return self.sandboxes.preview(sid, str(args.get("command", "")))
        if tool in ("delete_file", "write_file"):
            p = safe_path(str(args.get("path", "")))
            exists = self.sandboxes.exists(sid, p)
            notes = []
            if tool == "delete_file":
                effect = "삭제" if exists else "삭제 시도 (현재 존재하지 않음)"
            else:
                effect = "덮어쓰기" if exists else "새 파일 만들기"
                la = self._logged_args(tool, args)
                notes.append(f"쓸 내용 {la['content_bytes']} bytes, sha256 {la['content_sha256'][:16]}…")
            return {"tool": tool, "cwd": WORKSPACE, "affected": [{"path": p, "effect": effect}], "notes": notes}
        return {"tool": tool, "cwd": WORKSPACE, "affected": [],
                "notes": ["시스템이 영향을 계산하지 못함. 도구 인자 원문을 확인할 것."]}

    def _needs_snapshot(self, sid: str, tool: str, args: dict[str, Any]) -> bool:
        """AP-2: 삭제·덮어쓰기는 승인 여부와 상관없이 직전에 스냅샷."""
        if tool == "delete_file":
            return True
        if tool == "write_file":
            try:
                return self.sandboxes.exists(sid, str(args.get("path", "")))
            except SandboxError:
                return False
        if tool in GUI_INPUT:
            return self.bursts.needs_snapshot(sid)
        return False

    def _over_snapshot_quota(self, sid: str, tool: str, args: dict[str, Any]) -> bool:
        """허용 규칙이 매번 docker commit을 일으켜 호스트 디스크를 채우지 못하게, 상한부터는 승인으로 돌린다."""
        quota = self.sandboxes.settings.snapshot_quota
        if quota <= 0 or self.sandboxes.snapshot_count(sid) < quota:
            return False
        return self._needs_snapshot(sid, tool, args)

    def _snapshot(self, sid: str, tool: str, reason: str, ref: dict[str, Any]) -> dict[str, Any]:
        if tool in GUI_INPUT:
            self.bursts.close(sid, "next_burst")
        snap = self.sandboxes.snapshot(sid, reason=reason)
        opened = True
        if tool in GUI_INPUT:
            self.bursts.mark_snapshot(sid)
            opened = self.bursts.open(sid, snap["id"])
        self.audit.append(actor="system", event="snapshot", sandbox_id=sid, tool=tool,
                          payload={**ref, "snapshot_id": snap["id"], "image": snap["image"]})
        if not opened:
            # 기준 없이 구간을 돌리면 그 동안 GUI로 바꾼 것이 기록되지 않는다. 에이전트가 pid 한도를 채워 일부러
            # 이 상태를 만들 수 있으니 이 입력은 실행하지 않고, 다음 입력이 다시 구간을 열게 한다 (보안 검수 run-3 v09)
            self.bursts.reset_timers(sid)
            raise SandboxError("GUI 구간 기준(파일·프로세스 목록)을 읽지 못해 GUI 입력을 실행하지 않음. 잠시 뒤 다시 호출할 것")
        return snap

    # ---- 도구 호출 --------------------------------------------------------
    def call_tool(self, sid: str, tool: str, args: dict[str, Any], actor: str = "agent") -> ToolOutcome:
        """샌드박스 하나가 동시에 돌리는 도구 호출 수를 제한한다. 출력 없는 허용 명령(tail -f 등)을
        여러 개 띄워 도구 실행 스레드를 제한 시간 내내 붙잡지 못하게 한다."""
        if actor == "agent" and self.disk_low():
            raise ServiceError(507, "컨트롤 플레인 디스크의 남은 공간이 부족해 도구 호출을 받지 않음. "
                                    "사람이 공간을 확보한 뒤 다시 호출할 것.")
        self.bursts.close_idle()
        limit = self.sandboxes.settings.tool_concurrency
        with self._busy_lock:
            if limit > 0 and self._busy.get(sid, 0) >= limit:
                raise ServiceError(429, f"이 샌드박스의 도구 호출이 이미 {limit}개 실행 중. 끝난 뒤 다시 호출할 것.")
            self._busy[sid] = self._busy.get(sid, 0) + 1
        try:
            if tool in SNAPSHOT_TOOLS:
                # 스냅샷 상한 확인부터 스냅샷 생성까지 한 번에 하나씩. 아니면 동시 호출이 모두 상한 확인을
                # 통과한 뒤 각자 스냅샷을 떠 상한을 넘는다 (GUI 구간 판단도 같다).
                with self._busy_lock:
                    lock = self._snap_locks.setdefault(sid, threading.Lock())
                with lock:
                    return self._call_tool(sid, tool, args, actor)
            return self._call_tool(sid, tool, args, actor)
        finally:
            with self._busy_lock:
                self._busy[sid] -= 1

    def _call_tool(self, sid: str, tool: str, args: dict[str, Any], actor: str) -> ToolOutcome:
        if tool not in TOOLS:
            raise ServiceError(404, f"알 수 없는 도구: {tool}")
        self.sandboxes.get(sid)  # 없으면 SandboxError
        try:
            req_id = self.audit.append(actor=actor, event="tool_request", sandbox_id=sid, tool=tool,
                                       payload={"args": self._logged_args(tool, args)})
            decision = self.policy.decide(tool, args)
            if decision.action == ALLOW and self._over_snapshot_quota(sid, tool, args):
                quota = self.sandboxes.settings.snapshot_quota
                decision = Decision(REQUIRE_APPROVAL, "snapshot-quota",
                                    f"스냅샷이 {quota}개 이상 쌓여 덮어쓰기·삭제마다 사람의 승인을 받음",
                                    decision.matched)
            self.audit.append(actor="system", event="policy_decision", sandbox_id=sid, tool=tool,
                              payload={"request": req_id, **decision.as_dict()})
        except AuditWriteError as e:
            raise ServiceError(503, f"{e}. 기록할 수 없어서 실행하지 않음.") from e

        if decision.action == DENY:
            return ToolOutcome(403, {"status": "denied", "rule_id": decision.rule_id, "reason": decision.reason})

        if decision.action == REQUIRE_APPROVAL:
            if len(self.approvals.list(status=A.PENDING, sandbox_id=sid)) >= PENDING_APPROVALS_MAX:
                self.log_best_effort(sid, tool, "tool_blocked", {"request": req_id, "reason": "too_many_pending_approvals",
                                                                 "limit": PENDING_APPROVALS_MAX})
                raise ServiceError(429, f"이 샌드박스의 승인 대기가 이미 {PENDING_APPROVALS_MAX}개. "
                                        "사람이 결정하거나 기한이 지난 뒤 다시 호출할 것.")
            try:
                preview = self._preview(sid, tool, args)
            except Exception as e:  # 미리보기가 실패해도 승인은 사람에게 넘긴다
                preview = {"command": args.get("command"), "affected": [], "notes": [f"미리보기 실패: {e}"]}
            cap = self._capture(sid)
            if cap:
                preview["capture"] = cap[1]
            apr = self.approvals.create(sandbox_id=sid, tool=tool, args=args, rule_id=decision.rule_id,
                                        rule_reason=decision.reason, preview=preview)
            if cap:
                self.captures.mkdir(parents=True, exist_ok=True)  # type: ignore[union-attr]
                (self.captures / f"{apr['id']}.png").write_bytes(cap[0])  # type: ignore[operator]
            try:
                self.audit.append(actor="system", event="approval_requested", sandbox_id=sid, tool=tool,
                                  payload={"request": req_id, "approval_id": apr["id"],
                                           "preview": {k: v for k, v in preview.items() if k != "capture"},
                                           "capture": preview.get("capture"), "expires_in": self.approval_timeout})
            except AuditWriteError as e:
                self.approvals.claim(apr["id"], A.FAILED, "system")
                self._drop_capture(apr["id"])
                raise ServiceError(503, f"{e}. 기록할 수 없어서 승인 요청을 취소함.") from e
            return ToolOutcome(202, {"status": "pending", "approval_id": apr["id"],
                                     "expires_in": self.approval_timeout,
                                     "message": "사람의 승인을 기다리는 중. GET /approvals/{id}로 결과를 확인."})

        assert decision.action == ALLOW
        if self._needs_snapshot(sid, tool, args):
            quota = self.sandboxes.settings.snapshot_quota
            if quota > 0 and self.sandboxes.snapshot_count(sid) >= quota:
                # 상한 확인 때는 스냅샷이 필요 없었는데 그 사이 대상이 생겼다(예: 같이 보낸 touch). 상한을 넘겨
                # 승인 없이 커밋하지 않는다. 다시 부르면 상한 확인에서 승인 요청으로 간다 (보안 검수 run-4 F7)
                self.log_best_effort(sid, tool, "tool_blocked", {"request": req_id, "reason": "snapshot_quota_changed",
                                                                 "quota": quota})
                raise ServiceError(409, f"스냅샷이 {quota}개 이상이라 사람의 승인이 필요해졌음. 실행하지 않음. "
                                        "다시 호출하면 승인 요청으로 처리됨")
            try:
                self._snapshot(sid, tool, f"before {tool} (request {req_id})", {"request": req_id})
            except (SandboxError, AuditWriteError, Exception) as e:
                self.log_best_effort(sid, tool, "tool_error", {"request": req_id, "error": f"스냅샷 실패: {e}"})
                raise ServiceError(503, f"스냅샷 또는 기록 실패, 실행하지 않음: {e}") from e
        try:
            result = self._run_tool(sid, tool, args)
        except HumanControl as h:
            try:
                self.audit.append(actor="system", event="tool_blocked", sandbox_id=sid, tool=tool,
                                  payload={"request": req_id, "reason": "human_control", "session": h.lease.session})
            except AuditWriteError as e:
                raise ServiceError(503, f"{e}. 기록할 수 없어서 실행하지 않음.") from e
            return ToolOutcome(423, {"status": "human_control", "since": h.lease.since,
                                     "message": "사람이 화면을 조작 중이라 GUI 도구를 실행하지 않았다. "
                                                "돌려받은 뒤 다시 호출할 것 (GET /sandboxes/{id}/desktop/state)."})
        except SandboxError as e:
            self.log_best_effort(sid, tool, "tool_error", {"request": req_id, "error": str(e)})
            raise ServiceError(400, str(e)) from e
        self.log_best_effort(sid, tool, "tool_result", {"request": req_id, **self._summary(tool, result)})
        return ToolOutcome(200, {"status": "executed", "result": result})

    def disk_low(self) -> bool:
        """DB가 있는 디스크의 남은 공간이 min_free_bytes보다 적은지. 에이전트가 늘리는 기록(도구 호출, 승인 시도)은
        이때 받지 않아서, 남은 공간을 사람의 삭제·승인·반환이 쓴다 (보안 검수 run-4 N2). 상태가 바뀔 때만 기록한다."""
        s = self.sandboxes.settings
        if s.min_free_bytes <= 0:
            return False
        try:
            free = shutil.disk_usage(s.db_path.parent).free
        except OSError:
            return False
        low = free < s.min_free_bytes
        with self._busy_lock:
            changed, self._low_disk = low != self._low_disk, low
        if changed:
            self.log_best_effort(None, None, "disk_low" if low else "disk_ok",
                                 {"free_bytes": free, "min_free_bytes": s.min_free_bytes})
        return low

    def _finish(self, apr: dict[str, Any], status: str, result: dict[str, Any], snapshot_id: str | None = None) -> None:
        """끝난 승인은 원본 인자를 다시 쓰지 않는다. 감사 로그와 같은 모양(크기·해시·앞부분)으로 줄여서,
        에이전트가 큰 인자로 키운 승인 행이 그대로 쌓이지 않게 한다 (보안 검수 run-4 N2)."""
        self.approvals.finish(apr["id"], status, result, snapshot_id=snapshot_id,
                              args=self._logged_args(apr["tool"], apr["args"]),
                              preview=bound_payload(apr["preview"]))

    def log_best_effort(self, sid: str | None, tool: str | None, event: str, payload: dict[str, Any],
                        actor: str = "system") -> None:
        try:
            self.audit.append(actor=actor, event=event, sandbox_id=sid, tool=tool, payload=payload)
        except AuditWriteError:
            # 이미 실행이 끝난 뒤라 되돌릴 수 없다. 다음 호출은 요청 기록 단계에서 막힌다.
            pass

    # ---- 승인 결정 --------------------------------------------------------
    def expire_stale(self) -> None:
        """AP-1: 기한이 지난 대기 요청을 거부로 끝낸다. 조회·결정 때마다 부른다."""
        self.bursts.close_idle()
        limit = datetime.now(timezone.utc) - timedelta(seconds=self.approval_timeout)
        for apr in self.approvals.list(status=A.PENDING):
            if datetime.fromisoformat(apr["created_at"]) > limit:
                continue
            try:
                if not self.approvals.claim(apr["id"], A.EXPIRED, "system"):
                    continue
                self._drop_capture(apr["id"])
                self._finish(apr, A.EXPIRED, {
                    "message": f"{self.approval_timeout}초 안에 결정이 없어 거부함. 실행하지 않음."})
            except sqlite3.Error:
                return   # 디스크가 차 있으면 다음 조회 때 다시 한다. 조회 자체는 막지 않는다
            self.log_best_effort(apr["sandbox_id"], apr["tool"], "approval_expired",
                                 {"approval_id": apr["id"], "timeout_s": self.approval_timeout})

    def decide(self, aid: str, approve: bool, actor: str = "human", session: str | None = None) -> dict[str, Any]:
        self.expire_stale()
        apr = self.approvals.get(aid)
        if not apr:
            raise ServiceError(404, f"승인 요청 없음: {aid}")
        decision = A.APPROVED if approve else A.DENIED
        try:
            claimed = self.approvals.claim(aid, decision, actor)
        except sqlite3.Error as e:
            raise ServiceError(503, f"승인 기록 실패: {e}. 결정하지 않음.") from e
        if not claimed:
            raise ServiceError(409, f"이미 결정된 요청: {aid} ({apr['status']})")
        self._drop_capture(aid)
        sid, tool, args = apr["sandbox_id"], apr["tool"], apr["args"]
        try:
            self.audit.append(actor=actor, event="approval_decision", sandbox_id=sid, tool=tool,
                              payload={"approval_id": aid, "decision": decision, "session": session})
        except AuditWriteError as e:
            self._finish(apr, A.FAILED, {"error": str(e)})
            raise ServiceError(503, f"{e}. 기록할 수 없어서 실행하지 않음.") from e

        if not approve:
            self._finish(apr, A.DENIED, {"message": "사람이 거절함. 실행하지 않음."})
            return self.approvals.get(aid)  # type: ignore[return-value]

        # AP-2: 실행 직전 스냅샷
        try:
            snap = self._snapshot(sid, tool, f"before {aid}", {"approval_id": aid})
            self.audit.append(actor="system", event="tool_execute", sandbox_id=sid, tool=tool,
                              payload={"approval_id": aid, "args": self._logged_args(tool, args)})
        except (SandboxError, AuditWriteError, Exception) as e:
            self._finish(apr, A.FAILED, {"error": f"스냅샷 또는 기록 실패, 실행하지 않음: {e}"})
            self.log_best_effort(sid, tool, "tool_error", {"approval_id": aid, "error": str(e)})
            raise ServiceError(503, f"스냅샷 또는 기록 실패, 실행하지 않음: {e}") from e

        try:
            result = self._run_tool(sid, tool, args)
        except (SandboxError, HumanControl) as e:
            self._finish(apr, A.FAILED, {"error": str(e)}, snapshot_id=snap["id"])
            self.log_best_effort(sid, tool, "tool_error", {"approval_id": aid, "error": str(e)})
            return self.approvals.get(aid)  # type: ignore[return-value]
        self._finish(apr, A.EXECUTED, result, snapshot_id=snap["id"])
        self.log_best_effort(sid, tool, "tool_result", {"approval_id": aid, **self._summary(tool, result)})
        return self.approvals.get(aid)  # type: ignore[return-value]

    # ---- 샌드박스 생성 (SB-1) --------------------------------------------
    def create_sandbox(self, source_dir: str | None, template: str,
                       session: str | None = None) -> tuple[dict[str, Any], str]:
        self.log_human("sandbox_create_request", None, {"source_dir": source_dir, "template": template,
                                                        "session": session})
        rec, token = self.sandboxes.create(source_dir, template)
        self.audit.register_secret(token)
        self.log_human("sandbox_created", rec["id"], {"source_dir": rec["source_dir"], "runtime": rec["runtime"],
                                                      "image": rec["image"], "template": rec["template"],
                                                      "session": session})
        return rec, token

    # ---- 샌드박스 일시정지·재개·스냅샷·복원·삭제 -----------------------------
    # session을 넘기지 않으면(JSON API) 기록에 session 항목을 넣지 않고, 넘기면(웹 UI) None이어도 넣는다.
    @contextmanager
    def _lifecycle(self, sid: str):
        with self._busy_lock:
            lock = self._life_locks.setdefault(sid, threading.Lock())
        with lock:
            yield

    def pause_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle(sid):
            self.log_human("sandbox_pause", sid, _with_session({}, session))
            self.bursts.end(sid, "sandbox_paused")  # 멈춘 컨테이너에서는 구간을 닫지 못한다
            self.sandboxes.pause(sid)
            return self.sandboxes.get(sid)

    def resume_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle(sid):
            self.log_human("sandbox_resume", sid, _with_session({}, session))
            self.sandboxes.resume(sid)
            self.bursts.reset_timers(sid)  # 멈춘 동안의 GUI 호출이 남긴 시각 때문에 다음 구간을 건너뛰지 않게
            return self.sandboxes.get(sid)

    def snapshot_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle(sid):
            self.log_human("snapshot_request", sid, _with_session({}, session))
            snap = self.sandboxes.snapshot(sid, reason="manual")
            self.log_human("snapshot", sid, _with_session({"snapshot_id": snap["id"], "image": snap["image"]},
                                                          session))
            return snap

    def restore_sandbox(self, sid: str, snap_id: str, session: str | None = _NO_SESSION) -> dict[str, Any]:
        with self._lifecycle(sid):
            self.log_human("restore_request", sid, _with_session({"snapshot_id": snap_id}, session))
            self.end_desktop(sid, "sandbox_restored")
            rec = self.sandboxes.restore(sid, snap_id)
            self.bursts.reset_timers(sid)  # 바꾸는 사이에 들어온 GUI 입력도 새 컨테이너에서 새 구간을 열게
            self.log_human("restored", sid, _with_session({"snapshot_id": snap_id,
                                                           "container_id": rec["container_id"]}, session))
            return rec

    def delete_sandbox(self, sid: str, session: str | None = _NO_SESSION) -> None:
        with self._lifecycle(sid):
            self.log_human("sandbox_delete", sid, _with_session({}, session))
            self.end_desktop(sid, "sandbox_deleted")
            self.sandboxes.delete(sid)
            self.drop_captures(sid)

    # ---- 파일 넣기·받기 (UX-3, UX-4) ---------------------------------------
    def import_file(self, sid: str, name: str, data: bytes, session: str | None = None) -> dict[str, Any]:
        name = clean_name(name)
        meta = {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "session": session}
        self.log_human("file_import_request", sid, meta)
        path = f"{WORKSPACE}/{name}"
        if self.sandboxes.is_dir(sid, path):
            raise ServiceError(409, f"같은 이름의 폴더가 있음: {name}")
        if self.sandboxes.exists(sid, path):  # AP-2: 사람이 덮어써도 먼저 스냅샷
            try:
                self._snapshot(sid, None, f"before import {name}", {"name": name})  # type: ignore[arg-type]
            except (SandboxError, AuditWriteError, Exception) as e:
                raise ServiceError(503, f"스냅샷 또는 기록 실패, 넣지 않음: {e}") from e
        res = self.sandboxes.upload(sid, name, data)
        self.log_best_effort(sid, None, "file_imported", {**meta, "path": res["path"]}, actor="human")
        return res

    def export_file(self, sid: str, name: str, session: str | None = None) -> bytes:
        name = clean_name(name)
        data = self.sandboxes.outbox_read(sid, name)
        # 반출은 기록한 뒤에 내보낸다. 기록을 못 하면 내보내지 않는다.
        self.log_human("file_exported", sid, {"name": name, "bytes": len(data),
                                              "sha256": hashlib.sha256(data).hexdigest(), "session": session})
        return data

    # ---- 화면 인수·반환 (UX-2) -------------------------------------------
    def takeover(self, sid: str, session: str) -> dict[str, Any]:
        self.sandboxes._desktop(sid)  # 데스크톱이 아니면 SandboxError
        with self._busy_lock:
            if sid not in self._takeover_wanted or self._takeover_wanted[sid][0] == session:
                self._takeover_wanted[sid] = (session, time.monotonic() + 2 * GUI_LOCK_WAIT)
        with self._gui_locked(sid, "인수"):  # 실행 중인 GUI 도구가 끝날 때까지 기다린다 (시간 초과면 표시는 남긴다)
            try:
                cur = self.desktop.lease(sid)
                if cur and cur.session != session:
                    raise ServiceError(409, f"다른 사람 세션({cur.session})이 이미 조작 중")
                if not cur:
                    self.bursts.close(sid, "human_takeover")  # 사람이 바꾸는 것은 에이전트 구간에 넣지 않는다
                    self.log_human("human_takeover", sid, {"session": session})  # 기록 못 하면 인수하지 않는다
                    self.desktop.take(sid, session)
            finally:
                with self._busy_lock:
                    if self._takeover_wanted.get(sid, ("",))[0] == session:
                        del self._takeover_wanted[sid]
        return self.desktop.state(sid, session)

    def handback(self, sid: str, session: str | None, reason: str = "handback") -> dict[str, Any]:
        with self._gui_locked(sid, "반환"):
            self._handback_locked(sid, session, reason)
        return self.desktop.state(sid, session)

    def _handback_locked(self, sid: str, session: str | None, reason: str) -> None:
        lease = self.desktop.lease(sid)
        if not lease:
            return
        if session is not None and lease.session != session:
            raise ServiceError(409, f"다른 사람 세션({lease.session})이 조작 중. 그 세션만 돌려줄 수 있음")
        payload = {"session": lease.session, "reason": reason,
                   "seconds": round(time.monotonic() - lease.started, 1), "client_bytes": lease.client_bytes}
        try:
            self.audit.append(actor="human" if reason == "handback" else "system", event="human_handback",
                              sandbox_id=sid, payload=payload)
        except AuditWriteError as e:
            # 기록 없이 에이전트에게 화면을 넘기지 않는다.
            raise ServiceError(503, f"{e}. 기록할 수 없어서 돌려주지 않음.") from e
        self.desktop.release(sid)
        self.bursts.forget_input(sid)  # 사람이 바꾼 상태까지 담도록 에이전트의 다음 GUI 입력 때 스냅샷

    def close(self) -> None:
        """DB 연결과 Docker 클라이언트를 닫는다 (서버 종료, 테스트)."""
        self.bursts.shutdown()
        for close in (self.audit.conn.close, self.approvals.conn.close, self.sandboxes.conn.close,
                      self.sandboxes.client.close, self.desktop.close):
            try:
                close()
            except Exception:
                pass

    def recover_takeovers(self) -> int:
        """서버를 켤 때: 지난 실행에서 돌려주지 않은 인수를 server_restart로 기록하고 정리한다.
        감사 로그에 human_takeover만 있고 짝이 없는 일이 없게 한다. 기록을 못 하면 서버를 띄우지 않는다."""
        n = 0
        for row in self.desktop.leftover_leases():
            payload = {"session": row["session"], "reason": "server_restart",
                       "seconds": round(max(0.0, time.time() - row["started"]), 1), "client_bytes": None}
            self.audit.append(actor="system", event="human_handback", sandbox_id=row["sandbox_id"], payload=payload)
            self.desktop.forget_lease(row["sandbox_id"])
            n += 1
        return n

    def end_ui_session(self, cookie: str | None) -> str | None:
        """로그아웃: 세션을 지우고, 그 세션이 인수한 화면은 돌려주고, 열린 화면 연결을 끊는다."""
        session = self.desktop.end_session(cookie)
        if session:
            for sid in self.desktop.leases_of(session):
                try:
                    self.handback(sid, session, "logout")
                except ServiceError:
                    pass
            self.desktop.close_session(session)
        return session

    def end_desktop(self, sid: str, reason: str) -> None:
        """삭제·복원 때: 인수 상태를 기록하고 정리, 열린 화면 연결을 끊는다."""
        self.bursts.end(sid, reason)  # 되돌리거나 지우기 전에, 그때까지 바뀐 것을 남긴다
        if self.desktop.lease(sid):
            try:
                self.handback(sid, None, reason)
            except ServiceError:
                pass
        self.desktop.close_all(sid)

    # ---- 사람이 하는 샌드박스 조작도 기록한다 ----------------------------
    def log_human(self, event: str, sid: str | None, payload: dict[str, Any]) -> None:
        try:
            self.audit.append(actor="human", event=event, sandbox_id=sid, payload=payload)
        except AuditWriteError as e:
            raise ServiceError(503, f"{e}. 기록할 수 없어서 실행하지 않음.") from e


def _int(args: dict[str, Any], key: str) -> int:
    try:
        return int(args[key])
    except (KeyError, TypeError, ValueError) as e:
        raise SandboxError(f"{key}는 정수여야 함") from e
