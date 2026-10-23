"""M2 단위 테스트 (Docker 없이): 화면 세션·인수 상태, 기본 정책, 감사 로그에 파일 내용이 안 남는 것."""

import threading
import time

import pytest

from agentbox.config import Settings
from agentbox.desktop import DesktopControl
from agentbox.policy import Policy
from agentbox.service import AgentBox


def test_ticket_is_one_time_and_bound_to_sandbox():
    d = DesktopControl()
    t = d.issue_ticket("sb_a")
    assert d.redeem(t, "sb_b") is None          # 다른 샌드박스로는 못 쓴다 (그리고 소진된다)
    t = d.issue_ticket("sb_a")
    cookie, public = d.redeem(t, "sb_a")
    assert d.session(cookie, "sb_a") == public and public.startswith("hs_")
    assert d.session(cookie) is None and d.session(cookie, "sb_b") is None   # 웹 UI 전체·다른 샌드박스는 안 됨
    assert d.redeem(t, "sb_a") is None          # 두 번째는 실패


def test_ticket_expires():
    d = DesktopControl(ticket_ttl=0.05)
    t = d.issue_ticket("sb_a")
    time.sleep(0.1)
    assert d.redeem(t, "sb_a") is None


def test_takeover_is_exclusive_and_release_closes_control_conns():
    d = DesktopControl()
    d.take("sb", "hs_1")
    with pytest.raises(PermissionError):
        d.take("sb", "hs_2")
    assert d.may_connect("sb", "hs_1", "control")
    assert not d.may_connect("sb", "hs_2", "control")
    assert d.may_connect("sb", "hs_2", "view")
    closed = []
    d.add_conn("sb", "hs_1", "control", lambda: closed.append("control"))
    d.add_conn("sb", "hs_2", "view", lambda: closed.append("view"))
    d.release("sb")
    assert closed == ["control"]                # 보기 연결은 그대로 둔다
    assert d.state("sb")["controller"] == "agent"


def test_stale_lease_only_without_control_connection():
    d = DesktopControl(idle=0.05)
    d.take("sb", "hs_1")
    conn = d.add_conn("sb", "hs_1", "control", lambda: None)
    time.sleep(0.1)
    assert not d.is_stale("sb")                 # 입력 연결이 살아 있으면 인수 유지
    d.drop_conn(conn)
    time.sleep(0.1)
    assert d.is_stale("sb")


def test_default_policy_delete_needs_approval():
    p = Policy.load(Settings().policy_path)
    assert p.decide("delete_file", {"path": "/workspace/a"}).action == "require_approval"
    assert p.decide("write_file", {"path": "/workspace/a", "content": "x"}).action == "allow"
    assert p.decide("exec", {"command": "rm a"}).action == "require_approval"
    assert p.decide("screenshot", {}).action == "allow"


def test_large_tool_args_are_capped_in_audit():
    # run-3 v08: 에이전트가 아무 도구 인자에 큰 값을 넣으면 지울 수 없는 감사 행이 그 크기로 남았다.
    import json
    from agentbox.service import LOGGED_ARGS_HEAD, LOGGED_ARGS_MAX
    junk = "A" * (3 * 1024 * 1024)
    la = AgentBox._logged_args("read_file", {"path": "/workspace/x", "junk": junk})
    assert la["args_truncated"] and la["args_bytes"] > len(junk) and len(la["args_sha256"]) == 64
    assert len(json.dumps(la).encode()) < LOGGED_ARGS_HEAD + 1024
    la = AgentBox._logged_args("write_file", {"path": "a", "content": "x", "junk": junk})
    assert la["content_bytes"] == 1 and la["args_truncated"]       # 승인 미리보기가 쓰는 키는 남는다
    small = {"command": "ls -la " + "a" * 100}
    assert AgentBox._logged_args("exec", small) == small
    edge = {"command": "a" * (LOGGED_ARGS_MAX - 20)}
    assert len(json.dumps(edge).encode()) <= LOGGED_ARGS_MAX and AgentBox._logged_args("exec", edge) == edge


def test_write_file_content_not_logged():
    la = AgentBox._logged_args("write_file", {"path": "a.md", "content": "비밀 내용"})
    assert "content" not in la and la["content_bytes"] == len("비밀 내용".encode()) and len(la["content_sha256"]) == 64


# ---- run-3 v11·v10: 응답 없는 화면이 다른 호출과 사람의 인수를 붙잡지 않는다 ------------------
class _Audit:
    def __init__(self):
        self.rows = []

    def append(self, **row):
        self.rows.append(row)
        return len(self.rows)


class _Sandboxes:
    """닫을 구간의 파일 목록을 읽다가 멈추는 컨테이너 (X 서버나 컨테이너가 응답하지 않는 경우)."""
    def __init__(self):
        self.settings = Settings()
        self.release = threading.Event()
        self.threads = []
        self.container_id = "c1"
        self.procs = []
        self.killed = []

    def get(self, sid):
        return {"id": sid, "container_id": self.container_id, "status": "running"}

    def desktop_processes(self, sid):
        return self.procs, set()

    def kill_processes(self, sid, pids):
        self.killed += pids

    def workspace_manifest(self, sid):
        self.threads.append(threading.current_thread().name)
        self.release.wait(10)
        return {"new.txt": (1, "1", "1")}, False

    def _desktop(self, sid):
        return None


def _gui_box():
    sb = _Sandboxes()
    box = AgentBox(_Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    return box, sb


def _burst(box, sid):
    box._gui_burst[sid] = b = {"snapshot_id": "snap_1", "manifest": {}, "truncated": False, "pids": set(),
                               "container_id": "c1"}
    box._gui_input_at[sid] = time.monotonic() - 3600
    return b


def test_idle_burst_close_does_not_run_on_caller_thread():
    box, sb = _gui_box()
    _burst(box, "sb_b")
    t0 = time.monotonic()
    box.close_idle_gui_bursts()          # 다른 샌드박스의 도구 호출·승인 조회가 부르는 곳
    box.close_idle_gui_bursts()          # 닫는 중인 구간은 다시 넣지 않는다
    assert time.monotonic() - t0 < 1
    for _ in range(100):
        if sb.threads:
            break
        time.sleep(0.01)
    assert sb.threads == ["agentbox-burst_0"]
    t0 = time.monotonic()
    box.close_idle_gui_bursts(wait=0.2)  # 감사 로그 조회는 잠깐만 기다린다
    assert time.monotonic() - t0 < 1
    sb.release.set()
    box.close_idle_gui_bursts(wait=5)
    assert "sb_b" not in box._gui_burst and not box._closing
    assert [r["event"] for r in box.audit.rows] == ["gui_changes"]
    assert box.audit.rows[0]["payload"]["added"] == ["new.txt"]
    box._burst_pool.shutdown()


def test_idle_close_leaves_a_newer_burst_alone():
    box, sb = _gui_box()
    sb.release.set()
    old = _burst(box, "sb_b")
    new = _burst(box, "sb_b")             # 닫기가 돌기 전에 다음 구간이 열렸다
    box._close_gui_burst("sb_b", "idle", only=old)
    assert box._gui_burst["sb_b"] is new and not box.audit.rows
    box._burst_pool.shutdown()


def test_takeover_waits_bounded_and_stops_new_agent_gui_calls(monkeypatch):
    from agentbox import service
    from agentbox.service import HumanControl, ServiceError

    monkeypatch.setattr(service, "GUI_LOCK_WAIT", 0.3)
    box, _ = _gui_box()
    lock = box.desktop.gui_lock("sb")
    lock.acquire()                         # 에이전트의 GUI 도구가 응답 없는 화면에서 멈춰 있다
    t0 = time.monotonic()
    with pytest.raises(ServiceError) as e:
        box.takeover("sb", "hs_1")
    assert e.value.status == 503 and time.monotonic() - t0 < 2
    lock.release()
    # 인수를 기다리던 동안과 그 뒤 잠시는 에이전트가 GUI 도구를 새로 돌리지 못한다 (다시 누르면 잡힌다)
    with box.desktop.gui_lock("sb"):
        with pytest.raises(HumanControl):
            box._check_control("sb")
    with pytest.raises(HumanControl):
        box._check_control("sb")
    assert box.takeover("sb", "hs_1")["controller"] == "human"
    assert "sb" not in box._takeover_wanted
    lock.acquire()
    with pytest.raises(ServiceError) as e:
        box.handback("sb", "hs_1")
    assert e.value.status == 503
    lock.release()
    box.handback("sb", "hs_1")
    box._check_control("sb")               # 돌려준 뒤에는 에이전트 차례
    box._burst_pool.shutdown()


def test_gui_execs_have_a_container_side_deadline():
    from docker.models.containers import ExecResult

    from agentbox.sandbox import SandboxError, SandboxManager

    class C:
        def __init__(self, code):
            self.code, self.argv = code, []

        def exec_run(self, argv, **kw):
            self.argv.append(argv)
            return ExecResult(self.code, (b"", b"") if kw.get("demux") else b"")

    c = C(124)
    with pytest.raises(SandboxError, match="응답하지 않음"):
        SandboxManager._x(c, ["xdotool", "getdisplaygeometry"])
    assert c.argv[0][:3] == ["timeout", "-k", "2"] and c.argv[0][4:] == ["xdotool", "getdisplaygeometry"]
    sm = SandboxManager.__new__(SandboxManager)
    sm._container = sm._desktop = lambda sid: c
    c.argv.clear()
    with pytest.raises(SandboxError):
        sm.workspace_manifest("sb")       # 잘린 목록으로 비교하지 않는다
    with pytest.raises(SandboxError):
        sm.desktop_processes("sb")
    sm.kill_processes("sb", [42])
    assert all(a[0] == "timeout" for a in c.argv) and len(c.argv) == 3


# ---- run-3 v12: GUI 구간 상태가 컨테이너의 일시정지·복원을 따라간다 -----------------------
def test_lifecycle_change_resets_gui_burst_timers():
    box, sb = _gui_box()
    sb.release.set()
    _burst(box, "sb")
    box._gui_input_at["sb"] = box._gui_snap_at["sb"] = time.monotonic()   # 막 GUI 입력이 있었다
    assert not box._gui_needs_snapshot("sb")
    box.end_gui_burst("sb", "sandbox_paused")
    assert "sb" not in box._gui_burst and box._gui_needs_snapshot("sb")   # 다음 입력이 새 구간을 연다
    assert [r["event"] for r in box.audit.rows] == ["gui_changes"]
    box._gui_input_at["sb"] = box._gui_snap_at["sb"] = time.monotonic()
    box.reset_gui_timers("sb")                                           # 재개·복원 뒤
    assert box._gui_needs_snapshot("sb")
    box._burst_pool.shutdown()


def test_burst_from_replaced_container_kills_nothing():
    from agentbox.sandbox import DESKTOP_UID

    box, sb = _gui_box()
    sb.release.set()
    _burst(box, "sb")                     # 복원 직전에 열린 구간 (옛 컨테이너의 pid가 기준)
    sb.container_id = "c2"
    sb.procs = [{"pid": 50, "ppid": 1, "sid": 50, "uid": DESKTOP_UID, "args": "xfce4-panel"}]
    box._close_gui_burst("sb", "idle")
    assert sb.killed == [] and [r["event"] for r in box.audit.rows] == ["gui_burst_close_failed"]
    box._burst_pool.shutdown()


def test_failed_burst_close_is_logged_not_dropped_silently():
    box, sb = _gui_box()

    def broken(sid):
        raise RuntimeError("일시정지된 샌드박스")

    sb.workspace_manifest = sb.desktop_processes = broken
    _burst(box, "sb")
    box._close_gui_burst("sb", "idle")
    rows = box.audit.rows
    assert [r["event"] for r in rows] == ["gui_burst_close_failed"] and "일시정지" in rows[0]["payload"]["error"]
    box._burst_pool.shutdown()


def test_failed_burst_baseline_is_logged():
    # run-3 v09: 기준(파일 목록·프로세스)을 못 읽으면 빈 기준으로 구간을 열지 않고, 못 열었다고 남긴다
    box, sb = _gui_box()

    def broken(sid):
        raise RuntimeError("/workspace 파일 목록 실패 (exit 126)")

    sb.workspace_manifest = broken
    box._open_gui_burst("sb", "snap_9")
    assert "sb" not in box._gui_burst
    assert [(r["event"], r["payload"]["snapshot_id"]) for r in box.audit.rows] == [("gui_burst_open_failed", "snap_9")]
    box._burst_pool.shutdown()
