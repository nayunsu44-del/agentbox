"""보안 검수 run-5 회귀 테스트. Docker 없이 돈다."""

import json
import time

import pytest

from agentbox.config import Settings
from agentbox.desktop import DesktopControl
from agentbox.policy import Policy, command_names
from agentbox.preview import NOTES_MAX, PREVIEW_CALLS_MAX, preview_command


def _counting():
    calls = []

    def expand(p):
        calls.append(("expand", p))
        return [p]

    def walk(p, n):
        calls.append(("walk", p))
        return [p]
    return calls, expand, walk


def test_preview_container_calls_are_bounded():
    """'rm -r d d d …' 한 번에 피연산자 수만큼 docker exec가 돌았다. 상한을 넘으면 계산하지 않고 알린다."""
    calls, expand, walk = _counting()
    out = preview_command("rm -r " + " ".join(f"d{i}" for i in range(500)), 200, expand, walk)
    assert len(calls) == PREVIEW_CALLS_MAX
    assert any("미리보기 상한" in n for n in out["notes"])
    calls, expand, walk = _counting()
    preview_command("rm -r " + " ".join(["d"] * 500), 200, expand, walk)
    assert calls == [("expand", "d"), ("walk", "d")]          # 같은 피연산자는 한 번만


def test_preview_notes_are_bounded():
    """알아보지 못한 조각마다 붙던 메모가 요청의 수십 배로 커졌다."""
    out = preview_command("x;" * 5000, 200, lambda p: [p], lambda p, n: [p])
    assert len(out["notes"]) == NOTES_MAX + 1
    assert "4950개" in out["notes"][-1]


def test_policy_parse_does_not_relex_every_token(monkeypatch):
    """구분자 토큰마다 shlex를 새로 만들어(깊이 한도까지 되풀이) 'x;x;…' 16KiB에 1초 가까이 걸렸다.
    다시 쪼개도 같은 토큰은 다시 렉싱하지 않는다. 숨은 명령은 계속 찾아야 한다."""
    import shlex as real_shlex

    from agentbox import policy
    made = []

    class Counting(real_shlex.shlex):
        def __init__(self, *a, **k):
            made.append(1)
            super().__init__(*a, **k)
    monkeypatch.setattr(policy.shlex, "shlex", Counting)
    for unit in ("x;", "x$ ", "$ "):
        made.clear()
        command_names(unit * 1000)
        assert len(made) <= 2, (unit, len(made))
    assert "rm" in command_names("bash -c 'x;rm y'")
    assert "rm" in command_names("echo `rm x`")
    assert "rm" in command_names("a$(rm z)")
    assert "curl" in command_names('sh -c "curl a"')
    # 공백 없이 따옴표·구분자로 숨긴 이름도 계속 찾는다 (다시 렉싱을 줄이며 놓치면 이름 기준 규칙이 뚫린다)
    assert "rm" in command_names("""sh -c 'x;r""m'""")
    assert "curl" in command_names("""sh -c 'a|c""url'""")
    assert "rm" in command_names("""sh -c 'a`r""m`'""")
    p = Policy.load(Settings().policy_path)
    assert p.decide("exec", {"command": "bash -c 'x;rm y'"}).rule_id == "rm-curl-needs-approval"


class _PreviewSandboxes:
    """도구는 실행하지 않고, 승인 미리보기만 돌려준다."""
    def __init__(self, home, preview):
        self.settings = Settings(home=home)
        self._preview = preview
        self.previews = 0

    def get(self, sid):
        return {"id": sid, "container_id": "c1", "status": "running"}

    def template_of(self, sid):
        return Settings().template("cli")

    def preview(self, sid, command):
        self.previews += 1
        return self._preview(self)


def _box(tmp_path, preview):
    from agentbox.approvals import ApprovalStore
    from agentbox.audit import AuditLog
    from agentbox.service import AgentBox
    db = tmp_path / "agentbox.db"
    sb = _PreviewSandboxes(tmp_path, preview)
    box = AgentBox(AuditLog(db), Policy({"default": "require_approval"}), sb, approvals=ApprovalStore(db),
                   desktop=DesktopControl(), approval_timeout=60)
    return box, sb


def test_long_tool_argument_is_refused_before_policy(tmp_path):
    """명령 길이에 비례하는 판단·미리보기를 하기 전에 막는다."""
    from agentbox.service import TOOL_ARG_MAX, ServiceError
    box, sb = _box(tmp_path, lambda s: {"command": "", "affected": [], "notes": []})
    with pytest.raises(ServiceError) as e:
        box.call_tool("sb", "exec", {"command": "x;" * TOOL_ARG_MAX}, actor="agent")
    assert e.value.status == 413
    with pytest.raises(ServiceError) as e:   # 목록에 넣어도 정책은 str()로 읽는다
        box.call_tool("sb", "exec", {"command": ["x;" * TOOL_ARG_MAX]}, actor="agent")
    assert e.value.status == 413
    assert sb.previews == 0
    assert [r["event"] for r in box.audit.list()] == ["tool_blocked", "tool_blocked"]
    out = box.call_tool("sb", "exec", {"command": "echo " + "a" * (TOOL_ARG_MAX - 5)}, actor="agent")
    assert out.status == 202                                     # 상한까지는 받는다
    box.bursts._burst_pool.shutdown()


def test_pending_approval_row_is_bounded(tmp_path):
    """보안 검수 run-5: 승인 대기 행에 미리보기가 그대로 들어가 요청 하나가 수 MB가 됐다."""
    huge = {"command": "c", "affected": [{"path": "p" * 1000, "effect": "삭제"}] * 200,
            "notes": ["n" * 2000] * 400}
    box, _ = _box(tmp_path, lambda s: huge)
    out = box.call_tool("sb", "exec", {"command": "rm a"}, actor="agent")
    assert out.status == 202
    row = box.approvals.conn.execute("SELECT preview FROM approvals").fetchone()[0]
    assert len(row.encode()) <= 160 * 1024
    assert json.loads(row)
    box.bursts._burst_pool.shutdown()


def test_disk_is_rechecked_before_pending_row(tmp_path):
    """호출을 받을 때는 여유가 있었어도, 행을 쓰기 직전에 부족하면 승인 요청을 만들지 않는다."""
    from agentbox.service import ServiceError

    def preview(sb):
        sb.settings.min_free_bytes = 1 << 62                    # 미리보기 동안 디스크가 찼다
        return {"command": "c", "affected": [], "notes": []}
    box, _ = _box(tmp_path, preview)
    with pytest.raises(ServiceError) as e:
        box.call_tool("sb", "exec", {"command": "rm a"}, actor="agent")
    assert e.value.status == 507
    assert box.approvals.list() == []
    box.bursts._burst_pool.shutdown()


from conftest import FakeAudit as _Audit, build_fake_app as _fake_app


def test_unauthenticated_body_is_refused_before_reading(tmp_path, monkeypatch):
    """보안 검수 run-5 N1: 토큰 없는 요청도 본문(최대 8MiB)을 다 읽고 JSON을 해석한 뒤에 401이 나서, 요청 하나가
    약 200MB를 썼고 512MiB 제한에서는 동시 4건에 서버가 죽었다. 본문을 읽기 전에 자격 증명을 확인한다."""
    from fastapi.testclient import TestClient

    from agentbox import api
    from agentbox import desktop as D
    app, box, human = _fake_app(tmp_path, monkeypatch)
    decoded = []
    real = api.json.loads
    monkeypatch.setattr(api.json, "loads", lambda *a, **k: decoded.append(1) or real(*a, **k))
    body = b'{"args":{"a":[' + b",".join([b"{}"] * 300_000) + b"]}}"
    with TestClient(app) as c:
        for headers in ({}, {"Authorization": "Bearer junk"}, {"cookie": f"{D.COOKIE}=nope"}):
            r = c.post("/sandboxes/sb_x/tools/exec", content=body,
                       headers={"content-type": "application/json", **headers})
            assert r.status_code == 401, headers
        assert decoded == []
        r = c.post("/login", data={"token": "x" * (70 * 1024)})
        assert r.status_code == 413                                    # 로그인 폼은 작게
        r = c.post("/approvals/apr_none", json={"decision": "approve"}, headers={"Authorization": f"Bearer {human}"})
        assert r.status_code == 404                                    # 사람 토큰은 그대로 라우트까지 간다
        assert decoded
        cookie, _ = box.desktop.new_session("*")
        r = c.post("/ui/approvals/apr_none/approve", data={"x": "1"}, headers={"cookie": f"{D.COOKIE}={cookie}"})
        assert r.status_code != 401                                    # 로그인 세션도 통과


def test_desktop_ws_does_not_block_event_loop_on_sqlite(tmp_path, monkeypatch):
    """보안 검수 run-5: 화면 웹소켓이 이벤트 루프에서 SQLite·감사 기록을 기다려, DB 쓰기 잠금이 잡혀 있으면
    연결 하나에 서버 전체(/healthz 포함)가 수 초 멈췄다."""
    import sqlite3
    import threading

    from fastapi.testclient import TestClient

    from agentbox import desktop as D

    app, box, _ = _fake_app(tmp_path, monkeypatch)
    cookie, _ = box.desktop.new_session("sb_x")
    held, release = threading.Event(), threading.Event()

    def hold_write_lock():   # 다른 연결이 쓰기 잠금을 쥔다 (정리 명령의 BEGIN IMMEDIATE처럼)
        c = sqlite3.connect(str(box.sandboxes.settings.db_path), isolation_level=None)
        c.execute("BEGIN IMMEDIATE")
        held.set()
        release.wait(10)
        c.execute("ROLLBACK")
        c.close()

    with TestClient(app) as client:
        t = threading.Thread(target=hold_write_lock)
        t.start()
        held.wait(5)

        def connect():
            try:
                with client.websocket_connect("/sandboxes/sb_x/desktop/ws?mode=view",
                                              headers={"cookie": f"{D.COOKIE}={cookie}"}) as ws:
                    ws.receive()
            except Exception:
                pass
        w = threading.Thread(target=connect)
        w.start()
        time.sleep(0.3)
        start = time.monotonic()
        assert client.get("/healthz").status_code == 200
        took = time.monotonic() - start
        release.set()
        t.join()
        w.join(15)
    assert took < 1.0, took


# ---- 인수 중에 열리는 GUI 구간 (보안 검수 run-5) -------------------------------------------------------------
_BASE = [{"pid": 1, "ppid": 0, "sid": 1, "uid": 0, "args": "tini"},
         {"pid": 100, "ppid": 1, "sid": 100, "uid": 1001, "args": "xfce4-session"},
         {"pid": 101, "ppid": 100, "sid": 100, "uid": 1001, "args": "xfce4-panel"}]
_HUMAN = [{"pid": 200, "ppid": 101, "sid": 100, "uid": 1001, "args": "xfce4-terminal"},
          {"pid": 201, "ppid": 200, "sid": 201, "uid": 1001, "args": "bash"},
          {"pid": 202, "ppid": 201, "sid": 201, "uid": 1001, "args": "python3 -m http.server"}]


class _GuiSb:
    def __init__(self, block=False):
        import threading
        self.settings = Settings()
        self.container_id = "c1"
        self.procs, self.windows = list(_BASE), {100, 101}
        self.manifest = {"a.txt": (1, "1", "1")}
        self.killed, self.snaps, self.clicks = [], [], []
        self.block, self.entered, self.go = block, threading.Event(), threading.Event()

    def get(self, sid):
        return {"id": sid, "container_id": self.container_id, "status": "running"}

    def template_of(self, sid):
        return Settings().template("desktop")

    def _desktop(self, sid):
        return None

    def desktop_processes(self, sid):
        return [dict(p) for p in self.procs], set(self.windows)

    def kill_processes(self, sid, pids):
        self.killed += list(pids)

    def workspace_manifest(self, sid):
        return dict(self.manifest), False

    def snapshot(self, sid, reason):
        self.snaps.append(reason)
        if self.block:
            self.entered.set()
            self.go.wait(10)       # 몇 초 걸리는 docker commit 자리
        return {"id": f"snap_{len(self.snaps)}", "image": "img"}

    def snapshot_count(self, sid):
        return len(self.snaps)

    def screenshot(self, sid):
        raise __import__("agentbox.sandbox", fromlist=["SandboxError"]).SandboxError("no screen")

    def click(self, sid, x, y, button, double):
        self.clicks.append((x, y))
        return {"clicked": [x, y]}

    def list_dir(self, sid, path):
        return {"path": path, "entries": []}


def _human_acts(sb):
    sb.procs += _HUMAN
    sb.windows |= {200}
    sb.manifest["human_notes.txt"] = (5, "2", "2")


def test_click_racing_takeover_opens_no_burst(tmp_path):
    """에이전트 클릭의 커밋 중에 사람이 인수하면, 커밋 뒤 구간을 열지 않는다. 열면 인수 중에 사람이 띄운 셸이
    나중에 구간이 닫힐 때 멈추고, 사람의 편집이 에이전트 변경으로 남았다."""
    import threading

    from agentbox.service import AgentBox
    sb = _GuiSb(block=True)
    box = AgentBox(_Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", box.call_tool("sb", "click", {"x": 1, "y": 1})))
    t.start()
    assert sb.entered.wait(5)                  # 에이전트가 스냅샷 판단을 지나 커밋 중
    box.takeover("sb", "hs_1")
    sb.go.set()
    t.join(5)
    assert out["r"].status == 423 and sb.clicks == []
    assert "sb" not in box.bursts._gui_burst
    _human_acts(sb)
    box.call_tool("sb", "list_dir", {"path": "/workspace"})   # 쉬는 구간을 닫는 호출
    box.bursts.close_idle(wait=5)
    assert sb.killed == []
    assert not [r for r in box.audit.rows if r["event"] == "gui_changes"]
    box.bursts._burst_pool.shutdown()


def test_gui_approval_decided_during_takeover_takes_no_snapshot(tmp_path):
    """인수 중에 GUI 입력 승인을 결정하면 스냅샷·구간 없이 실패로 끝난다."""
    from agentbox.approvals import ApprovalStore
    from agentbox.service import AgentBox
    sb = _GuiSb()
    box = AgentBox(_Audit(), Policy({"default": "allow", "rules": [{"id": "g", "tool": "click",
                                                                     "action": "require_approval"}]}),
                   sb, approvals=ApprovalStore(tmp_path / "a.db"), desktop=DesktopControl())
    box.takeover("sb", "hs_1")
    out = box.call_tool("sb", "click", {"x": 1, "y": 1})
    assert out.status == 202
    apr = box.decide(out.body["approval_id"], True, session="hs_1")
    assert apr["status"] == "failed"
    assert sb.snaps == [] and sb.clicks == []
    assert "sb" not in box.bursts._gui_burst
    box.bursts._burst_pool.shutdown()


# ---- 보안 검수 run-6 회귀 테스트 ----------------------------------------------------
def test_gui_burst_covers_rejects_replaced_container_and_restore_ends_burst():
    """보안 검수 run-6 F1: 복원 도중 옛 컨테이너에서 열린 GUI 구간은 컨테이너 ID가 바뀐 뒤 covers()가 거부하고,
    restore_sandbox가 끝날 때 bursts.end로 닫아 새 컨테이너의 첫 GUI 입력이 스냅샷을 건너뛰지 않게 한다."""
    from agentbox.service import AgentBox

    sb = _GuiSb()
    sb.restore = lambda sid, snap_id: (setattr(sb, "container_id", "c2") or {"id": sid, "container_id": "c2"})
    box = AgentBox(_Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    assert box.bursts.open("sb", "snap_0")
    assert box.bursts.covers("sb")
    sb.container_id = "c2"
    assert not box.bursts.covers("sb")
    # 복원 중 열린 옛 구간도 restore_sandbox 끝에서 닫힌다
    sb.container_id = "c1"
    box.bursts.open("sb", "snap_0")
    box.restore_sandbox("sb", "snap_0")
    assert "sb" not in box.bursts._gui_burst and box.bursts.needs_snapshot("sb")
    box.bursts._burst_pool.shutdown()


def test_audit_sandbox_index_and_batched_verify(tmp_path, monkeypatch):
    """보안 검수 run-6 F2: sandbox_id 조회는 복합 인덱스(idx_audit_sandbox_id)를 타고, verify()는 _VERIFY_BATCH씩
    끊어 _lock 밖에서 해시를 검사한다."""
    import sqlite3

    from agentbox.audit import AuditLog

    db = tmp_path / "audit.db"
    log = AuditLog(db)
    monkeypatch.setattr(AuditLog, "_VERIFY_BATCH", 5)
    for i in range(17):
        log.append(actor="agent", event="tool_call", sandbox_id=f"sb_{i % 3}", payload={"i": i})
    plan = log.conn.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM audit WHERE sandbox_id = ? ORDER BY id DESC LIMIT 10", ("sb_1",)
    ).fetchall()
    assert any("idx_audit_sandbox_id" in str(r) for r in plan)
    v = log.verify()
    assert v.ok and v.checked == 17
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER audit_no_update")
    raw.execute("UPDATE audit SET payload = '{\"i\":999}' WHERE id = 13")
    raw.commit()
    v2 = log.verify()
    assert not v2.ok and v2.broken_at == 13 and v2.checked == 12


def test_preview_warns_on_brace_and_tilde_expansion():
    """보안 검수 run-6 F3: 중괄호({a,b})나 틸드(~) 확장이 든 rm 명령은 주의 문구를 띄우고,
    펼쳐지지 않은 원문을 '현재 존재하지 않음'으로 단정하지 않는다."""
    from agentbox.preview import preview_command

    p = preview_command("rm {a,b}.txt ~/secret.txt", 200, lambda pat: [], lambda path, n: [path])
    assert any("중괄호·틸드" in n for n in p["notes"])
    effects = {item["path"]: item["effect"] for item in p["affected"]}
    assert "중괄호·틸드 확장" in effects["{a,b}.txt"]
    assert "중괄호·틸드 확장" in effects["~/secret.txt"]


def test_same_origin_rejects_http_origin_when_secure_cookie_active(tmp_path, monkeypatch):
    """보안 검수 run-6 N1: Secure 쿠키(HTTPS) 환경에서는 같은 호스트라도 평문 http:// Origin을 거부한다."""
    import hashlib
    from fastapi import HTTPException
    from starlette.requests import Request

    if not hasattr(hashlib, "pbkdf2_hmac"):
        monkeypatch.setattr(hashlib, "pbkdf2_hmac",
                            lambda name, pw, salt, iters: hashlib.sha256(pw + salt).digest(), raising=False)

    def req(scheme: str, origin: str) -> Request:
        return Request({
            "type": "http",
            "method": "POST",
            "scheme": scheme,
            "path": "/logout",
            "headers": [(b"host", b"box.example"), (b"origin", origin.encode())],
        })

    app, _, _ = _fake_app(tmp_path, monkeypatch)
    logout = next(r.endpoint for r in app.routes if getattr(r, "path", None) == "/logout")
    assert logout(req("http", "http://box.example")).status_code == 303
    with pytest.raises(HTTPException) as e:
        logout(req("https", "http://box.example"))
    assert e.value.status_code == 403
    assert logout(req("https", "https://box.example")).status_code == 303

    monkeypatch.setenv("AGENTBOX_SECURE_COOKIE", "1")
    app_sec, _, _ = _fake_app(tmp_path / "sec", monkeypatch)
    logout_sec = next(r.endpoint for r in app_sec.routes if getattr(r, "path", None) == "/logout")
    with pytest.raises(HTTPException) as e2:
        logout_sec(req("http", "http://box.example"))
    assert e2.value.status_code == 403
    assert logout_sec(req("http", "https://box.example")).status_code == 303


def test_container_readers_cap_output_and_timeout():
    """보안 검수 run-6 N2: list_dir·outbox_list·_expand·screenshot이 컨테이너 쪽 시간 제한과 바이트·개수 상한을 건다."""
    from docker.models.containers import ExecResult

    from agentbox.sandbox import SandboxError, SandboxManager

    class C:
        id = "c1"

        def __init__(self):
            self.argv = []

        def exec_run(self, argv, **kw):
            self.argv.append(argv)
            return ExecResult(0, (b"total 0\\n", b"") if kw.get("demux") else b"")

    c = C()
    sm = SandboxManager.__new__(SandboxManager)
    sm.client = None
    sm._require_running = sm._container = sm._desktop = lambda sid: c
    assert sm.list_dir("sb", "/workspace")["path"] == "/workspace"
    assert sm.outbox_list("sb") == []
    assert sm._expand(c, "*.txt", 50) == ["total 0\\n"]
    assert all(a[0] == "timeout" for a in c.argv) and len(c.argv) == 3
    assert "head -c" in c.argv[1][-1]
    assert 'head -z -n "$2"' in c.argv[2][6] and c.argv[2][-1] == "51"
    with pytest.raises(SandboxError):
        sm.screenshot("sb")
    assert "head -c" in c.argv[3][-1]


def test_disk_low_checks_docker_root_dir(tmp_path, monkeypatch):
    """보안 검수 run-6 N3: DB 파티션에 여유가 있어도 Docker 저장소(docker_root) 파티션이 부족하면 disk_low가 켜진다."""
    import shutil
    from collections import namedtuple

    from agentbox.service import AgentBox

    Usage = namedtuple("Usage", ["total", "used", "free"])
    sb = _GuiSb()
    sb.settings.min_free_bytes = 1000
    sb.settings.home = tmp_path / "home"
    sb.docker_root = tmp_path / "docker"
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda p: Usage(10000, 9500, 500) if p == sb.docker_root else Usage(10000, 1000, 9000),
    )
    box = AgentBox(_Audit(), Policy({"default": "allow"}), sb, approvals=None, desktop=DesktopControl())
    assert box.disk_low()
    box.bursts._burst_pool.shutdown()
