"""M2 수용 테스트: 파일 도구·승인 기한·사전 스냅샷, 데스크톱(화면 보기·인수, GUI 도구). 실제 Docker가 필요하다.

데스크톱 테스트는 agentbox-desktop 이미지가 있어야 돈다 (images/desktop/Dockerfile).
"""

import base64
import sqlite3
import time

import pytest

docker = pytest.importorskip("docker")
try:
    _dc = docker.from_env()
    _dc.ping()
except Exception:  # pragma: no cover
    pytest.skip("Docker 데몬이 없음", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from agentbox.config import Settings  # noqa: E402
from agentbox.desktop import COOKIE  # noqa: E402


def _has_image(name: str) -> bool:
    try:
        _dc.images.get(name)
        return True
    except Exception:
        return False


needs_desktop = pytest.mark.skipif(not _has_image(Settings().desktop_image), reason="데스크톱 이미지가 없음")


class E:
    pass


def _make(tmp_path, monkeypatch, template):
    monkeypatch.setenv("AGENTBOX_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("AGENTBOX_HUMAN_TOKEN", raising=False)
    src = tmp_path / "reports"
    src.mkdir()
    (src / "old-report.md").write_text("# 오래된 보고서\n매출 10억\n")
    (src / "new-report.md").write_text("# 새 보고서\n매출 12억\n")
    from agentbox.api import build

    app, box, human = build()
    client = TestClient(app)
    H = {"Authorization": f"Bearer {human}"}
    r = client.post("/sandboxes", json={"source_dir": str(src), "template": template}, headers=H)
    assert r.status_code == 201, r.text
    sb = r.json()
    e = E()
    e.c, e.H, e.A, e.sid, e.box = client, H, {"Authorization": f"Bearer {sb['agent_token']}"}, sb["id"], box
    e.db = tmp_path / "data" / "agentbox.db"
    return e


@pytest.fixture()
def env(tmp_path, monkeypatch):
    e = _make(tmp_path, monkeypatch, "cli")
    yield e
    e.c.delete(f"/sandboxes/{e.sid}", headers=e.H)


@pytest.fixture()
def desk(tmp_path, monkeypatch):
    e = _make(tmp_path, monkeypatch, "desktop")
    yield e
    e.c.delete(f"/sandboxes/{e.sid}", headers=e.H)


def tool(e, name, who="A", **args):
    return e.c.post(f"/sandboxes/{e.sid}/tools/{name}", json={"args": args}, headers=getattr(e, who))


def events(e):
    return e.c.get("/audit", params={"sandbox_id": e.sid}, headers=e.H).json()


def ls(e):
    return tool(e, "exec", command="ls /workspace").json()["result"]["stdout"].split()


# ---- TL-1 파일 도구, AP-2 사전 스냅샷 --------------------------------------
def test_write_and_read_file(env):
    e = env
    r = tool(e, "write_file", path="nodir/summary.md", content="x")
    assert r.status_code == 400  # 없는 폴더는 만들어 주지 않는다
    r = tool(e, "write_file", path="outbox/summary.md", content="# 요약\n한글 OK\n")  # 결과함은 처음부터 있다
    assert r.status_code == 200, r.text
    assert tool(e, "read_file", path="/workspace/outbox/summary.md").json()["result"]["content"] == "# 요약\n한글 OK\n"
    ev = events(e)
    req = [x for x in ev if x["event"] == "tool_request" and x["tool"] == "write_file"][-1]
    assert "content" not in req["payload"]["args"] and req["payload"]["args"]["content_sha256"]
    assert not [x for x in ev if x["event"] == "snapshot"], "새 파일은 스냅샷이 필요 없다"


def test_write_file_large_crosses_chunks(env):
    e = env
    body = ("가나다라마바사 " * 20000)[:150000]
    assert tool(e, "write_file", path="big.txt", content=body).status_code == 200
    out = tool(e, "exec", command="wc -c < big.txt").json()["result"]["stdout"].strip()
    assert int(out) == len(body.encode())


def test_overwrite_takes_snapshot_first(env):
    e = env
    r = tool(e, "write_file", path="old-report.md", content="덮어씀")
    assert r.status_code == 200
    ev = events(e)
    snap = next(x for x in ev if x["event"] == "snapshot")
    res = next(x for x in ev if x["event"] == "tool_result" and x["tool"] == "write_file")
    assert snap["id"] < res["id"]
    e.c.post(f"/sandboxes/{e.sid}/restore", json={"snapshot_id": snap["payload"]["snapshot_id"]}, headers=e.H)
    assert tool(e, "read_file", path="old-report.md").json()["result"]["content"].startswith("# 오래된")


def test_write_outside_workspace_refused(env):
    for p in ("/source/old-report.md", "/etc/passwd", "../x", "/workspace"):
        assert tool(env, "write_file", path=p, content="x").status_code == 400, p


def test_delete_file_needs_approval_snapshot_and_restore(env):
    e = env
    r = tool(e, "delete_file", path="old-report.md")
    assert r.status_code == 202
    aid = r.json()["approval_id"]
    assert "old-report.md" in ls(e)
    apr = e.c.get(f"/approvals/{aid}", headers=e.H).json()
    assert apr["preview"]["affected"] == [{"path": "/workspace/old-report.md", "effect": "삭제"}]
    res = e.c.post(f"/approvals/{aid}", json={"decision": "approve"}, headers=e.H).json()
    assert res["status"] == "executed" and res["snapshot_id"]
    assert "old-report.md" not in ls(e)
    e.c.post(f"/sandboxes/{e.sid}/restore", json={"snapshot_id": res["snapshot_id"]}, headers=e.H)
    assert "old-report.md" in ls(e)


def test_delete_file_refuses_directory(env):
    e = env
    tool(e, "exec", command="mkdir -p d")
    aid = tool(e, "delete_file", path="d").json()["approval_id"]
    res = e.c.post(f"/approvals/{aid}", json={"decision": "approve"}, headers=e.H).json()
    assert res["status"] == "failed"
    assert "d" in ls(e)


# ---- AP-1 승인 기한 ---------------------------------------------------------
def test_approval_expires_and_is_refused(env):
    e = env
    e.box.approval_timeout = 1
    r = tool(e, "exec", command="rm /workspace/old-report.md")
    aid = r.json()["approval_id"]
    time.sleep(1.5)
    st = e.c.get(f"/approvals/{aid}", headers=e.A).json()
    assert st["status"] == "expired"
    assert e.c.post(f"/approvals/{aid}", json={"decision": "approve"}, headers=e.H).status_code == 409
    assert "old-report.md" in ls(e)
    assert any(x["event"] == "approval_expired" for x in events(e))


def test_gui_tool_on_cli_sandbox_refused(env):
    assert tool(env, "screenshot").status_code == 400


# ---- TL-2 GUI 도구, UX-1·UX-2 화면 -----------------------------------------
def _session(e):
    t = e.c.post(f"/sandboxes/{e.sid}/desktop/ticket", headers=e.H)
    assert t.status_code == 201, t.text
    r = e.c.get(t.json()["path"], follow_redirects=False)
    assert r.status_code == 303
    cookie = r.cookies[COOKIE]
    e.c.cookies.clear()
    return {"cookie": f"{COOKIE}={cookie}"}


@needs_desktop
def test_gui_tools_work(desk):
    e = desk
    shot = tool(e, "screenshot").json()["result"]
    png = base64.b64decode(shot["png_base64"])
    assert png[:4] == b"\x89PNG" and (shot["width"], shot["height"]) == (1280, 800)
    assert tool(e, "click", x=640, y=400).status_code == 200
    assert tool(e, "click", x=5000, y=1).status_code == 400
    assert tool(e, "key", keys="ctrl+Escape").status_code == 200
    assert tool(e, "key", keys="ctrl+s; rm").status_code == 400
    assert tool(e, "type", text="hello").status_code == 200
    ev = events(e)
    res = next(x for x in ev if x["event"] == "tool_result" and x["tool"] == "screenshot")
    assert "png_base64" not in res["payload"] and res["payload"]["sha256"]


@needs_desktop
def test_gui_input_snapshots_per_burst(desk):
    """보안 검수 N-1: GUI 입력은 정책 밖에서 /workspace를 바꿀 수 있으니 구간마다 복구 지점을 남긴다."""
    e = desk

    def snaps():
        return len(e.box.sandboxes.list_snapshots(e.sid))

    assert tool(e, "screenshot").status_code == 200 and snaps() == 0      # 화면 보기는 스냅샷 없음
    assert tool(e, "key", keys="ctrl+Escape").status_code == 200 and snaps() == 1   # 구간 시작
    assert tool(e, "click", x=10, y=10).status_code == 200 and snaps() == 1        # 같은 구간
    e.box._gui_input_at[e.sid] -= 61                                              # 60초 쉬었다가
    assert tool(e, "click", x=10, y=10).status_code == 200 and snaps() == 2
    e.box._gui_snap_at[e.sid] -= 601                                              # 쉬지 않아도 10분마다
    assert tool(e, "type", text="a").status_code == 200 and snaps() == 3

    # 스냅샷 상한에서는 구간 시작 입력이 승인을 거치고, 승인하면 그 구간은 다시 바로 돈다
    e.box.sandboxes.settings.snapshot_quota = snaps()
    e.box._gui_input_at[e.sid] -= 61
    r = tool(e, "click", x=10, y=10)
    assert r.status_code == 202, r.text
    res = e.c.post(f"/approvals/{r.json()['approval_id']}", json={"decision": "approve"}, headers=e.H).json()
    assert res["status"] == "executed" and res["snapshot_id"] and snaps() == 4
    assert tool(e, "click", x=10, y=10).status_code == 200 and snaps() == 4


@needs_desktop
def test_gui_burst_changes_logged(desk):
    """보안 검수 N-1(방안 G): GUI 구간 동안 정책 밖에서 바뀐 파일을 기록하고, 시작 스냅샷으로 되돌릴 수 있다."""
    e = desk
    assert tool(e, "key", keys="ctrl+Escape").status_code == 200       # 구간 시작 (스냅샷 + 파일 목록)
    snap = e.box.sandboxes.list_snapshots(e.sid)[0]["id"]
    # GUI 앱(터미널·파일 관리자)이 화면 계정으로 바꾼 것처럼
    c = e.box.sandboxes._container(e.sid)
    # new-report.md는 같은 길이로 바꾸고 mtime을 되돌린다 (크기·mtime만 보면 놓친다)
    assert c.exec_run(["sh", "-c", "rm /workspace/old-report.md; echo x > /workspace/gui-new.txt; "
                       "cp -p /workspace/new-report.md /tmp/ref; "
                       "sed -i 's/12/99/' /workspace/new-report.md; touch -r /tmp/ref /workspace/new-report.md"],
                      user="desktop").exit_code == 0
    assert not [x for x in events(e) if x["event"] == "gui_changes"]   # 아직 구간 안
    e.box._gui_input_at[e.sid] -= 61                                   # 입력이 끊기면 구간이 닫힌다
    ch = [x for x in events(e) if x["event"] == "gui_changes"]
    assert len(ch) == 1 and ch[0]["actor"] == "system"
    p = ch[0]["payload"]
    assert p["snapshot_id"] == snap and p["reason"] == "idle"
    assert (p["added"], p["modified"], p["deleted"]) == (["gui-new.txt"], ["new-report.md"], ["old-report.md"])
    page = e.c.get(f"/ui/audit?sandbox_id={e.sid}", headers=e.H).text
    assert "삭제됨: old-report.md" in page
    assert e.c.post(f"/sandboxes/{e.sid}/restore", json={"snapshot_id": snap}, headers=e.H).status_code == 200
    assert "old-report.md" in ls(e) and "gui-new.txt" not in ls(e)


@needs_desktop
def test_gui_burst_logged_before_restore(desk):
    """구간이 열린 채 사람이 되돌려도, 그때까지 바뀐 파일은 남긴다."""
    e = desk
    assert tool(e, "key", keys="ctrl+Escape").status_code == 200
    snap = e.box.sandboxes.list_snapshots(e.sid)[0]["id"]
    c = e.box.sandboxes._container(e.sid)
    assert c.exec_run(["rm", "/workspace/old-report.md"], user="desktop").exit_code == 0
    assert e.c.post(f"/sandboxes/{e.sid}/restore", json={"snapshot_id": snap}, headers=e.H).status_code == 200
    ch = [x["payload"] for x in events(e) if x["event"] == "gui_changes"]
    assert len(ch) == 1 and ch[0]["reason"] == "sandbox_restored" and ch[0]["deleted"] == ["old-report.md"]


@needs_desktop
def test_agent_cannot_reach_display_directly(desk):
    """에이전트 exec는 X 쿠키를 못 읽으니 xdotool로 화면을 직접 조작할 수 없다 (GUI 도구를 거쳐야 한다)."""
    from agentbox.policy import Policy

    desk.box.policy = Policy({"default": "allow"})  # 정책이 아니라 X 쿠키 격리를 본다
    out = tool(desk, "exec", command="cat /home/desktop/.Xauthority; DISPLAY=:0 xdotool getmouselocation; echo rc=$?")
    res = out.json()["result"]
    assert "Permission denied" in res["stderr"]
    assert "rc=0" not in res["stdout"]


@needs_desktop
def test_desktop_files_shared_with_agent(desk):
    """데스크톱 계정이 만든 파일을 에이전트가 고칠 수 있다 (같은 작업 폴더)."""
    e = desk
    c = e.box.sandboxes._container(e.sid)
    assert c.exec_run(["sh", "-c", "umask 002; echo gui > /workspace/from-gui.txt"], user="desktop").exit_code == 0
    assert tool(e, "write_file", path="from-gui.txt", content="agent").status_code == 200


@needs_desktop
def test_desktop_page_and_ticket(desk):
    e = desk
    assert e.c.post(f"/sandboxes/{e.sid}/desktop/ticket", headers=e.A).status_code == 403
    assert e.c.get(f"/sandboxes/{e.sid}/desktop").status_code == 401
    t = e.c.post(f"/sandboxes/{e.sid}/desktop/ticket", headers=e.H).json()
    assert e.c.get(t["path"], follow_redirects=False).status_code == 303
    e.c.cookies.clear()
    assert e.c.get(t["path"], follow_redirects=False).status_code == 403   # 1회용
    s = _session(e)
    page = e.c.get(f"/sandboxes/{e.sid}/desktop", headers=s)
    assert page.status_code == 200 and "rfb.js" in page.text
    assert e.c.get("/static/novnc/core/rfb.js").status_code == 200
    # 쿠키는 화면 경로에서만 통한다
    assert e.c.get("/audit", headers=s).status_code == 401
    # 다른 출처에서 온 요청은 막는다
    assert e.c.post(f"/sandboxes/{e.sid}/desktop/takeover",
                    headers=s | {"origin": "http://evil.example"}).status_code == 403


@needs_desktop
def test_view_websocket_speaks_rfb(desk):
    e = desk
    s = _session(e)
    with e.c.websocket_connect(f"/sandboxes/{e.sid}/desktop/ws?mode=view", headers=s,
                               subprotocols=["binary"]) as ws:
        assert ws.receive_bytes().startswith(b"RFB 003.")
    with pytest.raises(Exception):  # 인수 없이 입력 연결은 거부
        with e.c.websocket_connect(f"/sandboxes/{e.sid}/desktop/ws?mode=control", headers=s) as ws:
            ws.receive_bytes()


# 수용 테스트 8. 화면 인수 중 사람의 조작이 "사람 세션"으로 로그에 남는다
@needs_desktop
def test_human_takeover_logged(desk):
    e = desk
    s = _session(e)
    r = e.c.post(f"/sandboxes/{e.sid}/desktop/takeover", headers=s)
    assert r.status_code == 200 and r.json()["controller"] == "human" and r.json()["mine"]
    # 다른 브라우저 세션은 인수할 수 없다
    assert e.c.post(f"/sandboxes/{e.sid}/desktop/takeover", headers=_session(e)).status_code == 409
    # 인수 중 에이전트의 GUI 도구는 대기(423), 파일 도구는 계속 돈다
    assert tool(e, "click", x=10, y=10).status_code == 423
    assert tool(e, "screenshot").status_code == 423
    assert tool(e, "list_dir", path="/workspace").status_code == 200
    assert e.c.get(f"/sandboxes/{e.sid}/desktop/state", headers=e.A).json()["controller"] == "human"
    # 사람 세션의 입력 연결
    with e.c.websocket_connect(f"/sandboxes/{e.sid}/desktop/ws?mode=control", headers=s,
                               subprotocols=["binary"]) as ws:
        assert ws.receive_bytes().startswith(b"RFB 003.")
        ws.send_bytes(b"RFB 003.008\n")
    r = e.c.post(f"/sandboxes/{e.sid}/desktop/handback", headers=s)
    assert r.json()["controller"] == "agent"
    assert tool(e, "click", x=10, y=10).status_code == 200
    ev = events(e)
    names = [x["event"] for x in ev]
    for need in ("desktop_session_start", "human_takeover", "tool_blocked", "desktop_connect",
                 "desktop_disconnect", "human_handback"):
        assert need in names, need
    assert next(x for x in ev if x["event"] == "human_handback")["payload"]["client_bytes"] > 0
    take = next(x for x in ev if x["event"] == "human_takeover")
    conn = next(x for x in ev if x["event"] == "desktop_connect" and x["payload"]["mode"] == "control")
    back = next(x for x in ev if x["event"] == "human_handback")
    assert take["actor"] == conn["actor"] == back["actor"] == "human"
    assert take["payload"]["session"] == conn["payload"]["session"] == back["payload"]["session"]
    assert e.c.get("/audit/verify", headers=e.H).json()["ok"]


@needs_desktop
def test_takeover_refused_when_audit_unwritable(desk):
    e = desk
    s = _session(e)
    audit = e.box.audit
    audit.conn = sqlite3.connect(f"file:{e.db}?mode=ro", uri=True, check_same_thread=False, isolation_level=None)
    assert e.c.post(f"/sandboxes/{e.sid}/desktop/takeover", headers=s).status_code == 503
    audit.conn = sqlite3.connect(str(e.db), check_same_thread=False, isolation_level=None)
    assert e.c.get(f"/sandboxes/{e.sid}/desktop/state", headers=s).json()["controller"] == "agent"


@needs_desktop
def test_desktop_survives_restore(desk):
    e = desk
    snap = e.c.post(f"/sandboxes/{e.sid}/snapshots", headers=e.H).json()
    assert e.c.post(f"/sandboxes/{e.sid}/restore", json={"snapshot_id": snap["id"]}, headers=e.H).status_code == 200
    assert tool(e, "screenshot").status_code == 200
