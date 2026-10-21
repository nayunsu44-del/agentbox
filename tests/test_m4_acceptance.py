"""세션 저장·재시작 처리와 TLS 쿠키. 실제 Docker가 필요하다 (인수 재시작은 데스크톱 이미지도)."""

import pytest

docker = pytest.importorskip("docker")
try:
    _dc = docker.from_env()
    _dc.ping()
except Exception:  # pragma: no cover
    pytest.skip("Docker 데몬이 없음", allow_module_level=True)

from fastapi.testclient import TestClient  # noqa: E402

from agentbox import cli  # noqa: E402
from agentbox.config import Settings  # noqa: E402
from agentbox.desktop import COOKIE  # noqa: E402


def _has_image(name):
    try:
        _dc.images.get(name)
        return True
    except Exception:
        return False


needs_desktop = pytest.mark.skipif(not _has_image(Settings().desktop_image), reason="데스크톱 이미지가 없음")


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("AGENTBOX_HUMAN_TOKEN", raising=False)
    monkeypatch.delenv("AGENTBOX_SECURE_COOKIE", raising=False)
    return tmp_path


def _build():
    from agentbox.api import build

    app, box, human = build()
    return TestClient(app), box, {"Authorization": f"Bearer {human}"}, human


def _events(c, H, sid):
    return c.get("/audit", params={"sandbox_id": sid}, headers=H).json()


def test_login_survives_restart(home):
    c, _, H, human = _build()
    r = c.post("/login", data={"token": human}, follow_redirects=False)
    cookie = r.cookies.get(COOKIE)
    assert cookie and "secure" not in r.headers["set-cookie"].lower()  # 평문 로컬에서는 Secure 없음
    c2, _, _, _ = _build()                                          # 서버 재시작
    c2.cookies.set(COOKIE, cookie)
    assert c2.get("/ui").status_code == 200
    assert c2.post("/logout", follow_redirects=False).status_code == 303
    c3, _, _, _ = _build()
    c3.cookies.set(COOKIE, cookie)
    assert c3.get("/ui", follow_redirects=False).status_code in (303, 401)


def test_secure_cookie_behind_tls(home, monkeypatch):
    monkeypatch.setenv("AGENTBOX_SECURE_COOKIE", "1")
    c, _, _, human = _build()
    r = c.post("/login", data={"token": human}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()


def test_secure_cookie_on_https_request(home):
    from agentbox.api import build

    app, _, human = build()
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/login", data={"token": human}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()


def test_serve_refuses_plain_http_outside_loopback(home, monkeypatch, capsys):
    import uvicorn

    ran = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(kw))
    with pytest.raises(SystemExit) as ex:
        cli.main(["serve", "--host", "0.0.0.0"])
    assert "TLS" in str(ex.value) and not ran
    cli.main(["serve", "--host", "0.0.0.0", "--insecure"])
    assert ran["host"] == "0.0.0.0" and "경고" in capsys.readouterr().err
    ran.clear()
    cli.main(["serve", "--host", "0.0.0.0", "--behind-tls-proxy"])
    assert ran["proxy_headers"] is True
    with pytest.raises(SystemExit):
        cli.main(["serve", "--host", "0.0.0.0", "--tls-cert", "x.pem"])  # 키 없이


@needs_desktop
def test_takeover_closed_on_restart(home):
    c, box, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "desktop"}, headers=H).json()
    sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
    try:
        t = c.post(f"/sandboxes/{sid}/desktop/ticket", headers=H).json()["ticket"]
        r = c.get(f"/sandboxes/{sid}/desktop?ticket={t}", follow_redirects=False)
        cookie = r.cookies.get(COOKIE)
        assert c.post(f"/sandboxes/{sid}/desktop/takeover").json()["controller"] == "human"
        # 돌려주지 않은 채 서버가 내려갔다가 다시 뜬다
        c2, _, _, _ = _build()
        c2.cookies.set(COOKIE, cookie)
        st = c2.get(f"/sandboxes/{sid}/desktop/state")
        assert st.status_code == 200 and st.json()["controller"] == "agent"  # 로그인은 유지, 인수는 끝남
        assert c2.post(f"/sandboxes/{sid}/tools/click", json={"args": {"x": 5, "y": 5}}, headers=A).status_code == 200
        ev = _events(c2, H, sid)
        takes = [x for x in ev if x["event"] == "human_takeover"]
        backs = [x for x in ev if x["event"] == "human_handback"]
        assert len(takes) == len(backs) == 1
        assert backs[0]["actor"] == "system" and backs[0]["payload"]["reason"] == "server_restart"
        assert backs[0]["payload"]["session"] == takes[0]["payload"]["session"]
        _build()                                   # 한 번 더 띄워도 중복 기록하지 않는다
        assert len([x for x in _events(c2, H, sid) if x["event"] == "human_handback"]) == 1
        assert c2.get("/audit/verify", headers=H).json()["ok"]
        # 다시 인수하고 정상 반환하면 짝이 하나 더 생긴다
        assert c2.post(f"/sandboxes/{sid}/desktop/takeover").json()["mine"]
        assert c2.post(f"/sandboxes/{sid}/desktop/handback").json()["controller"] == "agent"
        ev = _events(c2, H, sid)
        assert len([x for x in ev if x["event"] == "human_takeover"]) == 2
        assert len([x for x in ev if x["event"] == "human_handback"]) == 2
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)


def test_preview_does_not_run_find_options(home):
    """파일 이름이 -delete여도 승인 카드용 미리보기가 find 옵션으로 읽어 지우지 않는다."""
    c, _, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}

    def tool(name, **args):
        return c.post(f"/sandboxes/{sid}/tools/{name}", json={"args": args}, headers=A)

    try:
        assert tool("write_file", path="/workspace/keep.md", content="keep").status_code == 200
        assert tool("write_file", path="/workspace/-delete", content="x").status_code == 200
        r = tool("exec", command="rm -r -- -delete")
        assert r.status_code == 202, r.text
        pending = c.get("/approvals", params={"status": "pending"}, headers=H).json()
        assert "-delete" in str(pending[0]["preview"])
        names = tool("exec", command="ls -a /workspace").json()["result"]["stdout"].split()
        assert "keep.md" in names and "-delete" in names          # 승인 전에는 아무것도 안 지워졌다
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)
