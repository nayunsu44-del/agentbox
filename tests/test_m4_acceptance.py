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


def test_human_token_rotation_logs_out_browsers(home, monkeypatch):
    c, _, _, human = _build()
    cookie = c.post("/login", data={"token": human}, follow_redirects=False).cookies.get(COOKIE)
    assert cookie
    monkeypatch.setenv("AGENTBOX_HUMAN_TOKEN", "hum_rotated_" + "x" * 24)   # 사람 토큰 교체 후 재시작
    c2, _, H2, _ = _build()
    c2.cookies.set(COOKIE, cookie)
    assert c2.get("/ui", follow_redirects=False).status_code in (303, 401)
    assert c2.get("/ui/approvals", follow_redirects=False).status_code == 401
    assert c2.get("/sandboxes", headers=H2).status_code == 200                # 새 토큰은 그대로 쓴다


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
    monkeypatch.setenv("AGENTBOX_ALLOW_RUNC", "1")   # 여기서는 TLS 규칙만 본다 (런타임 규칙은 아래 테스트)
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


def test_serve_refuses_runc_when_exposed(home, monkeypatch, capsys):
    """밖에 여는 컨트롤 플레인은 runc(호스트 커널 공유)로 샌드박스를 돌리지 않는다."""
    import uvicorn

    ran = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: ran.update(kw))
    monkeypatch.setenv("AGENTBOX_RUNTIME", "runc")
    monkeypatch.delenv("AGENTBOX_ALLOW_RUNC", raising=False)
    for args in (["--host", "0.0.0.0", "--behind-tls-proxy"], ["--host", "0.0.0.0", "--insecure"],
                 ["--host", "127.0.0.1", "--behind-tls-proxy"]):
        with pytest.raises(SystemExit) as ex:
            cli.main(["serve", *args])
        assert "runc" in str(ex.value) and "--allow-runc" in str(ex.value) and not ran, args
    cli.main(["serve", "--host", "0.0.0.0", "--behind-tls-proxy", "--allow-runc"])
    assert ran and "경고" in capsys.readouterr().err
    ran.clear()
    monkeypatch.setenv("AGENTBOX_ALLOW_RUNC", "1")
    cli.main(["serve", "--host", "0.0.0.0", "--behind-tls-proxy"])
    assert ran
    ran.clear()
    monkeypatch.delenv("AGENTBOX_ALLOW_RUNC")
    cli.main(["serve"])                                # 127.0.0.1 개발용은 경고만 하고 뜬다
    assert ran["host"] == "127.0.0.1" and "개발 전용" in capsys.readouterr().err


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


def test_nested_mount_under_source_not_copied(home):
    """보안 검수 run-3 v06 남은 틈: 원본 폴더 안쪽에 다른 폴더(데이터 폴더 등)가 마운트돼 있어도 복사하지 않는다."""
    import os
    import subprocess

    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    src, secret = home / "proj", home / "secret"
    (src / "inner").mkdir(parents=True)
    secret.mkdir()
    (src / "keep.md").write_text("keep")
    (secret / "agentbox.db").write_text("비밀")
    if subprocess.run([*sudo, "mount", "--bind", str(secret), str(src / "inner")], capture_output=True).returncode != 0:
        pytest.skip("바인드 마운트를 만들 수 없음")
    c, _, H, _ = _build()
    sid = None
    try:
        r = c.post("/sandboxes", json={"source_dir": str(src), "template": "cli"}, headers=H)
        assert r.status_code == 201, r.text
        sid, A = r.json()["id"], {"Authorization": f"Bearer {r.json()['agent_token']}"}
        r = c.post(f"/sandboxes/{sid}/tools/exec", json={"args": {"command": "ls -R /workspace"}}, headers=A)
        out = r.json()["result"]["stdout"]
        assert "keep.md" in out and "inner" in out and "agentbox.db" not in out, out
    finally:
        if sid:
            c.delete(f"/sandboxes/{sid}", headers=H)
        subprocess.run([*sudo, "umount", str(src / "inner")])


def test_ui_refuses_framing(home):
    """보안 검수 run-3 v14: 쿠키로 로그인하는 화면을 다른 출처가 iframe에 넣지 못한다 (같은 출처의 데스크톱 iframe은 된다)."""
    c, _, H, _ = _build()
    for path in ("/login", "/ui", "/healthz"):
        r = c.get(path, headers=H, follow_redirects=False)
        assert r.headers["x-frame-options"] == "SAMEORIGIN", path
        assert r.headers["content-security-policy"] == "frame-ancestors 'self'", path


def test_preview_flags_every_unmodeled_segment(home):
    """보안 검수 run-3 v17: rm이 섞인 명령의 다른 조각(mv, find -delete)도 '계산 못 함'으로 표시한다."""
    c, _, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
    try:
        r = c.post(f"/sandboxes/{sid}/tools/exec", headers=A, json={"args": {
            "command": "rm -f /workspace/harmless.txt; mv /workspace/important.db /tmp/gone && sudo rm -f /workspace/x"}})
        assert r.status_code == 202, r.text
        prev = c.get(f"/approvals/{r.json()['approval_id']}", headers=H).json()["preview"]
        assert [a["path"] for a in prev["affected"]] == ["/workspace/harmless.txt", "/workspace/x"]
        assert prev["notes"] == ["'mv /workspace/important.db /tmp/gone' 부분의 영향은 자동 계산하지 못함. 명령 원문을 확인할 것."]
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)


def test_unauthenticated_body_rejected_before_read(home, monkeypatch):
    """보안 검수 run-4 F1: 토큰 없는 큰 본문은 읽기 전에 413이고, 파일 넣기는 인증 전에 임시 파일을 만들지 않는다."""
    import starlette.formparsers as fp
    c, _, H, _ = _build()
    big = b'{"source_dir": "' + b"a" * (9 * 1024 * 1024) + b'"}'
    assert c.post("/sandboxes", content=big, headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/sandboxes", content=big, headers={**H, "content-type": "application/json"}).status_code == 413
    spooled = []
    real = fp.SpooledTemporaryFile

    def counting(*a, **kw):
        spooled.append(1)
        return real(*a, **kw)

    monkeypatch.setattr(fp, "SpooledTemporaryFile", counting)
    r = c.post("/sandboxes/sb_none/files", files={"files": ("big.bin", b"x" * (2 * 1024 * 1024))})
    assert r.status_code == 401 and spooled == []          # 인증 전에는 본문을 받지 않는다
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    try:
        r = c.post(f"/sandboxes/{sb['id']}/files", files={"files": ("ok.txt", b"hello")}, headers=H)
        assert r.status_code == 201 and spooled                 # 인증하면 그대로 넣는다
        assert c.post(f"/sandboxes/{sb['id']}/files", data={"x": "1"}, headers=H).status_code == 422
    finally:
        c.delete(f"/sandboxes/{sb['id']}", headers=H)


def test_agent_input_cannot_grow_audit_rows(home):
    """보안 검수 run-4 F3: 도구 오류 문자열과 승인 미리보기로 들어가는 에이전트 입력도 감사 행 크기가 묶인다."""
    import sqlite3
    c, box, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
    try:
        r = c.post(f"/sandboxes/{sid}/tools/read_file", headers=A, json={"args": {"path": "/etc/" + "A" * 131072}})
        assert r.status_code == 400
        r = c.post(f"/sandboxes/{sid}/tools/delete_file", headers=A, json={"args": {"path": "/etc/" + "B" * 262144}})
        assert r.status_code == 202
        r = c.post(f"/sandboxes/{sid}/tools/exec", headers=A, json={"args": {"command": "; ".join(["mv a b"] * 2001)}})
        assert r.status_code == 202
        db = sqlite3.connect(home / "data" / "agentbox.db")
        sizes = [len(p.encode()) for (p,) in db.execute("SELECT payload FROM audit WHERE sandbox_id=?", (sid,))]
        assert max(sizes) <= 128 * 1024   # AUDIT_PAYLOAD_MAX
        assert c.get("/audit/verify", headers=H).json()["ok"]
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)


def _race_restore(box, sid, snap_id, do_delete):
    """복원이 새 컨테이너를 만든 직후에 멈춰 있는 동안 do_delete를 다른 스레드에서 부른다."""
    import threading
    import time
    real = box.sandboxes._run_container
    started, go = threading.Event(), threading.Event()

    def paused(*a, **kw):
        cont = real(*a, **kw)
        started.set()
        go.wait(20)
        return cont

    box.sandboxes._run_container = paused
    out = {}

    def restore():
        try:
            out["restore"] = box.restore_sandbox(sid, snap_id)
        except Exception as e:
            out["restore"] = e

    def delete():
        try:
            do_delete()
            out["delete"] = "ok"
        except Exception as e:
            out["delete"] = e

    t = threading.Thread(target=restore)
    t.start()
    assert started.wait(60)
    d = threading.Thread(target=delete)
    d.start()
    time.sleep(1.0)            # 잠금이 없으면 삭제가 이 사이에 끝난다
    go.set()
    t.join(120)
    d.join(120)
    box.sandboxes._run_container = real
    return out


def _live(box, sid):
    return [c for c in box.sandboxes.client.containers.list(all=True) if c.name == f"agentbox-{sid}"]


def test_restore_racing_delete_does_not_resurrect(home):
    """보안 검수 run-4 F6: 복원과 삭제가 겹쳐도 지운 샌드박스와 그 에이전트 토큰이 되살아나지 않는다."""
    c, box, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid, tok = sb["id"], sb["agent_token"]
    snap = box.snapshot_sandbox(sid)
    out = _race_restore(box, sid, snap["id"], lambda: box.delete_sandbox(sid))
    assert out["delete"] == "ok"
    assert box.sandboxes.get(sid)["status"] == "deleted"
    assert not box.sandboxes.token_matches(sid, tok) and box.sandboxes.sandbox_for_token(tok) is None
    assert not _live(box, sid)


def test_restore_refuses_a_deleted_sandbox(home):
    """F6 다층 방어: 서비스 잠금을 거치지 않은 삭제가 끼어도 복원의 마지막 쓰기가 행을 되살리지 않는다."""
    from agentbox.sandbox import SandboxError
    c, box, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid, tok = sb["id"], sb["agent_token"]
    snap = box.snapshot_sandbox(sid)
    out = _race_restore(box, sid, snap["id"], lambda: box.sandboxes.delete(sid))
    assert isinstance(out["restore"], SandboxError)
    assert box.sandboxes.get(sid)["status"] == "deleted" and not box.sandboxes.token_matches(sid, tok)
    assert not _live(box, sid)
    with pytest.raises(SandboxError):
        box.sandboxes.restore(sid, snap["id"])


def test_preview_paths_with_spaces_and_newlines(home):
    """보안 검수 run-4 F4: 영향 표가 공백·줄바꿈이 든 경로를 한 경로로 보이고, 있는 파일을 '없음'으로 보이지 않는다."""
    c, box, H, _ = _build()
    sb = c.post("/sandboxes", json={"source_dir": None, "template": "cli"}, headers=H).json()
    sid = sb["id"]
    try:
        box.sandboxes._container(sid).exec_run(
            ["sh", "-c", 'cd /workspace && touch "final report.docx" final report.docx "$(printf "a\\nb")" && '
                         'mkdir "dir with space" && touch "dir with space/inner"'], user="1000")
        p = box.sandboxes.preview(sid, 'rm "final report.docx"')
        assert p["affected"] == [{"path": "final report.docx", "effect": "삭제"}]
        p = box.sandboxes.preview(sid, "rm *")
        assert {"path": "a\nb", "effect": "삭제"} in p["affected"]
        assert {a["path"] for a in p["affected"]} >= {"final report.docx", "final", "report.docx"}
        p = box.sandboxes.preview(sid, 'rm -r "dir with space"')
        assert [a["path"] for a in p["affected"]] == ["dir with space", "dir with space/inner"]
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)


@needs_desktop
def test_novnc_extracted_once_under_concurrency(home, monkeypatch):
    """보안 검수 run-4 F5: 인증 없는 정적 파일 요청이 동시에 와도 noVNC 꺼내기는 한 번이고, 실패하면 한동안 다시 하지 않는다."""
    from concurrent.futures import ThreadPoolExecutor
    from docker.models.containers import ContainerCollection
    created = []
    real = ContainerCollection.create
    monkeypatch.setattr(ContainerCollection, "create", lambda self, *a, **kw: (created.append(1), real(self, *a, **kw))[1])
    c, box, H, _ = _build()
    box.sandboxes.settings.desktop_image = "agentbox-missing-image:0"     # 실패 쪽 먼저
    assert [c.get("/static/novnc/core/rfb.js").status_code for _ in range(3)] == [404, 404, 404]
    assert len(created) == 1                                             # 실패한 뒤에는 바로 다시 하지 않는다
    c2, _, _, _ = _build()                                               # 새 서버: 진짜 이미지
    created.clear()
    with ThreadPoolExecutor(8) as ex:
        codes = list(ex.map(lambda _: c2.get("/static/novnc/core/rfb.js").status_code, range(8)))
    assert codes == [200] * 8 and len(created) == 1


def test_failed_logins_are_aggregated(home, monkeypatch):
    """보안 검수 run-4 F8: 인증 없는 로그인 실패가 시도마다 감사 행을 만들지 않고, ASCII 밖 입력도 500이 아니다."""
    import time
    from agentbox import web
    c, box, H, _ = _build()

    def failed_rows():
        return [r for r in box.audit.list(limit=5000) if r["event"] == "ui_login_failed"]

    for _ in range(12):
        assert c.post("/login", data={"token": "hum_wrong"}).status_code == 200
    assert len(failed_rows()) == 5                       # web.LOGIN_FAIL_LOG_MAX
    monkeypatch.setattr(web, "LOGIN_FAIL_WINDOW", 0.2, raising=False)
    time.sleep(0.3)
    c.post("/login", data={"token": "hum_wrong"})
    rows = failed_rows()
    assert len(rows) == 6 and rows[-1]["payload"] == {"suppressed_before": 7}
    assert c.post("/login", data={"token": "토큰"}).status_code == 200      # 예전에는 TypeError로 500
    assert c.get("/sandboxes", headers={"Authorization": b"Bearer \xe9t\xe9"}).status_code == 401


_FORGE = """
import ctypes as C, sys, time
X = C.CDLL("libX11.so.6")
X.XOpenDisplay.restype = C.c_void_p
X.XDefaultRootWindow.argtypes, X.XDefaultRootWindow.restype = [C.c_void_p], C.c_ulong
X.XCreateSimpleWindow.argtypes = [C.c_void_p, C.c_ulong] + [C.c_int] * 2 + [C.c_uint] * 3 + [C.c_ulong] * 2
X.XCreateSimpleWindow.restype = C.c_ulong
X.XInternAtom.argtypes, X.XInternAtom.restype = [C.c_void_p, C.c_char_p, C.c_int], C.c_ulong
X.XChangeProperty.argtypes = [C.c_void_p, C.c_ulong, C.c_ulong, C.c_ulong, C.c_int, C.c_int, C.c_void_p, C.c_int]
X.XStoreName.argtypes = [C.c_void_p, C.c_ulong, C.c_char_p]
X.XMapWindow.argtypes = X.XFlush.argtypes = None
d = X.XOpenDisplay(None)
w = X.XCreateSimpleWindow(d, X.XDefaultRootWindow(d), 0, 0, 1, 1, 0, 0, 0)
v = C.c_ulong(int(sys.argv[1]))
X.XChangeProperty(d, w, X.XInternAtom(d, b"_NET_WM_PID", 0), X.XInternAtom(d, b"CARDINAL", 0), 32, 0, C.byref(v), 1)
X.XStoreName(d, w, b"forged")
X.XMapWindow(C.c_void_p(d), C.c_ulong(w))
X.XFlush(C.c_void_p(d))
time.sleep(120)
"""


@needs_desktop
def test_window_owner_comes_from_x_server_not_net_wm_pid(home):
    """보안 검수 run-4 N4: 창이 _NET_WM_PID로 남의 pid를 대도, 창 주인은 X 서버가 아는 실제 클라이언트다.
    예전에는 그 pid의 데몬이 '창 있는 앱'으로 보여 GUI 구간이 끝나도 멈추지 않았다."""
    import time
    from agentbox.sandbox_desktop import DESKTOP_ENV, DESKTOP_USER
    c, box, H, _ = _build()
    sid = c.post("/sandboxes", json={"source_dir": None, "template": "desktop"}, headers=H).json()["id"]
    try:
        box.sandboxes.screenshot(sid)                                     # 화면이 뜰 때까지
        ct = box.sandboxes._desktop(sid)
        out = ct.exec_run(["sh", "-c", 'sleep 300 >/dev/null 2>&1 & d=$!; '
                           'python3 -c "$0" $d >/dev/null 2>&1 & echo $d $!', _FORGE],
                          user=DESKTOP_USER, environment=DESKTOP_ENV).output.split()
        daemon, forger = int(out[0]), int(out[1])
        for _ in range(50):
            _, wins = box.sandboxes.desktop_processes(sid)
            if forger in wins:
                break
            time.sleep(0.2)
        assert forger in wins and daemon not in wins
        net = ct.exec_run(["sh", "-c", "for w in $(xdotool search --name '^forged$'); do xdotool getwindowpid $w; done"],
                          user=DESKTOP_USER, environment=DESKTOP_ENV).output.split()
        assert net == [str(daemon).encode()]                              # 창이 적은 값은 데몬 pid (위조)
    finally:
        c.delete(f"/sandboxes/{sid}", headers=H)
