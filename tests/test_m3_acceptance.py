"""M3 수용 테스트: 웹 UI 로그인, 파일 넣기·결과함 받기, 승인 화면(요약 + 화면 캡처), 감사 타임라인·검증.

실제 Docker가 필요하다. 데스크톱 항목은 agentbox-desktop 이미지가 있어야 돈다.
"""

import sqlite3

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
from agentbox.policy import Policy  # noqa: E402


def _has_image(name):
    try:
        _dc.images.get(name)
        return True
    except Exception:
        return False


needs_desktop = pytest.mark.skipif(not _has_image(Settings().desktop_image), reason="데스크톱 이미지가 없음")


class E:
    pass


@pytest.fixture()
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("AGENTBOX_HUMAN_TOKEN", raising=False)
    from agentbox.api import build

    app, box, human = build()
    e = E()
    e.c, e.box, e.human, e.db = TestClient(app), box, human, tmp_path / "data" / "agentbox.db"
    e.H = {"Authorization": f"Bearer {human}"}
    e.sids = []
    yield e
    for sid in e.sids:
        e.c.delete(f"/sandboxes/{sid}", headers=e.H)


def login(e):
    r = e.c.post("/login", data={"token": e.human}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/ui"
    return r


def create(e, template="cli"):
    r = e.c.post("/ui/sandboxes", data={"template": template, "source_dir": ""})
    assert r.status_code == 200 and "agent-token" in r.text, r.text
    sid = r.text.split("샌드박스 ")[1].split("</b>")[0].strip()
    token = r.text.split('<pre id="agent-token">')[1].split("</pre>")[0].strip()
    e.sids.append(sid)
    return sid, {"Authorization": f"Bearer {token}"}


def tool(e, sid, A, name, **args):
    return e.c.post(f"/sandboxes/{sid}/tools/{name}", json={"args": args}, headers=A)


def events(e, sid):
    return e.c.get("/audit", params={"sandbox_id": sid}, headers=e.H).json()


# ---- 로그인 ---------------------------------------------------------------
def test_login_required_and_agent_token_refused(ui):
    e = ui
    assert e.c.get("/ui", follow_redirects=False).headers["location"] == "/login"
    assert e.c.get("/ui/approvals").status_code == 401
    sb = e.c.post("/sandboxes", json={}, headers=e.H).json()
    e.sids.append(sb["id"])
    r = e.c.post("/login", data={"token": sb["agent_token"]}, follow_redirects=False)
    assert r.status_code == 200 and COOKIE not in r.cookies
    # 에이전트 토큰을 헤더로 붙여도 웹 UI·결과함은 사람만
    A = {"Authorization": f"Bearer {sb['agent_token']}"}
    assert e.c.get("/ui/approvals", headers=A).status_code == 403
    assert e.c.get(f"/sandboxes/{sb['id']}/outbox", headers=A).status_code == 403
    assert e.c.post(f"/sandboxes/{sb['id']}/files", files={"files": ("a.txt", b"x")}, headers=A).status_code == 403
    assert e.c.post("/ui/ticket", headers=A).status_code == 403
    login(e)
    assert e.c.get("/ui").status_code == 200
    assert any(x["event"] == "ui_login_failed" for x in e.c.get("/audit", headers=e.H).json())


def test_login_ticket_is_one_time(ui):
    e = ui
    t = e.c.post("/ui/ticket", headers=e.H).json()["path"]
    assert e.c.get(t, follow_redirects=False).status_code == 303
    e.c.cookies.clear()
    r = e.c.get(t, follow_redirects=False)
    assert r.status_code == 200 and "만료" in r.text


def test_cross_origin_post_refused(ui):
    e = ui
    login(e)
    r = e.c.post("/ui/sandboxes", data={"template": "cli"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


# ---- SB-1 + UX-3 + UX-4 -------------------------------------------------------
def test_create_upload_outbox_download(ui):
    e = ui
    login(e)
    sid, A = create(e)
    assert sid in e.c.get("/ui/sandboxes").text
    r = e.c.post(f"/sandboxes/{sid}/files", files=[("files", ("2023-보고서.md", "# 오래됨\n".encode())),
                                                   ("files", ("new.md", b"# new\n"))])
    assert r.status_code == 201, r.text
    assert [x["path"] for x in r.json()] == ["/workspace/2023-보고서.md", "/workspace/new.md"]
    out = tool(e, sid, A, "exec", command="stat -c '%u %a' 2023-보고서.md").json()["result"]
    assert out["stdout"].strip() == "1000 664"                           # 에이전트가 고칠 수 있다
    imported = [x for x in events(e, sid) if x["event"] == "file_imported"]
    assert len(imported) == 2 and len(imported[0]["payload"]["sha256"]) == 64 and imported[0]["actor"] == "human"
    # 결과함
    assert "비어 있음" in e.c.get(f"/ui/sandboxes/{sid}/outbox").text
    e.box.policy = Policy({"default": "allow"})  # 결과함이 링크를 걸러내는지 본다 (정책은 따로 테스트)
    tool(e, sid, A, "exec", command="printf '요약 본문' > outbox/요약.md && ln -s /etc/passwd outbox/link")
    names = [f["name"] for f in e.c.get(f"/sandboxes/{sid}/outbox").json()]
    assert names == ["요약.md"]                                           # 링크는 보이지 않는다
    assert "요약.md" in e.c.get(f"/ui/sandboxes/{sid}/outbox").text
    d = e.c.get(f"/sandboxes/{sid}/outbox/요약.md")
    assert d.status_code == 200 and d.content == "요약 본문".encode() and "attachment" in d.headers["content-disposition"]
    assert e.c.get(f"/sandboxes/{sid}/outbox/link").status_code == 400
    exp = [x for x in events(e, sid) if x["event"] == "file_exported"]
    assert len(exp) == 1 and exp[0]["payload"]["name"] == "요약.md" and exp[0]["payload"]["session"].startswith("hs_")


def test_upload_large_binary(ui):
    import hashlib
    import os

    e = ui
    login(e)
    sid, A = create(e)
    blob = os.urandom(3 * 1024 * 1024 + 7)
    assert e.c.post(f"/sandboxes/{sid}/files", files={"files": ("blob.bin", blob)}).status_code == 201
    out = tool(e, sid, A, "exec", command="sha256sum blob.bin; ls -a").json()["result"]["stdout"]
    assert hashlib.sha256(blob).hexdigest() in out and ".agentbox-upload" not in out


def test_upload_overwrite_snapshots_and_bad_names(ui):
    e = ui
    login(e)
    sid, A = create(e)
    e.c.post(f"/sandboxes/{sid}/files", files={"files": ("a.txt", b"one")})
    assert not [x for x in events(e, sid) if x["event"] == "snapshot"]
    e.c.post(f"/sandboxes/{sid}/files", files={"files": ("a.txt", b"two")})
    assert [x for x in events(e, sid) if x["event"] == "snapshot"]           # 덮어쓰기 전 스냅샷
    for bad in ("..", "x/y.txt", "a\\b"):
        r = e.c.post(f"/sandboxes/{sid}/files", files={"files": (bad, b"x")})
        assert r.status_code == 400, bad


def test_export_refused_when_audit_unwritable(ui):
    e = ui
    login(e)
    sid, A = create(e)
    assert tool(e, sid, A, "write_file", path="/workspace/outbox/r.txt", content="hi").status_code == 200
    e.box.audit.conn = sqlite3.connect(f"file:{e.db}?mode=ro", uri=True, check_same_thread=False,
                                       isolation_level=None)
    assert e.c.get(f"/sandboxes/{sid}/outbox/r.txt").status_code == 503       # 기록 못 하면 반출 안 함
    e.box.audit.conn = sqlite3.connect(str(e.db), check_same_thread=False, isolation_level=None)


# ---- AP-1 + UX-5 웹 승인 ----------------------------------------------------
def test_web_approval_shows_system_summary_and_executes(ui):
    e = ui
    login(e)
    sid, A = create(e)
    e.c.post(f"/sandboxes/{sid}/files", files={"files": ("old.md", b"x")})
    r = tool(e, sid, A, "delete_file", path="old.md")
    aid = r.json()["approval_id"]
    page = e.c.get("/ui/approvals", params={"sandbox_id": sid}).text
    assert aid in page and "/workspace/old.md" in page and "삭제" in page and "delete-file-needs-approval" in page
    assert "승인 대기 1건" in e.c.get("/ui/notify").text
    # 내용이 그대로면 다시 그리지 않는다 (누르려던 버튼이 바뀌지 않게)
    first = e.c.get("/ui/approvals", params={"sandbox_id": sid})
    v = first.headers["x-ab-version"]
    assert e.c.get("/ui/approvals", params={"sandbox_id": sid}, headers={"X-AB-Have": v}).status_code == 204
    assert e.c.get("/ui/approvals", params={"sandbox_id": sid}, headers={"X-AB-Have": "old"}).status_code == 200
    r = e.c.post(f"/ui/approvals/{aid}/approve", params={"sandbox_id": sid})
    assert r.status_code == 200 and "executed" in r.text
    assert "old.md" not in tool(e, sid, A, "list_dir", path="/workspace").json()["result"]["listing"]
    dec = next(x for x in events(e, sid) if x["event"] == "approval_decision")
    assert dec["actor"] == "human" and dec["payload"]["session"].startswith("hs_")
    # 이미 결정된 요청을 다시 누르면 화면에 오류만 보인다
    assert "이미 결정된" in e.c.post(f"/ui/approvals/{aid}/deny", params={"sandbox_id": sid}).text


@needs_desktop
def test_web_approval_neutralises_bidi_controls(ui):
    """보안 검수 run-3 v13: 승인 화면이 에이전트 명령의 양방향 문자를 그대로 내보내면 브라우저가 순서를 바꿔 보여준다."""
    e = ui
    login(e)
    sid, A = create(e)
    cmd = "sh -c 'echo ok \u2067; rm -rf /workspace/x \u2069 #\u202e'\nexit"
    r = tool(e, sid, A, "exec", command=cmd)
    assert r.status_code == 202, r.text
    for path in ("/ui/approvals", "/ui/audit"):
        page = e.c.get(path, params={"sandbox_id": sid}).text
        assert not any(ch in page for ch in "\u2067\u2069\u202e"), path
        assert "\\u2067" in page and "\\u202e" in page, path
    page = e.c.get("/ui/approvals", params={"sandbox_id": sid}).text
    assert "#\\u202e&#39;\nexit</pre>" in page                     # 줄바꿈은 그대로 보인다


def test_approval_has_screen_capture(ui):
    e = ui
    login(e)
    sid, A = create(e, "desktop")
    # 캡처는 실패해도 승인 요청을 막지 않는다(최선 노력). 화면이 뜰 때까지 기다린 뒤 요청한다.
    assert tool(e, sid, A, "screenshot").status_code == 200
    aid = tool(e, sid, A, "exec", command="rm -f /workspace/nothing").json()["approval_id"]
    apr = e.c.get(f"/approvals/{aid}", headers=e.H).json()
    assert apr["preview"]["capture"]["width"] == 1280
    assert f"/approvals/{aid}/capture.png" in e.c.get("/ui/approvals").text
    png = e.c.get(f"/approvals/{aid}/capture.png")
    assert png.status_code == 200 and png.content[:4] == b"\x89PNG"
    ev = next(x for x in events(e, sid) if x["event"] == "approval_requested")
    assert len(ev["payload"]["capture"]["sha256"]) == 64
    assert e.c.get(f"/approvals/{aid}/capture.png", headers={"Authorization": A["Authorization"]}).status_code == 403
    page = e.c.get(f"/ui/sandboxes/{sid}").text
    assert f'src="/sandboxes/{sid}/desktop"' in page
    assert e.c.get(f"/sandboxes/{sid}/desktop").status_code == 200       # 로그인 세션으로 화면도 열린다


# ---- UX-6 타임라인과 검증 ----------------------------------------------------
def test_timeline_and_verify_points_to_tampered_entry(ui):
    e = ui
    login(e)
    sid, A = create(e)
    tool(e, sid, A, "exec", command="echo hello")
    tl = e.c.get("/ui/audit", params={"sandbox_id": sid}).text
    assert "sandbox_created" in tl and "tool_request" in tl and "AI" in tl and "사람" in tl
    assert "해시 체인 온전함" in e.c.get("/ui/verify", params={"sandbox_id": sid}).text
    target = next(x for x in events(e, sid) if x["event"] == "tool_request")
    raw = sqlite3.connect(e.db)
    raw.execute("DROP TRIGGER audit_no_update")
    raw.execute("UPDATE audit SET payload = ? WHERE id = ?", ('{"args": {"command": "echo innocent"}}', target["id"]))
    raw.commit()
    v = e.c.get("/ui/verify", params={"sandbox_id": sid}).text
    assert "깨짐" in v and f"#{target['id']}" in v and "이 샌드박스의 항목" in v


def test_restore_and_delete_from_ui(ui):
    e = ui
    login(e)
    sid, A = create(e)
    e.c.post(f"/sandboxes/{sid}/files", files={"files": ("keep.md", b"k")})
    e.c.post(f"/ui/sandboxes/{sid}/snapshots")
    snap = e.box.sandboxes.list_snapshots(sid)[-1]["id"]
    aid = tool(e, sid, A, "exec", command="rm keep.md").json()["approval_id"]
    e.c.post(f"/ui/approvals/{aid}/approve")
    assert "keep.md" not in tool(e, sid, A, "exec", command="ls").json()["result"]["stdout"]
    assert snap in e.c.post(f"/ui/sandboxes/{sid}/restore/{snap}").text
    assert "keep.md" in tool(e, sid, A, "exec", command="ls").json()["result"]["stdout"]
    r = e.c.post(f"/ui/sandboxes/{sid}/delete")
    assert r.headers["hx-redirect"] == "/ui"
    assert sid not in e.c.get("/ui/sandboxes").text
