"""세션 저장(SQLite)과 평문 HTTP 바인딩 막기. Docker 없이 돈다."""

import time

import pytest

from agentbox.cli import bind_problem, is_loopback
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
