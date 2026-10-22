"""M2 단위 테스트 (Docker 없이): 화면 세션·인수 상태, 기본 정책, 감사 로그에 파일 내용이 안 남는 것."""

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
