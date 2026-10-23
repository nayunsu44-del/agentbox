"""보안 검수 run-5 회귀 테스트. Docker 없이 돈다."""

import json

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
    assert sb.previews == 0
    assert [r["event"] for r in box.audit.list()] == ["tool_blocked"]
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
