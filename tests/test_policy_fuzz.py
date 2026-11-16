"""exec 허용 목록 차등 퍼저 (정책 대 실제 bash). 하니스는 tests/policy_fuzz.py.

정해진 씨앗으로 짧게 돌린다. 수를 늘리려면 AGENTBOX_FUZZ_EXECUTED, 씨앗은 AGENTBOX_FUZZ_SEED.
Docker는 쓰지 않는다. bash만 있으면 된다.
"""
import os
import shutil

import pytest

from agentbox.policy import Policy
from tests.policy_fuzz import DEFAULT_POLICY, Harness, allowed, allowlist_of, fuzz

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash가 없음")

POLICY = Policy.load(DEFAULT_POLICY)


@pytest.fixture(scope="module")
def harness():
    with Harness(allowlist_of(POLICY)) as h:
        yield h


# 하니스가 위반을 실제로 잡는지 먼저 본다. 정책이 댄 목록을 일부러 좁게(또는 틀리게) 준다.
@pytest.mark.parametrize("cmd,claimed,unclaimed", [
    ("ls ; chmod 777 x", {"ls"}, ["chmod"]),
    ("pwd;</dev/null sh -c id", {"pwd"}, ["sh"]),
    ("ls | ( cat && ./ls )", {"ls", "cat"}, ["./ls"]),
    ("ls2>&1", {"ls"}, ["ls2"]),
    ("/bin/ls & /bin/../bin/true", {"ls"}, ["/bin/../bin/true"]),
])
def test_harness_sees_programs_the_policy_did_not_name(harness, cmd, claimed, unclaimed):
    res = harness.run(cmd, claimed)
    assert res.unclaimed == unclaimed and res.violation


@pytest.mark.parametrize("cmd,claimed", [
    ("echo x > out", {"echo"}),
    ("echo x >> f", {"echo"}),                 # 있던 파일에 덧붙임
    ("true > CLAUDE.md", {"true"}),            # 있던 파일을 비움
    ("mkdir 9~ ; echo x >&9~/../new", {"mkdir", "echo"}),    # fd 복제처럼 보이는 파일 리다이렉션
])
def test_harness_sees_writes(harness, cmd, claimed):
    res = harness.run(cmd, claimed)
    assert res.writes and not res.unclaimed


@pytest.mark.parametrize("cmd,claimed", [
    ("ls -l a | wc -l && cat < a.txt", {"ls", "wc", "cat"}),
    ("echo x >&2 ; /bin/ls 2>/dev/null", {"echo", "ls"}),
    ("touch new ; mkdir -p d/e ; cd d && pwd", {"touch", "mkdir", "cd", "pwd"}),   # 빈 파일·폴더는 허용된 일
    ("echo 'a b' \"c\" | head -1", {"echo", "head"}),
])
def test_harness_accepts_honest_commands(harness, cmd, claimed):
    res = harness.run(cmd, claimed)
    assert not res.violation, res.describe()
    assert allowed(POLICY, cmd) == claimed


def test_policy_and_bash_agree_on_allowed_commands():
    n = int(os.environ.get("AGENTBOX_FUZZ_EXECUTED", "400"))
    seed = int(os.environ.get("AGENTBOX_FUZZ_SEED", "20261116"))
    s = fuzz(POLICY, seed=seed, executed=n)
    assert s.executed == n, f"허용된 명령이 {s.executed}개뿐이다 (만든 명령 {s.generated}개)"
    assert not s.violations, "\n".join(r.describe() for r in s.violations[:10])
