"""감사·승인 행 정리 (보안 검수 run-4 N2 2단계). Docker 없이 돈다."""

import gzip
import sqlite3
import time
from datetime import datetime, timezone

import pytest

from agentbox.approvals import ApprovalStore
from agentbox.audit import AuditLog, read_archive
from agentbox.retention import prune


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _log(db, n, start=0):
    log = AuditLog(db)
    for i in range(n):
        log.append(actor="system", event="e", payload={"i": start + i})
    return log


def _cut(db, n_old, n_new):
    """n_old개를 쓰고 기준 시각을 잡은 뒤 n_new개를 더 쓴다."""
    log = _log(db, n_old)
    time.sleep(0.01)
    cut = _now()
    time.sleep(0.01)
    for i in range(n_new):
        log.append(actor="system", event="e", payload={"i": n_old + i})
    return log, cut


def test_prune_moves_old_rows_and_verify_continues_from_anchor(tmp_path):
    db = tmp_path / "a.db"
    log, cut = _cut(db, 5, 3)
    s = prune(db, cut, tmp_path / "1.jsonl.gz")
    assert s["pruned"] and s["audit_rows"] == 5 and (s["first_id"], s["last_id"]) == (1, 5)
    rows = log.list()
    assert [r["id"] for r in rows] == [6, 7, 8, 9] and rows[-1]["event"] == "audit_pruned"
    v = log.verify()
    assert v.ok and v.checked == 4 and v.pruned_through == 5
    head, arows, _ = read_archive(tmp_path / "1.jsonl.gz")
    assert head["audit_rows"] == 5 and [r[0] for r in arows] == [1, 2, 3, 4, 5]
    full = log.verify_archives([tmp_path / "1.jsonl.gz"])
    assert full.ok and full.checked == 9
    log.append(actor="system", event="after", payload={})
    assert log.verify().ok                                    # 정리 뒤에도 체인이 이어진다


def test_ad_hoc_delete_is_still_detected_after_prune(tmp_path):
    db = tmp_path / "a.db"
    log, cut = _cut(db, 4, 4)
    prune(db, cut, tmp_path / "1.jsonl.gz")
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER audit_no_delete")
    raw.execute("DELETE FROM audit WHERE id = 6")               # 정리 기록 없이 지움
    raw.commit()
    v = log.verify()
    assert not v.ok and v.broken_at == 7 and v.pruned_through == 4
    raw.execute("DELETE FROM audit")                             # 전부 지워도 빈 로그로 통과하지 않는다
    raw.commit()
    v = log.verify()
    assert not v.ok and v.broken_at == 5 and "하나도 없음" in v.reason
    assert not log.verify_archives([tmp_path / "1.jsonl.gz"]).ok


def test_two_prunes_and_archive_checks(tmp_path):
    db = tmp_path / "a.db"
    log, cut1 = _cut(db, 3, 2)
    prune(db, cut1, tmp_path / "1.jsonl.gz")
    time.sleep(0.01)
    cut2 = _now()
    time.sleep(0.01)
    log.append(actor="system", event="e", payload={})
    s = prune(db, cut2, tmp_path / "2.jsonl.gz")
    assert (s["first_id"], s["last_id"]) == (4, 6)               # 앞 정리 뒤의 행 + 그 정리 기록
    a1, a2 = tmp_path / "1.jsonl.gz", tmp_path / "2.jsonl.gz"
    assert log.verify().ok and log.verify().pruned_through == 6
    assert log.verify_archives([a1, a2]).ok
    assert not log.verify_archives([a2, a1]).ok                 # 순서가 틀림
    assert not log.verify_archives([a2]).ok                     # 하나 빠짐
    data = gzip.decompress(a1.read_bytes()).replace(b'"i": 1', b'"i": 9')
    a1.write_bytes(gzip.compress(data))                         # 아카이브를 고침
    v = log.verify_archives([a1, a2])
    assert not v.ok and "sha256" in v.reason


def test_prune_everything_then_append(tmp_path):
    db = tmp_path / "a.db"
    log = _log(db, 3)
    time.sleep(0.01)
    s = prune(db, _now(), tmp_path / "1.jsonl.gz")
    assert s["audit_rows"] == 3
    rows = log.list()
    assert [r["id"] for r in rows] == [4] and rows[0]["prev_hash"] == read_archive(tmp_path / "1.jsonl.gz")[1][-1][8]
    assert log.verify().ok and log.verify_archives([tmp_path / "1.jsonl.gz"]).checked == 4


def test_prune_takes_finished_approvals_and_keeps_pending(tmp_path):
    db = tmp_path / "a.db"
    log = _log(db, 1)
    store = ApprovalStore(db)
    mk = lambda: store.create(sandbox_id="sb", tool="exec", args={"command": "rm x"}, rule_id="r",
                              rule_reason="x", preview={})
    done, pending, running = mk(), mk(), mk()
    store.claim(done["id"], "denied", "human")
    store.finish(done["id"], "denied", {"message": "no"})
    store.claim(running["id"], "approved", "human")
    time.sleep(0.01)
    s = prune(db, _now(), tmp_path / "1.jsonl.gz")
    assert s["approval_rows"] == 1
    assert {a["id"] for a in store.list()} == {pending["id"], running["id"]}
    assert [a["id"] for a in read_archive(tmp_path / "1.jsonl.gz")[2]] == [done["id"]]
    assert log.verify_archives([tmp_path / "1.jsonl.gz"]).ok


def test_prune_refuses_and_leaves_everything(tmp_path):
    db = tmp_path / "a.db"
    log, cut = _cut(db, 3, 1)
    (tmp_path / "x.jsonl.gz").write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        prune(db, cut, tmp_path / "x.jsonl.gz")
    assert (tmp_path / "x.jsonl.gz").read_bytes() == b"keep"
    with pytest.raises(ValueError):
        prune(db, "2999-01-01", tmp_path / "y.jsonl.gz")         # 미래 시각은 오타일 것
    s = prune(db, cut, tmp_path / "z.jsonl.gz", dry_run=True)
    assert s["audit_rows"] == 3 and not s["pruned"] and not (tmp_path / "z.jsonl.gz").exists()
    assert len(log.list()) == 4 and log.verify().pruned_through is None


def test_cli_prune_and_verify_with_archive(tmp_path, monkeypatch, capsys):
    from agentbox.cli import main
    db = tmp_path / "a.db"
    _, cut = _cut(db, 3, 1)
    monkeypatch.setenv("AGENTBOX_DB", str(db))
    main(["prune", "--before", cut, "--archive", str(tmp_path / "1.jsonl.gz")])
    assert "감사 행 3개 (#1~#3)" in capsys.readouterr().out
    main(["verify", "--archive", str(tmp_path / "1.jsonl.gz")])
    assert "항목 5개 모두 확인" in capsys.readouterr().out
    time.sleep(0.01)
    with pytest.raises(SystemExit):                              # 있는 아카이브는 덮어쓰지 않는다
        main(["prune", "--before", _now(), "--archive", str(tmp_path / "1.jsonl.gz")])


class _CommitThenInterrupt(sqlite3.Connection):
    """COMMIT은 실제로 하고, 끝나자마자 Ctrl-C가 온 것처럼 KeyboardInterrupt를 던진다."""

    def execute(self, sql, *a):
        cur = super().execute(sql, *a)
        if sql == "COMMIT":
            raise KeyboardInterrupt
        return cur


def test_interrupt_after_commit_keeps_archive(tmp_path, monkeypatch):
    # 보안 검수 run-5: 지운 뒤 COMMIT 직후의 Ctrl-C가 유일한 사본인 아카이브를 지웠다
    import types

    from agentbox import retention
    db = tmp_path / "a.db"
    log, cut = _cut(db, 5, 2)
    shim = types.SimpleNamespace(connect=lambda *a, **k: sqlite3.connect(*a, factory=_CommitThenInterrupt, **k),
                                 Error=sqlite3.Error, Connection=sqlite3.Connection)
    monkeypatch.setattr(retention, "sqlite3", shim)
    arc = tmp_path / "1.jsonl.gz"
    with pytest.raises(KeyboardInterrupt):
        prune(db, cut, arc)
    assert arc.exists()
    assert log.verify().ok
    assert AuditLog(db).verify_archives([arc]).ok


def test_failed_archive_write_leaves_no_partial_file(tmp_path, monkeypatch):
    from agentbox import retention
    db = tmp_path / "a.db"
    log, cut = _cut(db, 5, 2)

    def boom(path, *a):
        path.write_bytes(b"partial")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(retention, "_write_archive", boom)
    arc = tmp_path / "1.jsonl.gz"
    with pytest.raises(OSError):
        prune(db, cut, arc)
    assert not arc.exists()
    assert len(log.list()) == 7
