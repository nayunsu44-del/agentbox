"""오래된 감사·승인 행 덜어내기 (보안 검수 run-4 N2).

감사 로그는 추가 전용이라 그대로 두면 디스크를 끝없이 차지한다. 그렇다고 오래된 행만 지우면 verify()가 영구히
실패하고, 전부 지우면 빈 로그가 통과해 몰래 지운 것과 구분되지 않는다. 그래서 운영자만 호스트에서 명령으로 정리한다:

1. 기준 시각보다 오래된 앞쪽 감사 행과, 끝난 승인 행을 아카이브 파일(gzip JSON Lines)로 먼저 내보낸다.
2. 한 트랜잭션에서 그 행들을 지우고, 지운 마지막 행의 id·해시와 아카이브 sha256을 기준점(audit_anchor)으로 남긴다.
3. 같은 트랜잭션에서 정리했다는 사실을 감사 로그에 한 줄 남긴다 (audit_pruned). 그래서 기준점이 있는데
   표가 비어 있으면 verify()가 실패한다.

verify()는 기준점부터 검사하고, verify_archives()는 아카이브들과 지금 표를 처음부터 이어 검사한다.
HTTP API로는 열지 않는다. DB 파일을 직접 다룰 수 있는 사람(호스트 운영자)만 정리할 수 있다.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import approvals as A
from .approvals import ApprovalStore
from .audit import (
    ARCHIVE_FORMAT,
    AUDIT_COLUMNS,
    GENESIS,
    NO_DELETE_SQL,
    NO_DELETE_TRIGGER,
    AuditLog,
    bound_payload,
    insert_record,
    latest_anchor,
)

# 아직 끝나지 않은 승인(대기, 실행 중)은 남긴다
_DONE = (A.DENIED, A.EXECUTED, A.FAILED, A.EXPIRED)


def _cutoff(before: str) -> str:
    """'2026-07-01'이나 ISO 시각을 저장 형식(UTC, 밀리초)으로. 시간대가 없으면 UTC로 본다."""
    t = datetime.fromisoformat(before)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    if t > datetime.now(timezone.utc):
        raise ValueError(f"기준 시각이 미래임: {before}")
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _plan(conn: sqlite3.Connection, cutoff: str) -> tuple[list[tuple], list[dict[str, Any]]]:
    """지울 감사 행(앞에서부터, 기준 시각 이후 행이 처음 나오기 전까지)과 끝난 승인 행."""
    first_new = conn.execute("SELECT MIN(id) FROM audit WHERE ts >= ?", (cutoff,)).fetchone()[0]
    q, args = f"SELECT {AUDIT_COLUMNS} FROM audit", []
    if first_new is not None:
        q, args = q + " WHERE id < ?", [first_new]
    rows = conn.execute(q + " ORDER BY id", args).fetchall()
    cur = conn.execute(f"SELECT * FROM approvals WHERE created_at < ? AND status IN ({','.join('?' * len(_DONE))})"
                       " ORDER BY created_at", (cutoff, *_DONE))
    cols = [d[0] for d in cur.description]
    return rows, [dict(zip(cols, r)) for r in cur.fetchall()]


def _write_archive(path: Path, cutoff: str, rows: list[tuple], approvals: list[dict[str, Any]]) -> str:
    """아카이브를 새 파일로 쓰고 디스크에 내린 뒤 sha256을 돌려준다. 이미 있으면 덮어쓰지 않는다."""
    names = AUDIT_COLUMNS.split(", ")
    with open(path, "xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            def put(d: dict[str, Any]) -> None:
                gz.write(json.dumps(d, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
            put({"kind": "header", "format": ARCHIVE_FORMAT, "before": cutoff,
                 "created": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                 "audit_rows": len(rows), "approval_rows": len(approvals),
                 "first_id": rows[0][0] if rows else None, "last_id": rows[-1][0] if rows else None})
            for r in rows:
                put({"kind": "audit", **dict(zip(names, r))})
            for a in approvals:
                put({"kind": "approval", **a})
        raw.flush()
        os.fsync(raw.fileno())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prune(db_path: Path | str, before: str, archive: Path | str, dry_run: bool = False) -> dict[str, Any]:
    """before보다 오래된 감사·승인 행을 archive로 옮긴다. 돌려주는 값은 정리 요약."""
    cutoff = _cutoff(before)
    archive = Path(archive)
    conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=30)
    try:
        AuditLog(db_path).conn.close()   # 기준점 표가 없는 옛 DB면 만든다 (승인 표도)
        ApprovalStore(db_path).conn.close()
        rows, approvals = _plan(conn, cutoff)
        summary = {"before": cutoff, "audit_rows": len(rows), "approval_rows": len(approvals),
                   "first_id": rows[0][0] if rows else None, "last_id": rows[-1][0] if rows else None,
                   "archive": str(archive)}
        if dry_run or not (rows or approvals):
            return summary | {"pruned": False}
        if archive.exists():
            raise FileExistsError(f"아카이브 파일이 이미 있음: {archive}")
        # 감사 행은 바뀌지 않으니(추가 전용) 잠금 밖에서 내보낸다. 서버의 기록이 그동안 막히지 않게.
        try:
            sha = _write_archive(archive, cutoff, rows, approvals)
        except BaseException:
            archive.unlink(missing_ok=True)   # 쓰다 만 파일이 남으면 다시 실행할 때 FileExistsError가 난다
            raise
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                anchor = latest_anchor(conn)
                first = conn.execute("SELECT MIN(id) FROM audit").fetchone()[0]
                if rows and (first != rows[0][0] or (anchor and anchor[0] + 1 != first)):
                    raise RuntimeError("그사이 다른 정리가 있었음. 다시 실행할 것")
                if rows:
                    conn.execute(f"DROP TRIGGER {NO_DELETE_TRIGGER}")
                    conn.execute("DELETE FROM audit WHERE id <= ?", (rows[-1][0],))
                    conn.execute(NO_DELETE_SQL)
                # 승인만 덜어낸 정리도 아카이브마다 기준점을 하나 남긴다 (verify_archives가 하나씩 맞춰 본다)
                last = (rows[-1][0], rows[-1][8]) if rows else (anchor or (0, GENESIS))
                conn.execute("INSERT INTO audit_anchor (ts, last_id, last_hash, rows, archive, archive_sha256)"
                             " VALUES (?,?,?,?,?,?)",
                             (datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                              last[0], last[1], len(rows), archive.name, sha))
                conn.executemany("DELETE FROM approvals WHERE id = ?", [(a["id"],) for a in approvals])
                # 정리 기록도 같은 트랜잭션에서 남긴다. 기준점이 있는데 표가 비어 있으면 누가 지운 것이다
                summary |= {"pruned": True, "archive_sha256": sha}
                insert_record(conn, "human", "audit_pruned", None, None, bound_payload(summary))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:   # COMMIT 뒤에 온 예외(Ctrl-C 등)면 되돌릴 것이 없다
                    conn.execute("ROLLBACK")
                raise
        except BaseException:
            # 지우지 못했을 때만 아카이브도 지운다 (다시 실행할 수 있게). 기준점이 이미 이 아카이브를 가리키면
            # 지운 행의 유일한 사본이니 남긴다. 확인조차 못 하면 남기는 쪽으로 (보안 검수 run-5)
            try:
                committed = conn.execute("SELECT 1 FROM audit_anchor WHERE archive = ? AND archive_sha256 = ?",
                                         (archive.name, sha)).fetchone() is not None
            except sqlite3.Error:
                committed = True
            if not committed:
                archive.unlink(missing_ok=True)
            raise
    finally:
        conn.close()
    return summary
