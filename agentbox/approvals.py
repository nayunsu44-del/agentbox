"""승인 큐 (AP-1). 감사 로그와 같은 SQLite 파일에 둔다.

승인 화면에는 에이전트가 쓴 설명을 보여주지 않는다. 에이전트는 거짓말을 할 수 있다.
그래서 여기에는 시스템이 직접 본 것만 저장한다: 실제 명령, 작업 폴더, 맞은 규칙, 시스템이 계산한 영향 파일.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    sandbox_id   TEXT NOT NULL,
    tool         TEXT NOT NULL,
    args         TEXT NOT NULL,
    rule_id      TEXT,
    rule_reason  TEXT,
    preview      TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    decided_at   TEXT,
    decided_by   TEXT,
    snapshot_id  TEXT,
    result       TEXT
);
"""

PENDING, APPROVED, DENIED, EXECUTED, FAILED = "pending", "approved", "denied", "executed", "failed"
EXPIRED = "expired"   # AP-1: 기한 안에 결정이 없어 거부로 끝남


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ApprovalStore:
    def __init__(self, path: Path | str):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.executescript(SCHEMA)

    def create(self, *, sandbox_id: str, tool: str, args: dict[str, Any], rule_id: str | None,
               rule_reason: str | None, preview: dict[str, Any]) -> dict[str, Any]:
        aid = "apr_" + secrets.token_hex(6)
        with self._lock:
            self.conn.execute(
                "INSERT INTO approvals (id, sandbox_id, tool, args, rule_id, rule_reason, preview, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (aid, sandbox_id, tool, json.dumps(args, ensure_ascii=False), rule_id, rule_reason,
                 json.dumps(preview, ensure_ascii=False), PENDING, _now()),
            )
        return self.get(aid)  # type: ignore[return-value]

    def get(self, aid: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM approvals WHERE id = ?", (aid,)).fetchone()
            cols = [d[0] for d in self.conn.execute("SELECT * FROM approvals LIMIT 0").description]
        return self._row(cols, r) if r else None

    def list(self, status: str | None = None, sandbox_id: str | None = None) -> list[dict[str, Any]]:
        q, a = "SELECT * FROM approvals WHERE 1=1", []
        if status:
            q += " AND status = ?"
            a.append(status)
        if sandbox_id:
            q += " AND sandbox_id = ?"
            a.append(sandbox_id)
        q += " ORDER BY created_at"
        with self._lock:
            cur = self.conn.execute(q, a)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return [self._row(cols, r) for r in rows]

    def claim(self, aid: str, decision: str, by: str) -> bool:
        """pending인 것만 결정할 수 있다. 두 번 결정되지 않도록 원자적으로 바꾼다."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = ?",
                (decision, _now(), by, aid, PENDING),
            )
            return cur.rowcount == 1

    def finish(self, aid: str, status: str, result: dict[str, Any], snapshot_id: str | None = None,
               args: dict[str, Any] | None = None, preview: dict[str, Any] | None = None) -> None:
        """끝난 요청의 상태와 결과를 남긴다. args·preview를 주면 그것으로 바꾼다 (줄인 원본)."""
        dump = (lambda v: None if v is None else json.dumps(v, ensure_ascii=False))
        with self._lock:
            self.conn.execute(
                "UPDATE approvals SET status = ?, result = ?, snapshot_id = COALESCE(?, snapshot_id),"
                " args = COALESCE(?, args), preview = COALESCE(?, preview) WHERE id = ?",
                (status, json.dumps(result, ensure_ascii=False), snapshot_id, dump(args), dump(preview), aid),
            )

    @staticmethod
    def _row(cols: list[str], r: tuple) -> dict[str, Any]:
        d = dict(zip(cols, r))
        for k in ("args", "preview", "result"):
            if d.get(k):
                d[k] = json.loads(d[k])
        return d
