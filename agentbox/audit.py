"""해시 체인 감사 로그 (AU-1 ~ AU-4).

- 모든 항목은 직전 항목의 해시를 포함해 SHA-256으로 묶인다.
- 테이블은 추가 전용이다. UPDATE·DELETE는 트리거가 막는다.
- 기록이 실행보다 먼저다. append()가 실패하면 호출자는 실행하지 않는다.
- verify()는 체인을 처음부터 다시 계산해 처음 깨진 지점을 돌려준다.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    sandbox_id  TEXT,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,
    tool        TEXT,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

# AU-4 비밀값 가림. 값만 *** 로 바꾸고 이름은 남긴다. 등록된 토큰은 register_secret()으로 추가.
# 에이전트가 정한 긴 문자열에도 선형으로 돌게, 이름 길이를 제한하고 왼쪽 끝을 고정한다.
#
# 1) 이름=값: 이름에 비밀 낱말이 있으면 값을 가린다.
#    DB_PASSWORD=…, GITHUB_TOKEN=…, "api_key": "…", password='…', --client-secret …, X-Api-Key: …
_SECRET_NAME = re.compile(
    r"(?i)passw(?:or)?d|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"
    r"|(?:^|[_.-])key$")
_VALUE = r"""(?:"(?:[^"\\\n]|\\.)*"?|'[^'\n]*'?|[^\s'"&;,|)]+)"""   # 닫히지 않은 따옴표도 줄 끝까지
_ASSIGN = re.compile(r"""(?<![\w.-])([\w.-]{1,100})(["'\]]{0,2}\s*[=:]\s*)(""" + _VALUE + ")")
_FLAG = re.compile(r"(?<![\w-])(--?[\w-]{1,100})(\s+)(" + _VALUE + ")")
# 2) 이름 없이 모양으로 아는 것
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]{0,40}PRIVATE KEY-----|[\s\S]*)")
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,20}://[^\s:/@]{1,100}):[^\s@/]{1,200}@")
_USER_PASS_FLAG = re.compile(r"(?<![\w-])(-u|--user)(\s+|=)([^\s:'\"]{1,100}):[^\s'\"]+")   # curl -u user:pass
_AUTH_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*)(?:(?:bearer|basic|token|digest)\s+)?[^\s'\"]+")
_TOKENS = [
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),                      # OpenAI·Anthropic
    re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),        # Stripe
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                 # AWS 키 ID
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),                   # GitLab
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),               # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),                      # Google API
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),   # JWT
    re.compile(r"\b(agt|hum)_[A-Za-z0-9_\-]{16,}"),
]


def _hide_named(m: re.Match) -> str:
    name, sep, val = m.groups()
    if not _SECRET_NAME.search(name.lstrip("-")):
        return m.group(0)
    q = val[0] if val[:1] in ("'", '"') else ""
    return f"{name}{sep}{q}***{q}"


def mask_text(text: str) -> str:
    text = _PRIVATE_KEY.sub("-----PRIVATE KEY ***-----", text)
    text = _URL_CRED.sub(r"\1:***@", text)
    text = _USER_PASS_FLAG.sub(r"\1\2\3:***", text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + "***", text)
    for pat in _TOKENS:
        text = pat.sub("***", text)
    text = _FLAG.sub(_hide_named, text)
    return _ASSIGN.sub(_hide_named, text)


class AuditWriteError(RuntimeError):
    """감사 기록 실패. 이 예외가 나면 도구 호출을 실행하지 않는다."""


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checked": self.checked, "broken_at": self.broken_at, "reason": self.reason}


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def compute_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + b"\n" + _canonical(record)).hexdigest()


def _row(r: tuple) -> dict[str, Any]:
    return {
        "id": r[0], "ts": r[1], "sandbox_id": r[2], "actor": r[3], "event": r[4],
        "tool": r[5], "payload": json.loads(r[6]), "prev_hash": r[7], "hash": r[8],
    }


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._secrets: set[str] = set()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    # ---- 비밀값 가림 -------------------------------------------------
    def register_secret(self, value: str) -> None:
        if value and len(value) >= 8:
            self._secrets.add(value)

    def _mask(self, value: Any) -> Any:
        if isinstance(value, str):
            out = value
            for s in self._secrets:
                out = out.replace(s, "***")
            return mask_text(out)
        if isinstance(value, dict):
            return {k: self._mask(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._mask(v) for v in value]
        return value

    # ---- 기록 ---------------------------------------------------------
    def append(
        self,
        *,
        actor: str,
        event: str,
        sandbox_id: str | None = None,
        tool: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> int:
        """한 항목을 기록하고 id를 돌려준다. 실패하면 AuditWriteError."""
        payload = self._mask(payload or {})
        try:
            with self._lock:
                self.conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self.conn.execute("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
                    prev_hash = row[1] if row else GENESIS
                    new_id = (row[0] + 1) if row else 1
                    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                    record = {
                        "id": new_id,
                        "ts": ts,
                        "sandbox_id": sandbox_id,
                        "actor": actor,
                        "event": event,
                        "tool": tool,
                        "payload": payload,
                    }
                    h = compute_hash(prev_hash, record)
                    self.conn.execute(
                        "INSERT INTO audit (id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (new_id, ts, sandbox_id, actor, event, tool,
                         json.dumps(payload, ensure_ascii=False, sort_keys=True), prev_hash, h),
                    )
                    self.conn.execute("COMMIT")
                    return new_id
                except BaseException:
                    try:
                        self.conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
        except sqlite3.Error as e:
            raise AuditWriteError(f"감사 로그 기록 실패: {e}") from e

    # ---- 조회·검증 ----------------------------------------------------
    def list(self, sandbox_id: str | None = None, limit: int = 500, after_id: int = 0) -> list[dict[str, Any]]:
        q = "SELECT id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash FROM audit WHERE id > ?"
        args: list[Any] = [after_id]
        if sandbox_id:
            q += " AND sandbox_id = ?"
            args.append(sandbox_id)
        q += " ORDER BY id LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self.conn.execute(q, args).fetchall()
        return [_row(r) for r in rows]

    def recent(self, sandbox_id: str | None = None, limit: int = 400) -> tuple[list[dict[str, Any]], int]:
        """최신 limit개(새것부터)와 같은 조건의 실제 전체 개수. list()는 오래된 것부터라 화면용으로 못 쓴다."""
        where, args = (" WHERE sandbox_id = ?", [sandbox_id]) if sandbox_id else ("", [])
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM audit" + where, args).fetchone()[0]
            rows = self.conn.execute(
                "SELECT id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash FROM audit" + where
                + " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()
        return [_row(r) for r in rows], total

    def belongs_to(self, rid: int, sandbox_id: str) -> bool:
        with self._lock:
            return self.conn.execute("SELECT 1 FROM audit WHERE id = ? AND sandbox_id = ?",
                                     (rid, sandbox_id)).fetchone() is not None

    def verify(self) -> VerifyResult:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, ts, sandbox_id, actor, event, tool, payload, prev_hash, hash FROM audit ORDER BY id"
            ).fetchall()
        prev = GENESIS
        expected_id = 1
        for i, r in enumerate(rows):
            rid = r[0]
            if rid != expected_id:
                return VerifyResult(False, i, rid, f"id가 {expected_id} 다음에 {rid}로 건너뜀 (항목 삭제 의심)")
            if r[7] != prev:
                return VerifyResult(False, i, rid, "prev_hash가 직전 항목의 해시와 다름")
            try:
                payload = json.loads(r[6])
            except json.JSONDecodeError:
                return VerifyResult(False, i, rid, "payload를 읽을 수 없음")
            record = {
                "id": rid, "ts": r[1], "sandbox_id": r[2], "actor": r[3],
                "event": r[4], "tool": r[5], "payload": payload,
            }
            if compute_hash(prev, record) != r[8]:
                return VerifyResult(False, i, rid, "내용이 기록 당시와 다름 (해시 불일치)")
            prev = r[8]
            expected_id += 1
        return VerifyResult(True, len(rows))
