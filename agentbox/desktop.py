"""화면 보기·인수 (UX-1, UX-2).

- 사람은 브라우저(noVNC)로 화면을 본다. 연결마다 x11vnc를 따로 띄우고, 보기 연결은 -viewonly라
  입력이 서버에서부터 막힌다. 샌드박스는 network=none이라 VNC 포트가 없다. 컨트롤 플레인이
  docker exec의 표준 입출력과 웹소켓을 이어 준다.
- 사람이 화면을 인수(takeover)하면 그 사람 세션만 입력 연결을 열 수 있고, 에이전트의 GUI 도구는
  423으로 대기한다. 돌려주면(handback) 입력 연결을 끊고 에이전트가 다시 쓴다.
- 브라우저는 Authorization 헤더를 못 붙인다. 사람 토큰으로 받은 1회용 티켓(60초)을 세션 쿠키로 바꾼다.
  에이전트 토큰으로는 티켓을 받을 수 없다.

로그인 세션, 1회용 티켓, 인수 상태는 SQLite에 둔다. 쿠키와 티켓 값은 SHA-256 해시로만 저장한다.
서버를 다시 띄우면 로그인은 유지되고, 지난 실행에서 돌려주지 않은 인수는 서비스가 server_restart로
기록하고 정리한다(화면 연결은 재시작으로 끊기므로 인수를 이어 가지 않는다).
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

COOKIE = "agentbox_session"

SCHEMA = """
CREATE TABLE IF NOT EXISTS ui_tickets (
  hash TEXT PRIMARY KEY, scope TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ui_sessions (
  hash TEXT PRIMARY KEY, public TEXT NOT NULL, created TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS takeover_leases (
  sandbox_id TEXT PRIMARY KEY, session TEXT NOT NULL, since TEXT NOT NULL, started REAL NOT NULL);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def set_cookie(response, value: str, max_age: int, secure: bool) -> None:
    """세션 쿠키. TLS 뒤에서는 Secure를 붙인다."""
    response.set_cookie(COOKIE, value, httponly=True, samesite="strict", max_age=max_age, secure=secure)


@dataclass
class Lease:
    sandbox_id: str
    session: str                 # 공개 세션 id (hs_…). 쿠키 값은 로그에 남기지 않는다.
    since: str = field(default_factory=_now_iso)
    started: float = field(default_factory=time.monotonic)
    last_active: float = field(default_factory=time.monotonic)
    client_bytes: int = 0


@dataclass
class Conn:
    id: str
    sandbox_id: str
    session: str
    mode: str                    # view | control
    close: Callable[[], None]    # 어느 스레드에서 불러도 된다


class DesktopControl:
    def __init__(self, ticket_ttl: float = 60, session_ttl: float = 12 * 3600, idle: float = 600,
                 db_path: str | Path | None = None):
        self.ticket_ttl = ticket_ttl
        self.session_ttl = session_ttl
        self.idle = idle
        self._lock = threading.Lock()
        # 만료 시각은 재시작을 넘어가야 하므로 벽시계(time.time)로 둔다.
        self._db = sqlite3.connect(str(db_path) if db_path else ":memory:", check_same_thread=False,
                                   isolation_level=None)
        self._db.executescript(SCHEMA)
        now = time.time()
        self._db.execute("DELETE FROM ui_tickets WHERE expires < ?", (now,))
        self._db.execute("DELETE FROM ui_sessions WHERE expires < ?", (now,))
        self._leases: dict[str, Lease] = {}
        self._gui: dict[str, threading.Lock] = {}
        self._conns: dict[str, Conn] = {}

    # ---- 티켓과 세션 ---------------------------------------------------
    def issue_ticket(self, sid: str) -> str:
        t = "tkt_" + secrets.token_urlsafe(24)
        with self._lock:
            self._db.execute("INSERT INTO ui_tickets VALUES (?, ?, ?)", (_h(t), sid, time.time() + self.ticket_ttl))
        return t

    def redeem(self, ticket: str, sid: str) -> tuple[str, str] | None:
        """1회용. 맞으면 (쿠키 값, 공개 세션 id). 웹 UI 로그인 티켓은 sid가 '*'이다."""
        with self._lock:
            row = self._db.execute("SELECT scope, expires FROM ui_tickets WHERE hash = ?", (_h(ticket),)).fetchone()
            if not row:
                return None
            self._db.execute("DELETE FROM ui_tickets WHERE hash = ?", (_h(ticket),))
            if row[0] != sid or row[1] < time.time():
                return None
        return self.new_session()

    def new_session(self) -> tuple[str, str]:
        cookie = secrets.token_urlsafe(32)
        public = "hs_" + secrets.token_hex(4)
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM ui_sessions WHERE expires < ?", (now,))
            self._db.execute("INSERT INTO ui_sessions VALUES (?, ?, ?, ?)",
                             (_h(cookie), public, _now_iso(), now + self.session_ttl))
        return cookie, public

    def end_session(self, cookie: str | None) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT public FROM ui_sessions WHERE hash = ?", (_h(cookie or ""),)).fetchone()
            self._db.execute("DELETE FROM ui_sessions WHERE hash = ?", (_h(cookie or ""),))
        return row[0] if row else None

    def session(self, cookie: str | None) -> str | None:
        if not cookie:
            return None
        with self._lock:
            row = self._db.execute("SELECT public, expires FROM ui_sessions WHERE hash = ?", (_h(cookie),)).fetchone()
            if not row:
                return None
            if row[1] < time.time():
                self._db.execute("DELETE FROM ui_sessions WHERE hash = ?", (_h(cookie),))
                return None
            return row[0]

    # ---- 인수 상태 -----------------------------------------------------
    def gui_lock(self, sid: str) -> threading.Lock:
        """GUI 도구 실행과 인수·반환이 서로 겹치지 않게 한다."""
        with self._lock:
            return self._gui.setdefault(sid, threading.Lock())

    def lease(self, sid: str) -> Lease | None:
        with self._lock:
            return self._leases.get(sid)

    def is_stale(self, sid: str) -> bool:
        """인수한 사람이 입력 연결 없이 idle초 넘게 지났는가 (창을 닫고 돌려주지 않은 경우)."""
        with self._lock:
            lease = self._leases.get(sid)
            if not lease:
                return False
            if any(c.sandbox_id == sid and c.mode == "control" for c in self._conns.values()):
                return False
            return time.monotonic() - lease.last_active > self.idle

    def take(self, sid: str, session: str) -> Lease:
        with self._lock:
            cur = self._leases.get(sid)
            if cur and cur.session != session:
                raise PermissionError(f"다른 사람 세션({cur.session})이 이미 조작 중")
            if cur:
                return cur
            lease = self._leases[sid] = Lease(sid, session)
            self._db.execute("INSERT OR REPLACE INTO takeover_leases VALUES (?, ?, ?, ?)",
                             (sid, session, lease.since, time.time()))
            return lease

    def release(self, sid: str) -> Lease | None:
        with self._lock:
            lease = self._leases.pop(sid, None)
            self._db.execute("DELETE FROM takeover_leases WHERE sandbox_id = ?", (sid,))
            conns = [c for c in self._conns.values() if c.sandbox_id == sid and c.mode == "control"]
        for c in conns:
            c.close()
        return lease

    def state(self, sid: str, session: str | None = None) -> dict[str, Any]:
        lease = self.lease(sid)
        out: dict[str, Any] = {"sandbox_id": sid, "controller": "human" if lease else "agent"}
        if lease:
            out["since"] = lease.since
            if session is not None:
                out["mine"] = lease.session == session
        return out

    def close(self) -> None:
        self._db.close()

    def leftover_leases(self) -> list[dict[str, Any]]:
        """지난 실행에서 돌려주지 않은 인수 (이번 실행의 메모리에는 없는 것)."""
        with self._lock:
            rows = self._db.execute("SELECT sandbox_id, session, since, started FROM takeover_leases").fetchall()
            return [{"sandbox_id": r[0], "session": r[1], "since": r[2], "started": r[3]}
                    for r in rows if r[0] not in self._leases]

    def forget_lease(self, sid: str) -> None:
        with self._lock:
            if sid not in self._leases:
                self._db.execute("DELETE FROM takeover_leases WHERE sandbox_id = ?", (sid,))

    # ---- 화면 연결 -----------------------------------------------------
    def may_connect(self, sid: str, session: str, mode: str) -> bool:
        if mode == "view":
            return True
        lease = self.lease(sid)
        return bool(lease and lease.session == session)

    def add_conn(self, sid: str, session: str, mode: str, close: Callable[[], None]) -> Conn:
        c = Conn("vc_" + secrets.token_hex(4), sid, session, mode, close)
        with self._lock:
            self._conns[c.id] = c
        self.touch(sid)
        return c

    def drop_conn(self, conn: Conn) -> None:
        with self._lock:
            self._conns.pop(conn.id, None)
            lease = self._leases.get(conn.sandbox_id)
            if lease and conn.mode == "control" and lease.session == conn.session:
                lease.last_active = time.monotonic()

    def touch(self, sid: str, client_bytes: int = 0) -> None:
        """입력 연결에서 받은 바이트를 바로 더한다 (돌려줄 때 기록에 들어가도록)."""
        with self._lock:
            lease = self._leases.get(sid)
            if lease:
                lease.last_active = time.monotonic()
                lease.client_bytes += client_bytes

    def close_all(self, sid: str) -> None:
        with self._lock:
            conns = [c for c in self._conns.values() if c.sandbox_id == sid]
            self._leases.pop(sid, None)
            self._db.execute("DELETE FROM takeover_leases WHERE sandbox_id = ?", (sid,))
        for c in conns:
            c.close()


PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>agentbox __SID__ 화면</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<style>
  body { margin: 0; font-family: system-ui, sans-serif; background: #1e1e1e; color: #eee; }
  header { display: flex; gap: 10px; align-items: center; padding: 8px 12px; background: #2b2b2b; height: 30px; }
  .badge { padding: 3px 8px; border-radius: 4px; background: #444; font-size: 13px; }
  .warn { background: #a33; } .human { background: #b85c00; } .agent { background: #1f6b3a; }
  #screen { width: 100vw; height: calc(100vh - 46px); }
  button { font-size: 14px; padding: 4px 12px; cursor: pointer; }
  #msg { color: #f99; font-size: 13px; }
</style></head>
<body>
<header>
  <b>__SID__</b>
  <span class="badge">격리: __RUNTIME__</span>
  __RUNC_WARNING__
  <span id="ctl" class="badge">…</span>
  <button id="take" hidden>화면 인수</button>
  <button id="give" hidden>돌려주기</button>
  <span id="msg"></span>
</header>
<div id="screen"></div>
<script type="module">
import RFB from "/static/novnc/core/rfb.js";
const base = "/sandboxes/__SID__/desktop";
const $ = (id) => document.getElementById(id);
let rfb = null, mode = null;

function connect(m) {
  if (rfb) { const old = rfb; old.__closing = true; if (!old.__dead) old.disconnect(); }
  mode = m;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const r = new RFB($("screen"), proto + "://" + location.host + base + "/ws?mode=" + m, { wsProtocols: ["binary"] });
  r.viewOnly = m !== "control";
  r.scaleViewport = true;
  // 서버가 끊은 경우만 다시 붙는다. 그 사이 다른 연결로 바뀌었으면(인수·반환) 아무것도 하지 않는다.
  r.addEventListener("disconnect", () => {
    r.__dead = true;
    if (!r.__closing) setTimeout(() => { if (rfb === r) refresh(true); }, 1500);
  });
  rfb = r;
}

async function refresh(reconnect) {
  const res = await fetch(base + "/state", { credentials: "same-origin" });
  if (!res.ok) { $("msg").textContent = "상태 확인 실패 (" + res.status + "). 링크를 다시 받을 것."; return; }
  const s = await res.json();
  const mine = s.controller === "human" && s.mine;
  $("ctl").textContent = s.controller === "agent" ? "에이전트 조작 중 · 보기 전용"
    : mine ? "내가 조작 중 · 에이전트 GUI 도구 대기" : "다른 사람이 조작 중";
  $("ctl").className = "badge " + s.controller;
  $("take").hidden = s.controller === "human";
  $("give").hidden = !mine;
  const want = mine ? "control" : "view";
  if (reconnect || mode !== want) connect(want);
}

async function post(path) {
  const res = await fetch(base + path, { method: "POST", credentials: "same-origin" });
  $("msg").textContent = res.ok ? "" : ((await res.json()).detail || res.status);
  await refresh(false);
}
$("take").onclick = () => post("/takeover");
$("give").onclick = () => post("/handback");
setInterval(() => refresh(false), 3000);
refresh(true);
</script>
</body></html>
"""


def page(sid: str, runtime: str) -> str:
    warn = '<span class="badge warn">runc: 개발 전용 (격리 약함)</span>' if runtime == "runc" else ""
    return PAGE.replace("__SID__", sid).replace("__RUNTIME__", runtime).replace("__RUNC_WARNING__", warn)
