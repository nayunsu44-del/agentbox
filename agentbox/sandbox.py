"""샌드박스 관리 (SB-1, SB-2, SB-3, SB-4, SB-5, SB-6, TL-1, TL-2).

- 컨테이너 1개 = 샌드박스 1개. 네트워크는 none.
- 원본 폴더는 /source에 읽기 전용으로 붙고, 시작할 때 /workspace로 복사된다.
- /workspace는 컨테이너 자체 레이어에 있다. 그래야 docker commit 스냅샷에 들어간다.
- 에이전트 명령은 uid 1000, no-new-privileges, 능력(capability) 최소화 상태로 돈다.
- 데스크톱 템플릿은 X 서버를 desktop 계정(uid 1001)으로 띄운다. GUI 도구와 화면 보기만
  그 계정으로 돌고, 에이전트의 exec는 X 쿠키를 읽을 수 없어 화면에 붙지 못한다.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import re
import secrets
import shlex
import sqlite3
import struct
import tarfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from .config import Settings, Template

AGENT_UID = "1000:1000"
WORKSPACE = "/workspace"
SOURCE = "/source"
_OUT_LIMIT = 64 * 1024

# 데스크톱 템플릿 (images/desktop/Dockerfile과 맞춘다)
DESKTOP_USER = "desktop"
DESKTOP_ENV = {"DISPLAY": ":0", "XAUTHORITY": "/home/desktop/.Xauthority", "HOME": "/home/desktop"}
_SHOT = "/home/desktop/.cache/agentbox-shot.png"
_BUTTONS = {"left": "1", "middle": "2", "right": "3"}
_KEY_RE = re.compile(r"^[A-Za-z0-9_+]{1,40}$")
_WRITE_CHUNK = 64 * 1024     # 인자 하나의 커널 상한(128KB)보다 작게, base64 뒤 기준
OUTBOX = WORKSPACE + "/outbox"
_BAD_NAME = re.compile(r"[\x00-\x1f\x7f/\\]")


def clean_name(name: str) -> str:
    """사람이 올리거나 받는 파일 이름. 폴더 없이 이름 하나만 허용한다."""
    n = (name or "").strip()
    if not n or n in (".", "..") or _BAD_NAME.search(n) or len(n.encode()) > 200:
        raise SandboxError(f"쓸 수 없는 파일 이름: {name!r}")
    return n

SCHEMA = """
CREATE TABLE IF NOT EXISTS sandboxes (
    id            TEXT PRIMARY KEY,
    container_id  TEXT NOT NULL,
    source_dir    TEXT NOT NULL,
    image         TEXT NOT NULL,
    runtime       TEXT NOT NULL,
    token_hash    TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    template      TEXT NOT NULL DEFAULT 'cli'
);
CREATE TABLE IF NOT EXISTS snapshots (
    id          TEXT PRIMARY KEY,
    sandbox_id  TEXT NOT NULL,
    image       TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL
);
"""

# 강한 격리부터 시도한다. AGENTBOX_RUNTIME으로 고정할 수 있다.
_RUNTIME_PREFERENCE = ["kata-fc", "kata-qemu-firecracker", "runsc", "runc"]


class SandboxError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _truncate(b: bytes | None, total: int | None = None) -> str:
    """total은 잘라 낸 뒤 b만 들고 있을 때의 원래 길이."""
    if not b:
        return ""
    total = len(b) if total is None else total
    s = b[:_OUT_LIMIT].decode("utf-8", errors="replace")
    if total > _OUT_LIMIT:
        s += f"\n…({total - _OUT_LIMIT} bytes 생략)"
    return s


class _Head:
    """스트림 앞쪽 _OUT_LIMIT 바이트만 들고 나머지는 세기만 한다 (컨트롤 플레인 메모리 상한)."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.total = 0

    def add(self, chunk: bytes | None) -> None:
        if not chunk:
            return
        self.total += len(chunk)
        room = _OUT_LIMIT + 1 - len(self.buf)
        if room > 0:
            self.buf += chunk[:room]

    def text(self) -> str:
        return _truncate(bytes(self.buf), self.total)


def _parse_outbox(raw: bytes) -> list[dict[str, Any]]:
    """`find -printf '%s\\t%T@\\t%f\\0'` 출력을 결과함 목록으로 바꾼다.

    레코드는 NUL로 나누고, 각 레코드는 크기·수정시각·이름 순서로 탭 둘(이름은 탭 2개 뒤 전부)이다.
    이름에 탭·줄바꿈이 들어가도 split(maxsplit=2)로 이름 안에 머문다. 숫자 변환이 깨지는 레코드는
    건너뛰어, 믿을 수 없는 컨테이너 출력이 컨트롤 플레인에서 500을 일으키지 못하게 한다.
    """
    out: list[dict[str, Any]] = []
    for rec in raw.decode("utf-8", errors="replace").split("\0"):
        if not rec:
            continue
        parts = rec.split("\t", 2)
        if len(parts) != 3:
            continue
        size, mtime, name = parts
        try:
            nbytes = int(size)
            when = datetime.fromtimestamp(float(mtime), timezone.utc).isoformat(timespec="seconds")
        except (ValueError, OverflowError, OSError):
            continue
        out.append({"name": name, "bytes": nbytes, "mtime": when})
    return sorted(out, key=lambda x: x["name"])


_MANIFEST_CAP = 8 * 1024 * 1024


def _parse_manifest(raw: bytes) -> tuple[dict[str, tuple[int, str, str]], bool]:
    """`find -printf '%P\\0%s\\0%T@\\0%C@\\0'` 출력(앞 _MANIFEST_CAP 바이트)을 {경로: (크기, mtime, ctime)}으로.
    상한에서 잘렸으면 끝의 불완전한 레코드는 버리고 truncated를 돌려준다."""
    truncated = len(raw) >= _MANIFEST_CAP
    fields = raw.decode("utf-8", errors="replace").split("\0")[:-1]  # 끝의 NUL 없는 조각은 잘린 것
    out: dict[str, tuple[int, str, str]] = {}
    for i in range(0, len(fields) - 3, 4):
        path, size, mtime, ctime = fields[i:i + 4]
        try:
            out[path] = (int(size), mtime, ctime)
        except ValueError:
            continue
    return out, truncated


def diff_manifest(old: dict[str, tuple], new: dict[str, tuple]) -> dict[str, list[str]]:
    return {"added": sorted(new.keys() - old.keys()),
            "modified": sorted(k for k in new.keys() & old.keys() if new[k] != old[k]),
            "deleted": sorted(old.keys() - new.keys())}


def safe_path(path: str) -> str:
    """에이전트가 준 경로를 /workspace 또는 /source 아래로 제한한다."""
    p = path.strip() or WORKSPACE
    if not p.startswith("/"):
        p = posixpath.join(WORKSPACE, p)
    p = posixpath.normpath(p)
    for root in (WORKSPACE, SOURCE):
        if p == root or p.startswith(root + "/"):
            return p
    raise SandboxError(f"허용되지 않은 경로: {path} (/workspace 또는 /source 아래만 가능)")


# ---------------------------------------------------------------------------
# 영향 미리보기: 승인 화면에 보여줄 '시스템이 계산한' 영향 범위
# ---------------------------------------------------------------------------

def _split_segments(command: str, depth: int = 0) -> list[list[str]]:
    """명령을 ; && || | 단위 argv 조각으로 나눈다. sh -c / bash -c 안쪽은 펼친다."""
    if depth > 3:
        return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        return [command.split()]
    segs: list[list[str]] = [[]]
    for t in tokens:
        if t and all(c in ";&|()<>" for c in t):
            segs.append([])
        else:
            segs[-1].append(t)
    out: list[list[str]] = []
    for s in segs:
        if not s:
            continue
        name = s[0].rsplit("/", 1)[-1]
        if name in ("sh", "bash", "dash", "zsh") and "-c" in s:
            i = s.index("-c")
            if i + 1 < len(s):
                out.extend(_split_segments(s[i + 1], depth + 1))
                continue
        if name in ("xargs", "sudo", "env", "nohup", "timeout", "nice") and len(s) > 1:
            out.append(s)  # 원래 조각도 남기고
            rest = s[1:]
            while rest and (rest[0].startswith("-") or re.match(r"^\w+=", rest[0]) or rest[0].isdigit()):
                rest = rest[1:]
            if rest:
                out.append(rest)
            continue
        out.append(s)
    return out


class SandboxManager:
    def __init__(self, settings: Settings, db_path: Path | str):
        self.settings = settings
        self.client = docker.from_env()
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(sandboxes)")}
        if "template" not in cols:  # M1에서 만든 DB
            self.conn.execute("ALTER TABLE sandboxes ADD COLUMN template TEXT NOT NULL DEFAULT 'cli'")
        self.runtime = self._detect_runtime()

    # ---- SB-6 격리 백엔드 감지 -----------------------------------------
    def _detect_runtime(self) -> str:
        available = set((self.client.info().get("Runtimes") or {}).keys()) or {"runc"}
        want = self.settings.runtime
        if want and want != "auto":
            if want not in available:
                raise SandboxError(f"요청한 런타임 {want}이 Docker에 없음. 가능한 것: {sorted(available)}")
            return want
        for r in _RUNTIME_PREFERENCE:
            if r in available:
                return r
        return "runc"

    # ---- 저장소 --------------------------------------------------------
    def _rec(self, sid: str) -> dict[str, Any]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM sandboxes WHERE id = ?", (sid,))
            row = cur.fetchone()
            cols = [d[0] for d in cur.description]
        if not row:
            raise SandboxError(f"샌드박스 없음: {sid}")
        return dict(zip(cols, row))

    def get(self, sid: str) -> dict[str, Any]:
        rec = self._rec(sid)
        rec.pop("token_hash", None)
        return rec

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM sandboxes WHERE status != 'deleted' ORDER BY created_at")
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        out = []
        for r in rows:
            d = dict(zip(cols, r))
            d.pop("token_hash", None)
            out.append(d)
        return out

    def token_matches(self, sid: str, token: str) -> bool:
        try:
            rec = self._rec(sid)
        except SandboxError:
            return False
        return secrets.compare_digest(rec["token_hash"], hash_token(token)) and rec["status"] != "deleted"

    def sandbox_for_token(self, token: str) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM sandboxes WHERE token_hash = ? AND status != 'deleted'", (hash_token(token),)
            ).fetchone()
        return row[0] if row else None

    def _container(self, sid: str):
        rec = self._rec(sid)
        if rec["status"] == "deleted":
            raise SandboxError(f"삭제된 샌드박스: {sid}")
        try:
            return self.client.containers.get(rec["container_id"])
        except NotFound as e:
            raise SandboxError(f"컨테이너가 사라짐: {sid}") from e

    def _set(self, sid: str, **fields: Any) -> None:
        keys = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self.conn.execute(f"UPDATE sandboxes SET {keys} WHERE id = ?", (*fields.values(), sid))

    def template_of(self, sid: str) -> Template:
        return self.settings.template(self._rec(sid).get("template") or "cli")

    # ---- SB-1 생성·삭제 -----------------------------------------------
    def _run_container(self, tpl: Template, image: str, source_dir: str, name: str):
        kwargs: dict[str, Any] = dict(
            image=image,
            command=tpl.command or ["sleep", "infinity"],
            name=name,
            detach=True,
            init=True,
            network_mode="none",                       # SB-4
            volumes={source_dir: {"bind": SOURCE, "mode": "ro"}},
            mem_limit=tpl.mem_limit,                   # SB-5
            memswap_limit=tpl.mem_limit,
            nano_cpus=int(tpl.cpus * 1e9),
            pids_limit=tpl.pids_limit,
            cap_drop=["ALL"],
            cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"],
            security_opt=["no-new-privileges"],
            runtime=self.runtime,
            labels={"agentbox": "1", "agentbox.template": tpl.name},
        )
        if self.settings.disk_limit:
            kwargs["storage_opt"] = {"size": self.settings.disk_limit}
        return self.client.containers.run(**kwargs)

    def create(self, source_dir: str | None, template: str = "cli") -> tuple[dict[str, Any], str]:
        """source_dir가 비어 있으면 빈 원본 폴더로 만든다 (웹 UI에서 파일을 끌어다 놓는 경우)."""
        try:
            tpl = self.settings.template(template)
        except ValueError as e:
            raise SandboxError(str(e)) from e
        sid = "sb_" + secrets.token_hex(4)
        if source_dir:
            src = Path(source_dir).expanduser().resolve()
            if not src.is_dir():
                raise SandboxError(f"원본 폴더가 없음: {src}")
            # 원본은 컨테이너 root가 권한 검사 없이(DAC_OVERRIDE) 복사해 에이전트 소유로 바꾼다.
            # 데이터 폴더와 겹치면 사람 토큰·DB·다른 샌드박스 원본이 에이전트에게 넘어간다.
            for d in {self.settings.home.resolve(), self.settings.db_path.resolve().parent}:
                if src == d or d in src.parents or src in d.parents:
                    raise SandboxError(f"원본 폴더가 agentbox 데이터 폴더({d})와 겹침. 데이터 폴더 밖의 폴더를 고를 것")
        else:
            src = (self.settings.home / "sources" / sid).resolve()
            src.mkdir(parents=True)
        try:
            self.client.images.get(tpl.image)
        except ImageNotFound as e:
            raise SandboxError(f"템플릿 {tpl.name}의 이미지 {tpl.image}가 없음. README의 이미지 빌드 절차를 볼 것.") from e
        token = "agt_" + secrets.token_urlsafe(24)
        try:
            c = self._run_container(tpl, tpl.image, str(src), f"agentbox-{sid}")
        except APIError as e:
            raise SandboxError(f"컨테이너를 만들 수 없음: {e.explanation or e}") from e
        # 그룹 쓰기 + setgid: 데스크톱 계정(agent 그룹)도 같은 작업 폴더를 쓴다.
        # 결과함(outbox)은 처음부터 만들어 둔다. 에이전트는 여기에 결과물을 두고, 사람은 웹 UI에서 받는다.
        setup = (
            f"mkdir -p {WORKSPACE} && cp -a {SOURCE}/. {WORKSPACE}/ && mkdir -p {OUTBOX} "
            f"&& chown -R {AGENT_UID} {WORKSPACE} && chmod -R g+rwX {WORKSPACE} "
            f"&& find {WORKSPACE} -type d -exec chmod g+s {{}} +"
        )
        res = c.exec_run(["sh", "-c", setup], user="0:0")
        if res.exit_code != 0:
            c.remove(force=True)
            raise SandboxError(f"작업 폴더 준비 실패: {_truncate(res.output)}")
        if tpl.desktop:
            try:
                self._wait_display(c)
            except SandboxError:
                c.remove(force=True)
                raise
        with self._lock:
            self.conn.execute(
                "INSERT INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at,"
                " template) VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, c.id, str(src), tpl.image, self.runtime, hash_token(token), "running", _now(), tpl.name),
            )
        return self.get(sid), token

    def delete(self, sid: str) -> None:
        rec = self._rec(sid)
        try:
            self.client.containers.get(rec["container_id"]).remove(force=True)
        except NotFound:
            pass
        self._set(sid, status="deleted")
        # 스냅샷 이미지는 컨테이너와 따로 남는다. 샌드박스를 지우면 같이 지워 디스크를 돌려준다.
        for s in self.list_snapshots(sid):
            try:
                self.client.images.remove(s["image"], force=True)
            except (NotFound, APIError):
                pass

    # ---- SB-2 일시정지·재개 -------------------------------------------
    def pause(self, sid: str) -> None:
        self._container(sid).pause()
        self._set(sid, status="paused")

    def resume(self, sid: str) -> None:
        self._container(sid).unpause()
        self._set(sid, status="running")

    def _require_running(self, sid: str):
        rec = self._rec(sid)
        if rec["status"] == "paused":
            raise SandboxError(f"일시정지된 샌드박스: {sid}")
        return self._container(sid)

    # ---- SB-3 스냅샷·복원 ---------------------------------------------
    def snapshot(self, sid: str, reason: str = "manual") -> dict[str, Any]:
        c = self._container(sid)
        snap_id = "snap_" + secrets.token_hex(4)
        repo = "agentbox-snap"
        tag = f"{sid}-{snap_id}"
        c.commit(repository=repo, tag=tag, pause=True,
                 conf={"Labels": {"agentbox.snapshot": snap_id, "agentbox.sandbox": sid}})
        rec = {"id": snap_id, "sandbox_id": sid, "image": f"{repo}:{tag}", "reason": reason, "created_at": _now()}
        with self._lock:
            self.conn.execute(
                "INSERT INTO snapshots (id, sandbox_id, image, reason, created_at) VALUES (?,?,?,?,?)",
                (rec["id"], sid, rec["image"], reason, rec["created_at"]),
            )
        return rec

    def list_snapshots(self, sid: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM snapshots WHERE sandbox_id = ? ORDER BY created_at", (sid,))
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        return [dict(zip(cols, r)) for r in rows]

    def workspace_manifest(self, sid: str) -> tuple[dict[str, tuple[int, str, str]], bool]:
        """/workspace의 파일 목록 {경로: (크기, mtime, ctime)}. root로 읽어 에이전트가 권한으로 숨기지 못하게 한다.
        mtime은 파일 주인이 touch로 되돌릴 수 있지만 ctime은 못 되돌린다(시계를 바꿀 권한이 없다)."""
        c = self._container(sid)
        res = c.exec_run(["sh", "-c", f"find {WORKSPACE} -xdev ! -type d -printf '%P\\0%s\\0%T@\\0%C@\\0' "
                                      f"| head -c {_MANIFEST_CAP}"], user="0:0", demux=True)
        return _parse_manifest(res.output[0] or b"")

    def snapshot_count(self, sid: str) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM snapshots WHERE sandbox_id = ?", (sid,)).fetchone()[0]

    def restore(self, sid: str, snap_id: str) -> dict[str, Any]:
        rec = self._rec(sid)
        snaps = {s["id"]: s for s in self.list_snapshots(sid)}
        if snap_id not in snaps:
            raise SandboxError(f"이 샌드박스의 스냅샷이 아님: {snap_id}")
        try:
            self.client.containers.get(rec["container_id"]).remove(force=True)
        except NotFound:
            pass
        tpl = self.template_of(sid)
        c = self._run_container(tpl, snaps[snap_id]["image"], rec["source_dir"], f"agentbox-{sid}")
        self._set(sid, container_id=c.id, status="running")
        if tpl.desktop:
            self._wait_display(c)
        return self.get(sid)

    # ---- 도구 ----------------------------------------------------------
    def exec(self, sid: str, command: str) -> dict[str, Any]:
        c = self._require_running(sid)
        t = self.settings.exec_timeout
        # umask 002: 데스크톱 계정도 에이전트가 만든 파일을 고칠 수 있게
        # 출력은 스트림으로 받아 앞부분만 남긴다. 한꺼번에 받으면 제한 시간 동안 나온 전부가
        # 컨트롤 플레인 메모리에 쌓인다 (cat /dev/zero 하나로 수백 MB).
        api = self.client.api
        ex = api.exec_create(c.id, ["timeout", "-k", "5", str(t), "bash", "-c", "umask 002\n" + command],
                             user=AGENT_UID, workdir=WORKSPACE)
        out, err = _Head(), _Head()
        for o, e in api.exec_start(ex["Id"], stream=True, demux=True):
            out.add(o)
            err.add(e)
        code = api.exec_inspect(ex["Id"])["ExitCode"]
        return {
            "exit_code": code,
            "stdout": out.text(),
            "stderr": err.text(),
            "timed_out": code in (124, 137),
        }

    def list_dir(self, sid: str, path: str) -> dict[str, Any]:
        c = self._require_running(sid)
        p = safe_path(path)
        res = c.exec_run(["ls", "-la", "--", p], user=AGENT_UID, workdir=WORKSPACE, demux=True)
        out, err = res.output
        if res.exit_code != 0:
            raise SandboxError(_truncate(err) or f"ls 실패 ({res.exit_code})")
        return {"path": p, "listing": _truncate(out)}

    def read_file(self, sid: str, path: str) -> dict[str, Any]:
        c = self._require_running(sid)
        p = safe_path(path)
        limit = self.settings.max_read_bytes
        res = c.exec_run(["head", "-c", str(limit + 1), "--", p], user=AGENT_UID, workdir=WORKSPACE, demux=True)
        out, err = res.output
        if res.exit_code != 0:
            raise SandboxError(_truncate(err) or f"읽기 실패 ({res.exit_code})")
        data = out or b""
        truncated = len(data) > limit
        return {"path": p, "content": data[:limit].decode("utf-8", errors="replace"), "truncated": truncated}

    def _workspace_path(self, path: str) -> str:
        p = safe_path(path)
        if p == WORKSPACE or not p.startswith(WORKSPACE + "/"):
            raise SandboxError(f"/workspace 아래 파일만 쓰거나 지울 수 있음: {path}")
        return p

    def exists(self, sid: str, path: str) -> bool:
        c = self._require_running(sid)
        p = safe_path(path)
        return c.exec_run(["test", "-e", p], user=AGENT_UID).exit_code == 0

    def write_file(self, sid: str, path: str, content: str) -> dict[str, Any]:
        """에이전트 계정으로 쓴다 (exec로 할 수 있는 것 이상은 못 한다). 임시 파일에 쓰고 옮긴다."""
        c = self._require_running(sid)
        p = self._workspace_path(path)
        data = content.encode("utf-8")
        if len(data) > self.settings.max_write_bytes:
            raise SandboxError(f"파일이 너무 큼: {len(data)} bytes (최대 {self.settings.max_write_bytes})")
        tmp = f"{p}.agentbox-tmp-{secrets.token_hex(3)}"
        self._write_chunks(c, tmp, data)
        res = c.exec_run(["mv", "-f", "--", tmp, p], user=AGENT_UID, demux=True)
        if res.exit_code != 0:
            c.exec_run(["rm", "-f", "--", tmp], user=AGENT_UID)
            raise SandboxError(_truncate(res.output[1]) or f"쓰기 실패 ({res.exit_code})")
        return {"path": p, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def delete_file(self, sid: str, path: str) -> dict[str, Any]:
        c = self._require_running(sid)
        p = self._workspace_path(path)
        script = ('if [ -d "$1" ] && [ ! -L "$1" ]; then echo "폴더는 delete_file로 지울 수 없음" >&2; exit 2; fi; '
                  'if [ ! -e "$1" ] && [ ! -L "$1" ]; then echo "파일 없음" >&2; exit 3; fi; rm -f -- "$1"')
        res = c.exec_run(["sh", "-c", script, "_", p], user=AGENT_UID, demux=True)
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or f"삭제 실패 ({res.exit_code})")
        return {"path": p, "deleted": True}

    # ---- UX-3 파일 넣기, UX-4 결과함 ------------------------------------
    def _write_chunks(self, c, tmp: str, data: bytes) -> None:
        """data를 base64 조각으로 나눠 에이전트 계정으로 tmp에 쓴다 (exec 인자 하나는 128KB 상한)."""
        import base64

        raw = _WRITE_CHUNK * 3 // 4
        chunks = [data[i:i + raw] for i in range(0, len(data), raw)] or [b""]
        for i, chunk in enumerate(chunks):
            op = ">" if i == 0 else ">>"
            res = c.exec_run(["sh", "-c", f'umask 002; printf %s "$1" | base64 -d {op} "$2"', "_",
                              base64.b64encode(chunk).decode(), tmp], user=AGENT_UID, workdir=WORKSPACE, demux=True)
            if res.exit_code != 0:
                c.exec_run(["rm", "-f", "--", tmp], user=AGENT_UID)
                raise SandboxError(_truncate(res.output[1]) or f"쓰기 실패 ({res.exit_code})")

    def upload(self, sid: str, name: str, data: bytes) -> dict[str, Any]:
        """사람이 건넨 파일을 /workspace 바로 아래에 에이전트 계정으로 쓴다.

        put_archive는 쓰지 않는다. gVisor는 바깥에서 바꾼 컨테이너 파일을 바로 보지 못한다.
        """
        c = self._require_running(sid)
        name = clean_name(name)
        if len(data) > self.settings.max_upload_bytes:
            raise SandboxError(f"파일이 너무 큼: {name} {len(data)} bytes (최대 {self.settings.max_upload_bytes})")
        path = f"{WORKSPACE}/{name}"
        tmp = f"{WORKSPACE}/.agentbox-upload-{secrets.token_hex(4)}"
        self._write_chunks(c, tmp, data)
        res = c.exec_run(["mv", "-f", "--", tmp, path], user=AGENT_UID, demux=True)
        if res.exit_code != 0:
            c.exec_run(["rm", "-f", "--", tmp], user=AGENT_UID)
            raise SandboxError(f"파일을 넣을 수 없음: {name} ({_truncate(res.output[1]).strip() or res.exit_code})")
        return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def is_dir(self, sid: str, path: str) -> bool:
        c = self._require_running(sid)
        return c.exec_run(["test", "-d", safe_path(path)], user=AGENT_UID).exit_code == 0

    def outbox_list(self, sid: str) -> list[dict[str, Any]]:
        """결과함(/workspace/outbox) 바로 아래의 일반 파일. 링크와 폴더는 보이지 않는다.

        파일 이름은 에이전트가 정하므로 믿을 수 없는 데이터다. 레코드는 NUL로 나누고 이름(%f)을
        맨 뒤에 둬서, 이름에 탭·줄바꿈이 들어가도 가짜 행을 끼워 넣거나 파싱을 깨지 못하게 한다.
        """
        c = self._require_running(sid)
        script = (f'[ -d {OUTBOX} ] && [ ! -L {OUTBOX} ] || exit 0; '
                  f"find {OUTBOX} -mindepth 1 -maxdepth 1 -type f -printf '%s\\t%T@\\t%f\\0'")
        res = c.exec_run(["sh", "-c", script], user=AGENT_UID, demux=True)
        return _parse_outbox(res.output[0] or b"")

    def outbox_read(self, sid: str, name: str) -> bytes:
        c = self._require_running(sid)
        name = clean_name(name)
        p = f"{OUTBOX}/{name}"
        limit = self.settings.max_upload_bytes
        script = (f'[ ! -L {OUTBOX} ] && [ -f "$1" ] && [ ! -L "$1" ] || {{ echo "결과함에 없는 파일" >&2; exit 3; }}; '
                  f'head -c {limit + 1} -- "$1"')
        res = c.exec_run(["sh", "-c", script, "_", p], user=AGENT_UID, demux=True)
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or f"읽기 실패 ({res.exit_code})")
        data = res.output[0] or b""
        if len(data) > limit:
            raise SandboxError(f"결과 파일이 너무 큼 (최대 {limit} bytes)")
        return data

    # ---- TL-2 GUI 도구 (데스크톱 템플릿) --------------------------------
    def _desktop(self, sid: str):
        if not self.template_of(sid).desktop:
            raise SandboxError("데스크톱이 없는 샌드박스 (template=desktop으로 만들 것)")
        return self._require_running(sid)

    @staticmethod
    def _x(c, argv: list[str]):
        return c.exec_run(argv, user=DESKTOP_USER, environment=DESKTOP_ENV, demux=True)

    def _wait_display(self, c, timeout: float = 45) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._x(c, ["xdotool", "getdisplaygeometry"]).exit_code == 0:
                return
            time.sleep(0.3)
        raise SandboxError("데스크톱(X 서버)이 시작되지 않음")

    def geometry(self, sid: str) -> tuple[int, int]:
        res = self._x(self._desktop(sid), ["xdotool", "getdisplaygeometry"])
        if res.exit_code != 0:
            raise SandboxError("화면 크기를 알 수 없음 (데스크톱이 떠 있지 않음)")
        w, h = (res.output[0] or b"0 0").split()[:2]
        return int(w), int(h)

    def screenshot(self, sid: str) -> dict[str, Any]:
        c = self._desktop(sid)
        res = self._x(c, ["sh", "-c", f'mkdir -p "$(dirname {_SHOT})" && scrot -o -z {_SHOT} && cat {_SHOT}; '
                                      f'r=$?; rm -f {_SHOT}; exit $r'])
        png = res.output[0] or b""
        if res.exit_code != 0 or png[:8] != b"\x89PNG\r\n\x1a\n":
            raise SandboxError(_truncate(res.output[1]) or "스크린샷 실패")
        width, height = struct.unpack(">II", png[16:24])
        return {"png": png, "width": width, "height": height, "sha256": hashlib.sha256(png).hexdigest()}

    def click(self, sid: str, x: int, y: int, button: str = "left", double: bool = False) -> dict[str, Any]:
        c = self._desktop(sid)
        w, h = self.geometry(sid)
        x, y = int(x), int(y)
        if not (0 <= x < w and 0 <= y < h):
            raise SandboxError(f"화면 밖 좌표: ({x}, {y}), 화면 {w}x{h}")
        if button not in _BUTTONS:
            raise SandboxError("button은 left, middle, right 중 하나")
        argv = ["xdotool", "mousemove", str(x), str(y), "click"]
        if double:
            argv += ["--repeat", "2", "--delay", "80"]
        res = self._x(c, argv + [_BUTTONS[button]])
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "클릭 실패")
        return {"x": x, "y": y, "button": button, "double": bool(double)}

    def type_text(self, sid: str, text: str) -> dict[str, Any]:
        c = self._desktop(sid)
        if len(text) > 2000:
            raise SandboxError("한 번에 2000자까지 입력할 수 있음")
        res = self._x(c, ["xdotool", "type", "--clearmodifiers", "--delay", "12", "--", text])
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "입력 실패")
        return {"chars": len(text)}

    def key(self, sid: str, keys: str) -> dict[str, Any]:
        c = self._desktop(sid)
        names = keys.split()
        if not names or len(names) > 20 or not all(_KEY_RE.match(k) for k in names):
            raise SandboxError("keys는 xdotool 키 이름을 공백으로 나눈 것 (예: 'ctrl+s', 'Return', 'alt+F4')")
        res = self._x(c, ["xdotool", "key", "--clearmodifiers", "--"] + names)
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or "키 입력 실패")
        return {"keys": names}

    def vnc_command(self, sid: str, view_only: bool) -> list[str]:
        """화면 연결 하나에 쓸 명령. 포트를 열지 않고 x11vnc가 표준 입출력으로 RFB를 말한다."""
        c = self._desktop(sid)
        argv = [self.settings.docker_cli, "exec", "-i", "-u", DESKTOP_USER]
        for k, v in DESKTOP_ENV.items():
            argv += ["-e", f"{k}={v}"]
        # 디스플레이는 DISPLAY 환경 변수로 넘긴다. socat 주소에서 ':'는 구분자라 '-display :0'을 못 쓴다.
        vnc = ["x11vnc", "-inetd", "-q", "-auth", DESKTOP_ENV["XAUTHORITY"],
               "-nopw", "-shared", "-norc", "-noshm", "-nosel", "-noxdamage"]
        if view_only:
            vnc.append("-viewonly")
        # x11vnc -inetd는 fd 0에 쓰기도 한다. docker exec의 표준 입력은 파이프라 쓰기가 실패하므로
        # socat EXEC(기본이 socketpair)로 감싼다. 인자에 공백·':'·','가 없어야 한다.
        return argv + [c.id, "socat", "-", "EXEC:" + " ".join(vnc)]

    def extract_novnc(self, dest: Path) -> bool:
        """noVNC 정적 파일을 데스크톱 이미지에서 꺼낸다. 인터넷 없이 설치하기 위해 따로 받지 않는다."""
        if (dest / "core" / "rfb.js").exists():
            return True
        # 컨테이너 로그로 tar를 받으면 바이너리가 잘린다. 실행하지 않은 컨테이너에서 복사 API로 꺼낸다.
        try:
            c = self.client.containers.create(self.settings.desktop_image, ["true"], network_mode="none")
        except (ImageNotFound, APIError):
            return False
        try:
            stream, _ = c.get_archive("/usr/share/novnc")
            out = b"".join(stream)
        except (NotFound, APIError):
            return False
        finally:
            c.remove(force=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(out)) as tf:
            # 링크는 건너뛴다 (vnc_auto.html 같은 별칭뿐이고, 밖을 가리키는 링크를 풀지 않기 위해)
            members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
            tf.extractall(dest.parent, members=members, filter="data")
        if dest.name != "novnc":
            (dest.parent / "novnc").rename(dest)
        return (dest / "core" / "rfb.js").exists()

    # ---- 승인 화면용 영향 미리보기 -------------------------------------
    def _expand(self, c, pattern: str) -> list[str]:
        """컨테이너 안에서 glob만 펼친다. 명령 치환은 일어나지 않는다."""
        script = 'cd /workspace; for p in $1; do if [ -e "$p" ] || [ -L "$p" ]; then printf "%s\\n" "$p"; fi; done'
        res = c.exec_run(["sh", "-c", script, "_", pattern], user=AGENT_UID, demux=True)
        out = (res.output[0] or b"").decode("utf-8", errors="replace")
        return [line for line in out.splitlines() if line]

    def _walk(self, c, path: str, limit: int) -> list[str]:
        res = c.exec_run(["sh", "-c", 'cd /workspace; case "$1" in -*) set -- "./$1" "$2";; esac; find "$1" 2>/dev/null | head -n "$2"',
                          "_", path, str(limit)],
                         user=AGENT_UID, demux=True)
        out = (res.output[0] or b"").decode("utf-8", errors="replace")
        return [line for line in out.splitlines() if line]

    def preview(self, sid: str, command: str, limit: int = 200) -> dict[str, Any]:
        c = self._container(sid)
        affected: list[dict[str, str]] = []
        notes: list[str] = []
        if any(s in command for s in ("$", "`", "<(", "eval ")):
            notes.append("변수·명령 치환이 있어 실제로 무엇이 실행될지 자동 계산이 정확하지 않을 수 있음. 명령 원문을 확인할 것.")
        for seg in _split_segments(command):
            if not seg:
                continue
            name = seg[0].rsplit("/", 1)[-1]
            if name == "rm":
                recursive = any(a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a)
                                for a in seg[1:]) or "--recursive" in seg
                operands, opts_done = [], False
                for a in seg[1:]:
                    if not opts_done and a == "--":
                        opts_done = True
                        continue
                    if not opts_done and a.startswith("-") and a != "-":
                        continue
                    operands.append(a)
                for op in operands:
                    matches = self._expand(c, op)
                    if not matches:
                        affected.append({"path": op, "effect": "삭제 시도 (현재 존재하지 않음)"})
                    for m in matches:
                        if m == SOURCE or m.startswith(SOURCE + "/"):
                            affected.append({"path": m, "effect": "삭제 시도 → 실패 예정 (원본은 읽기 전용)"})
                            continue
                        items = self._walk(c, m, limit) if recursive else [m]
                        for it in items:
                            affected.append({"path": it, "effect": "삭제"})
            elif name == "curl":
                urls = [a for a in seg[1:] if re.match(r"^[a-z][a-z0-9+.-]*://", a, re.I)]
                uploads = []
                for i, a in enumerate(seg[1:], start=1):
                    v = None
                    if a.startswith("@"):
                        v = a[1:]
                    elif a.startswith("--data") or a in ("-d", "-F", "-T", "--upload-file", "--form"):
                        nxt = seg[i + 1] if i + 1 < len(seg) else ""
                        if "=@" in nxt:
                            v = nxt.split("=@", 1)[1]
                        elif nxt.startswith("@"):
                            v = nxt[1:]
                        elif a in ("-T", "--upload-file"):
                            v = nxt
                    if v:
                        uploads.extend(self._expand(c, v) or [v])
                for u in urls:
                    affected.append({"path": u, "effect": "외부 접속 시도 (샌드박스는 network=none이라 실패 예정)"})
                for u in uploads:
                    affected.append({"path": u, "effect": "외부로 보낼 파일"})
                if not urls:
                    notes.append("curl 대상 주소를 명령에서 찾지 못함.")
        if len(affected) > limit:
            notes.append(f"영향 항목 {len(affected)}개 중 앞의 {limit}개만 표시.")
            affected = affected[:limit]
        if not affected and not notes:
            notes.append("시스템이 영향 파일을 계산하지 못함. 명령 원문을 확인할 것.")
        return {"command": command, "cwd": WORKSPACE, "affected": affected, "notes": notes}
