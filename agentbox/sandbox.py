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
import os
import posixpath
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from docker.types import Mount

from .config import Settings, Template
from .gui_state import _MANIFEST_CAP, _parse_manifest
from .preview import preview_command
from .sandbox_common import _OUT_LIMIT, SOURCE, WORKSPACE, SandboxError, _timed, _truncate
from .sandbox_desktop import DesktopTools

AGENT_UID = "1000:1000"
# 파일 읽기 한 번의 제한 시간(초). 일반 파일만 읽지만, 확인과 읽기 사이에 FIFO로 바뀌면 head가 끝없이 기다린다.
_READ_TIMEOUT = 30
# GUI 구간 기록용 파일 목록 exec의 제한 시간(초). 화면(X) 쪽 제한은 sandbox_desktop._X_TIMEOUT.
_MANIFEST_TIMEOUT = 30
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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


def _source_mount(source_dir: str) -> Mount:
    """원본 폴더 안쪽에 다른 폴더(데이터 폴더 등)가 바인드 마운트돼 있으면 docker 기본값(rbind)은 그것까지 붙이고,
    cp -a가 작업 폴더로 복사한다. 같은 디스크의 바인드 마운트는 장치 번호가 같아 cp -x로도 못 거른다 (보안 검수 run-3 v06)."""
    m = Mount(SOURCE, source_dir, type="bind", read_only=True)
    m["BindOptions"] = {"NonRecursive": True}
    return m


def overlaps(a: Path, b: Path) -> bool:
    """두 폴더가 같거나 한쪽이 다른 쪽 안에 있는가. 경로 문자열이 아니라 파일 시스템의 실체(장치·inode)로
    비교한다. 대소문자를 가리지 않는 파일 시스템(WSL2 /mnt/c 등)의 다른 철자나 바인드 마운트처럼
    심볼릭 링크가 아닌 다른 이름도 같은 폴더로 본다."""
    def same(x: Path, y: Path) -> bool:
        try:
            return x == y or os.path.samefile(x, y)
        except OSError:
            return False
    return any(same(x, b) for x in (a, *a.parents)) or any(same(a, y) for y in (b, *b.parents))


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


class SandboxManager(DesktopTools):
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
        """원본 폴더는 읽기 전용으로, 그 안쪽에 걸린 다른 마운트는 빼고 붙인다."""
        kwargs: dict[str, Any] = dict(
            image=image,
            command=tpl.command or ["sleep", "infinity"],
            name=name,
            detach=True,
            init=True,
            network_mode="none",                       # SB-4
            mounts=[_source_mount(source_dir)],
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
                if overlaps(src, d):
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
        res = c.exec_run(_timed(_MANIFEST_TIMEOUT, "sh", "-c",
                                f"find {WORKSPACE} -xdev ! -type d -printf '%P\\0%s\\0%T@\\0%C@\\0' "
                                f"| head -c {_MANIFEST_CAP}"), user="0:0", demux=True)
        if res.exit_code != 0:  # 시간 초과 등. 잘린 목록으로 비교하면 없는 파일을 지워졌다고 적는다
            raise SandboxError(f"/workspace 파일 목록 실패 (exit {res.exit_code})")
        return _parse_manifest(res.output[0] or b"")

    def snapshot_count(self, sid: str) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM snapshots WHERE sandbox_id = ?", (sid,)).fetchone()[0]

    def restore(self, sid: str, snap_id: str) -> dict[str, Any]:
        rec = self._rec(sid)
        if rec["status"] == "deleted":
            raise SandboxError(f"삭제된 샌드박스: {sid}")
        snaps = {s["id"]: s for s in self.list_snapshots(sid)}
        if snap_id not in snaps:
            raise SandboxError(f"이 샌드박스의 스냅샷이 아님: {snap_id}")
        try:
            self.client.containers.get(rec["container_id"]).remove(force=True)
        except NotFound:
            pass
        tpl = self.template_of(sid)
        c = self._run_container(tpl, snaps[snap_id]["image"], rec["source_dir"], f"agentbox-{sid}")
        # 그사이 삭제됐으면 되살리지 않는다. 삭제는 상태로 토큰을 폐기하므로 덮어쓰면 토큰이 다시 살아난다 (run-4 F6)
        with self._lock:
            cur = self.conn.execute("UPDATE sandboxes SET container_id = ?, status = 'running' "
                                    "WHERE id = ? AND status != 'deleted'", (c.id, sid))
        if cur.rowcount == 0:
            c.remove(force=True)
            raise SandboxError(f"복원하는 사이 삭제된 샌드박스: {sid}")
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
        ex = api.exec_create(c.id, _timed(t, "bash", "-c", "umask 002\n" + command, kill_after=5),
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
        # 일반 파일만 읽는다. FIFO를 읽으면 쓰는 쪽이 생길 때까지 끝나지 않는다 (README 알려진 한계였다).
        script = ('[ -f "$1" ] || { echo "일반 파일이 아님 (폴더·FIFO·소켓 등): $1" >&2; exit 3; }; '
                  f'head -c {limit + 1} -- "$1"')
        res = c.exec_run(_timed(_READ_TIMEOUT, "sh", "-c", script, "_", p),
                         user=AGENT_UID, workdir=WORKSPACE, demux=True)
        out, err = res.output
        if res.exit_code in (124, 137):
            raise SandboxError(f"읽기 시간 초과 ({_READ_TIMEOUT}초): {p}")
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
        # 확인과 읽기 사이에 에이전트가 FIFO로 바꿔치기해도 사람의 요청이 멈추지 않게 시간 제한을 둔다.
        res = c.exec_run(_timed(_READ_TIMEOUT, "sh", "-c", script, "_", p),
                         user=AGENT_UID, demux=True)
        if res.exit_code in (124, 137):
            raise SandboxError(f"읽기 시간 초과 ({_READ_TIMEOUT}초): {name}")
        if res.exit_code != 0:
            raise SandboxError(_truncate(res.output[1]) or f"읽기 실패 ({res.exit_code})")
        data = res.output[0] or b""
        if len(data) > limit:
            raise SandboxError(f"결과 파일이 너무 큼 (최대 {limit} bytes)")
        return data

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
        return preview_command(command, limit, lambda pattern: self._expand(c, pattern),
                               lambda path, n: self._walk(c, path, n))
