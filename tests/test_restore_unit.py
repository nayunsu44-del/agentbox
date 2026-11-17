"""스냅샷 복원: 새 컨테이너를 먼저 띄워 확인한 뒤에만 바꾼다. 가짜 Docker로 실패 지점마다 확인한다. Docker 없이 돈다.

복원이 기존 컨테이너를 먼저 지우고 새 것을 만들면, 새 것이 뜨지 못할 때 작업 상태도 스냅샷 상태도 없이
DB만 지워진 컨테이너를 가리킨 채 남았다."""

import secrets
import sqlite3
import threading

import pytest
from docker.errors import APIError, NotFound
from docker.models.containers import ExecResult

from agentbox import sandbox as S
from agentbox.config import Settings
from agentbox.sandbox import RESTORE_LABEL, SandboxError, SandboxManager


class FakeContainer:
    def __init__(self, d, name, image, labels):
        self.d = d
        self.id = "c" + secrets.token_hex(8)
        self.name = name
        self.image = image
        self.labels = dict(labels or {})
        self.exec_code = d.new_exec_code
        self.workspace_code = d.new_workspace_code
        self.execs: list = []
        self.users: list = []

    def exec_run(self, argv, **kw):
        if self.id not in self.d.by_id:
            raise NotFound("container gone")
        self.execs.append(argv)
        self.users.append(kw.get("user"))
        code = self.exec_code
        if argv[:2] == ["sh", "-c"] and "test -w" in argv[2]:
            code = code or self.workspace_code
        return ExecResult(code, (b"", b"") if kw.get("demux") else b"")

    def remove(self, force=False):
        if self.id in self.d.refuse_remove:
            raise APIError("remove refused")
        self.d.by_id.pop(self.id, None)

    def rename(self, name):
        if any(c.name == name for c in self.d.by_id.values() if c is not self):
            raise APIError(f"name {name} in use")
        self.name = name

    def commit(self, repository, tag, **kw):
        return None

    def pause(self):
        pass

    def unpause(self):
        pass


class FakeContainers:
    def __init__(self, d):
        self.d = d

    def run(self, **kw):
        if any(c.name == kw["name"] for c in self.d.by_id.values()):
            raise APIError(f"Conflict: name {kw['name']}")
        if self.d.on_run:
            self.d.on_run(kw)
        c = FakeContainer(self.d, kw["name"], kw["image"], kw.get("labels"))
        self.d.by_id[c.id] = c
        if self.d.fail_start:
            raise APIError("OCI runtime create failed")  # docker는 만든 컨테이너를 created 상태로 남긴다
        return c

    def get(self, ident):
        if ident in self.d.by_id:
            return self.d.by_id[ident]
        for c in self.d.by_id.values():
            if c.name == ident:
                return c
        raise NotFound(ident)

    def list(self, all=False, filters=None):
        key = (filters or {}).get("label")
        return [c for c in self.d.by_id.values() if key is None or key in c.labels]


class FakeImages:
    def get(self, name):
        return object()

    def remove(self, name, force=False):
        pass


class FakeDocker:
    def __init__(self):
        self.by_id: dict[str, FakeContainer] = {}
        self.fail_start = False
        self.new_exec_code = 0
        self.new_workspace_code = 0
        self.refuse_remove: set[str] = set()
        self.on_run = None
        self.containers = FakeContainers(self)
        self.images = FakeImages()

    def info(self):
        return {"Runtimes": {"runc": {}}}


@pytest.fixture
def sm(tmp_path, monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(S.docker, "from_env", lambda: fake)
    m = SandboxManager(Settings(home=tmp_path), tmp_path / "a.db")
    return m


def _make(sm):
    rec, _token = sm.create(None, "cli")
    sid = rec["id"]
    snap = sm.snapshot(sid)
    return sid, rec["container_id"], snap["id"]


def _names(sm):
    return sorted(c.name for c in sm.client.by_id.values())


def test_restore_swaps_after_new_container_is_ready(sm):
    sid, old, snap = _make(sm)
    rec = sm.restore(sid, snap)
    new = sm.client.containers.get(rec["container_id"])
    assert rec["container_id"] != old and rec["status"] == "running"
    assert old not in sm.client.by_id                       # 이전 것은 정리
    assert new.name == f"agentbox-{sid}"                    # 임시 이름에서 정식 이름으로
    assert new.labels[RESTORE_LABEL] == sid
    assert new.image.startswith("agentbox-snap:")
    assert new.execs[0] == ["true"]                         # 바꾸기 전에 명령이 도는지 확인
    assert new.execs[1][-1] == "/workspace" and new.users[1] == S.AGENT_UID   # 에이전트 계정으로 작업 폴더 확인
    assert _names(sm) == [f"agentbox-{sid}"]


def test_restore_start_failure_keeps_old_container_and_db(sm):
    """완료 기준: 이미지 실행을 강제로 실패시켜도 기존 컨테이너가 계속 돌고 DB도 그것을 가리킨다."""
    sid, old, snap = _make(sm)
    sm.client.fail_start = True
    with pytest.raises(SandboxError, match="기존 컨테이너는 그대로"):
        sm.restore(sid, snap)
    rec = sm.get(sid)
    assert rec["container_id"] == old and rec["status"] == "running"
    assert _names(sm) == [f"agentbox-{sid}"]                # created 상태로 남은 임시 컨테이너도 지웠다
    assert sm.exec(sid, "ls")["exit_code"] == 0             # 기존 컨테이너로 계속 쓸 수 있다
    sm.client.fail_start = False
    assert sm.restore(sid, snap)["container_id"] != old    # 원인이 풀리면 다시 복원된다


def test_restore_probe_failure_keeps_old_container(sm):
    sid, old, snap = _make(sm)
    sm.client.new_exec_code = 126
    with pytest.raises(SandboxError, match="명령을 실행하지 못함"):
        sm.restore(sid, snap)
    assert sm.get(sid)["container_id"] == old and _names(sm) == [f"agentbox-{sid}"]


@pytest.mark.parametrize("code,why", [(3, "없음"), (4, "쓸 수 없음")])
def test_restore_without_writable_workspace_keeps_old_container(sm, code, why):
    """gVisor를 --overlay2=none 없이 쓰면 스냅샷에 /workspace가 빠진다. 그 스냅샷으로 바꾸면 작업이 든
    기존 컨테이너를 지우고 빈 컨테이너만 남으므로, 에이전트 계정으로 쓸 수 있는지 보고 아니면 바꾸지 않는다."""
    sid, old, snap = _make(sm)
    sm.client.new_workspace_code = code
    with pytest.raises(SandboxError, match=why):
        sm.restore(sid, snap)
    assert sm.get(sid)["container_id"] == old and _names(sm) == [f"agentbox-{sid}"]
    assert sm.exec(sid, "ls")["exit_code"] == 0


def test_restore_desktop_not_ready_keeps_old_container(sm, monkeypatch):
    sid, old, snap = _make(sm)
    tpl = sm.template_of(sid)
    monkeypatch.setattr(sm, "template_of", lambda _sid: S.Template(**{**tpl.__dict__, "desktop": True}))

    def no_display(c, timeout=45):
        raise SandboxError("데스크톱(X 서버)이 시작되지 않음")

    monkeypatch.setattr(sm, "_wait_display", no_display)
    with pytest.raises(SandboxError, match="X 서버"):
        sm.restore(sid, snap)
    assert sm.get(sid)["container_id"] == old and _names(sm) == [f"agentbox-{sid}"]


class _FailingSwitch:
    """sqlite 연결을 감싸 container_id를 바꾸는 UPDATE만 실패시킨다."""

    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, *a):
        if sql.lstrip().startswith("UPDATE sandboxes SET container_id"):
            raise sqlite3.OperationalError("database is locked")
        return self.conn.execute(sql, *a)


def test_restore_db_update_failure_keeps_old_container(sm):
    sid, old, snap = _make(sm)
    real = sm.conn
    sm.conn = _FailingSwitch(real)
    with pytest.raises(SandboxError, match="기존 컨테이너는 그대로"):
        sm.restore(sid, snap)
    sm.conn = real
    assert sm.get(sid)["container_id"] == old and _names(sm) == [f"agentbox-{sid}"]
    assert sm.exec(sid, "ls")["exit_code"] == 0


def test_restore_deleted_meanwhile_removes_new_container(sm):
    """run-4 F6: 새 컨테이너를 띄우는 사이 삭제되면 되살리지 않고 새 것도 지운다."""
    sid, _old, snap = _make(sm)
    sm.client.on_run = lambda kw: sm.delete(sid) if kw["name"] != f"agentbox-{sid}" else None
    with pytest.raises(SandboxError, match="삭제되었거나 바뀐"):
        sm.restore(sid, snap)
    assert sm.get(sid)["status"] == "deleted" and _names(sm) == []


def test_tool_calls_are_refused_while_restoring(sm):
    """바꾸는 동안 들어온 도구 호출이 이전 컨테이너에 성공으로 쓰이고 전환 뒤 사라지지 않게 막는다."""
    sid, _old, snap = _make(sm)
    seen = {}

    def during(kw):
        if kw["name"] == f"agentbox-{sid}":
            return
        for name, call in [("exec", lambda: sm.exec(sid, "ls")),
                           ("write", lambda: sm.write_file(sid, "/workspace/a.txt", "x")),
                           ("snapshot", lambda: sm.snapshot(sid))]:
            try:
                call()
                seen[name] = "ran"
            except SandboxError as e:
                seen[name] = str(e)

    sm.client.on_run = during
    sm.restore(sid, snap)
    assert all("복원 중" in v for v in seen.values()), seen
    assert sm.exec(sid, "ls")["exit_code"] == 0              # 끝나면 다시 된다


def test_second_restore_of_same_sandbox_is_refused_while_first_runs(sm):
    sid, old, snap = _make(sm)
    go, inside = threading.Event(), threading.Event()
    sm.client.on_run = lambda kw: (inside.set(), go.wait(10)) if kw["name"] != f"agentbox-{sid}" else None
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("first", sm.restore(sid, snap)))
    t.start()
    assert inside.wait(10)
    sm.client.on_run = None
    with pytest.raises(SandboxError, match="이미 복원 중"):
        sm.restore(sid, snap)
    go.set()
    t.join(10)
    assert out["first"]["container_id"] != old


def test_old_container_removal_refused_is_cleaned_on_restart(sm):
    """전환 뒤 이전 컨테이너를 못 지우면 복원은 성공하고, 새 것은 임시 이름으로 남는다. 다음 시작 때 정리한다."""
    sid, old, snap = _make(sm)
    sm.client.refuse_remove.add(old)
    rec = sm.restore(sid, snap)
    new = rec["container_id"]
    assert new != old and old in sm.client.by_id
    assert sm.client.by_id[new].name.startswith(f"agentbox-{sid}-restore-")
    sm.client.refuse_remove.clear()
    assert sm.recover_restores() == [old]
    assert _names(sm) == [f"agentbox-{sid}"] and sm.client.by_id[new].name == f"agentbox-{sid}"


def test_recover_after_crash_before_switch(sm):
    """DB를 바꾸기 전에 죽음: 임시 컨테이너만 남는다. DB가 가리키는 것은 남기고 임시 것만 지운다."""
    sid, old, _snap = _make(sm)
    tmp = sm.client.containers.run(name=f"agentbox-{sid}-restore-abc123", image="x", labels={RESTORE_LABEL: sid})
    other = sm.client.containers.run(name="agentbox-sb_other-restore-1", image="x",
                                     labels={RESTORE_LABEL: "sb_other"})   # 이 DB에 없는 샌드박스
    assert sm.recover_restores() == [tmp.id]
    assert old in sm.client.by_id and other.id in sm.client.by_id
    assert sm.get(sid)["container_id"] == old


def test_recover_after_crash_between_switch_and_rename(sm):
    """DB를 바꾼 뒤 죽음: 이전 것을 지우고(아직 남았으면) 새 것의 이름을 정식 이름으로 바꾼다."""
    sid, old, _snap = _make(sm)
    new = sm.client.containers.run(name=f"agentbox-{sid}-restore-abc123", image="x", labels={RESTORE_LABEL: sid})
    sm._set(sid, container_id=new.id)
    assert sm.recover_restores() == [old]
    assert _names(sm) == [f"agentbox-{sid}"] and sm.get(sid)["container_id"] == new.id
    assert sm.recover_restores() == []                      # 두 번 불러도 같다


def test_recover_removes_superseded_restored_container_and_deleted_leftovers(sm):
    sid, _old, snap = _make(sm)
    first = sm.restore(sid, snap)["container_id"]           # 라벨이 붙은 정식 컨테이너
    second = sm.client.containers.run(name=f"agentbox-{sid}-restore-def456", image="x",
                                      labels={RESTORE_LABEL: sid})
    sm._set(sid, container_id=second.id)                    # 두 번째 복원이 바꾼 뒤 죽음
    assert sm.recover_restores() == [first]
    assert _names(sm) == [f"agentbox-{sid}"]

    sid2, _old2, _snap2 = _make(sm)
    gone = sm.client.containers.run(name=f"agentbox-{sid2}-restore-1", image="x", labels={RESTORE_LABEL: sid2})
    sm.delete(sid2)
    assert sm.recover_restores() == [gone.id]


# --- 데스크톱 준비: X 서버만이 아니라 Xfce 세션이 다 뜰 때까지 기다린다 (만들기·복원) ---
class _Booting:
    """X 서버는 바로 뜨고, Xfce 구성 요소는 ps를 볼 때마다 하나씩 늘어나는 컨테이너."""

    def __init__(self, stages):
        self.stages = list(stages)
        self.ps_calls = 0

    def exec_run(self, argv, **kw):
        if "ps" in argv:
            rows = self.stages[min(self.ps_calls, len(self.stages) - 1)]
            self.ps_calls += 1
            return ExecResult(0, "".join(f"{pid} {name}\n" for pid, name in rows).encode())
        return ExecResult(0, (b"1280 800", b""))


def _desk_tools(monkeypatch):
    from agentbox import sandbox_desktop as D
    monkeypatch.setattr(D, "_SESSION_SETTLE", 0.0)
    monkeypatch.setattr(D.time, "sleep", lambda s: None)
    return SandboxManager.__new__(SandboxManager)


def test_wait_display_waits_for_xfce_session_to_settle(monkeypatch):
    sm = _desk_tools(monkeypatch)
    x = [(28, "Xvfb")]
    core = [(83, "xfwm4"), (98, "xfsettingsd"), (102, "xfce4-panel"), (123, "xfdesktop")]
    c = _Booting([x, x + core[:2], x + core, x + core + [(107, "Thunar")], x + core + [(107, "Thunar")]])
    sm._wait_display(c, timeout=5)
    assert c.ps_calls == 5     # 구성 요소가 다 뜬 뒤에도 목록이 그대로일 때까지 기다렸다


def test_wait_display_fails_when_session_never_starts(monkeypatch):
    sm = _desk_tools(monkeypatch)
    with pytest.raises(SandboxError, match="Xfce"):
        sm._wait_display(_Booting([[(28, "Xvfb")]]), timeout=0.05)
