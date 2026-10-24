import pytest


@pytest.fixture(autouse=True)
def _close_boxes(monkeypatch):
    """FastAPI는 엔드포인트 함수를 모듈 전역 캐시에 붙잡아 둔다. 그래서 테스트마다 build()한 서버의
    DB·Docker 연결이 프로세스가 끝날 때까지 남아 파일 핸들이 바닥난다. 테스트가 끝나면 닫는다."""
    try:
        import agentbox.api as api
    except ImportError:  # pragma: no cover
        yield
        return
    made = []
    real = api.build

    def build(*a, **kw):
        out = real(*a, **kw)
        made.append(out[1])
        return out

    monkeypatch.setattr(api, "build", build)
    yield
    for box in made:
        box.close()


class FakeAudit:
    """메모리에만 감사 행을 쌓는 테스트용 대역."""

    def __init__(self):
        self.rows = []

    def append(self, **row):
        self.rows.append(row)
        return len(self.rows)


def build_fake_app(tmp_path, monkeypatch):
    """Docker 데몬 없이 라우트·미들웨어·웹소켓을 검증하는 테스트용 앱."""
    import docker

    from agentbox import api

    class _C:
        id = "c" * 64
        status = "running"
        attrs = {"State": {"Status": "running"}}

    class _Client:
        containers = type("Cs", (), {"get": lambda self, cid: _C()})()

        def info(self):
            return {"Runtimes": {"runc": {}}}

        def close(self):
            pass

    monkeypatch.setattr(docker, "from_env", lambda *a, **k: _Client())
    for k, v in {"AGENTBOX_HOME": str(tmp_path), "AGENTBOX_HUMAN_TOKEN": "hum_" + "d" * 40,
                 "AGENTBOX_DOCKER_CLI": "/bin/false", "AGENTBOX_MIN_FREE": "0"}.items():
        monkeypatch.setenv(k, v)
    app, box, human = api.build()
    box.sandboxes.conn.execute(
        "INSERT INTO sandboxes (id, container_id, source_dir, image, runtime, token_hash, status, created_at, template)"
        " VALUES ('sb_x', ?, '/tmp', 'img', 'runc', 'h', 'running', '2026-01-01', 'desktop')", (_C.id,))
    return app, box, human
