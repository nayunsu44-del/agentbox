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
