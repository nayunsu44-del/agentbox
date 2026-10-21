"""LLM API 에이전트 루프 테스트.

진짜 LLM 대신 대본대로 답하는 가짜 API 서버(OpenAI 형식, Anthropic 형식)를 띄우고,
컨트롤 플레인은 실제 Docker 샌드박스로 돌린다. 승인은 다른 스레드에서 사람 토큰으로 한다.
"""

import json
import threading
import time

import pytest

docker = pytest.importorskip("docker")
try:
    docker.from_env().ping()
except Exception:  # pragma: no cover
    pytest.skip("Docker 데몬이 없음", allow_module_level=True)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agentbox import agent as ag  # noqa: E402

# 대본: 폴더 보기 → 파일 읽기 → 삭제 시도(승인 대기) → 마지막 도구 결과를 그대로 말하고 끝
SCRIPT = [
    ("list_dir", {"path": "/workspace"}),
    ("read_file", {"path": "/workspace/old-report.md"}),
    ("exec", {"command": "rm /workspace/old-report.md && echo removed"}),
]


def openai_mock(record):
    app = FastAPI()

    @app.post("/chat/completions")
    async def chat(req: Request):
        body = await req.json()
        record.append({"headers": dict(req.headers), "body": body})
        n = sum(1 for m in body["messages"] if m["role"] == "tool")
        if n < len(SCRIPT):
            name, args = SCRIPT[n]
            msg = {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"call_{n}", "type": "function",
                 "function": {"name": name, "arguments": json.dumps(args)}}]}
        else:
            last = [m for m in body["messages"] if m["role"] == "tool"][-1]["content"]
            msg = {"role": "assistant", "content": "끝. 마지막 결과: " + last}
        return {"choices": [{"index": 0, "message": msg, "finish_reason": "stop"}]}

    return app


def anthropic_mock(record):
    app = FastAPI()

    @app.post("/v1/messages")
    async def messages(req: Request):
        body = await req.json()
        record.append({"headers": dict(req.headers), "body": body})
        results = [b for m in body["messages"] if m["role"] == "user" and isinstance(m["content"], list)
                   for b in m["content"] if b.get("type") == "tool_result"]
        n = len(results)
        if n < len(SCRIPT):
            name, args = SCRIPT[n]
            content = [{"type": "text", "text": f"{n + 1}단계"},
                       {"type": "tool_use", "id": f"toolu_{n}", "name": name, "input": args}]
            stop = "tool_use"
        else:
            content = [{"type": "text", "text": "끝. 마지막 결과: " + results[-1]["content"]}]
            stop = "end_turn"
        return {"id": "msg", "type": "message", "role": "assistant", "content": content, "stop_reason": stop}

    return app


@pytest.fixture()
def plane(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_HOME", str(tmp_path / "data"))
    monkeypatch.delenv("AGENTBOX_HUMAN_TOKEN", raising=False)
    src = tmp_path / "reports"
    src.mkdir()
    (src / "old-report.md").write_text("# 오래된 보고서\n매출 10억\n")
    from agentbox.api import build

    app, box, human = build()
    human_client = TestClient(app)
    H = {"Authorization": f"Bearer {human}"}
    sb = human_client.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json()
    yield app, human_client, H, sb
    human_client.delete(f"/sandboxes/{sb['id']}", headers=H)


def _run_with_decision(plane, provider, decision):
    app, human_client, H, sb = plane
    record: list = []
    mock = openai_mock(record) if provider == "openai" else anthropic_mock(record)
    cfg = ag.LLMConfig(provider=provider, base_url="http://llm", model="test-model", api_key="sk-test-123")
    llm_client = TestClient(mock, headers=(
        {"Authorization": "Bearer sk-test-123"} if provider == "openai"
        else {"x-api-key": "sk-test-123", "anthropic-version": "2023-06-01"}))
    chat = ag.make_chat(cfg, client=llm_client)
    pending: list[str] = []
    tools = ag.ToolClient("http://plane", sb["id"], sb["agent_token"], client=TestClient(app),
                          poll_interval=0.1, on_pending=pending.append)
    out: dict = {}
    t = threading.Thread(target=lambda: out.setdefault("res", ag.run("오래된 보고서 정리해", chat, tools)))
    t.start()
    for _ in range(200):
        if pending:
            break
        time.sleep(0.05)
    assert pending, "삭제 명령이 승인 대기에 걸리지 않음"
    # 결정 전에는 파일이 그대로다
    ls = TestClient(app).post(f"/sandboxes/{sb['id']}/tools/list_dir", json={"args": {"path": "/workspace"}},
                              headers={"Authorization": f"Bearer {sb['agent_token']}"}).json()
    assert "old-report.md" in ls["result"]["listing"]
    r = human_client.post(f"/approvals/{pending[0]}", json={"decision": decision}, headers=H)
    assert r.status_code == 200
    t.join(timeout=60)
    assert not t.is_alive()
    return out["res"], record, human_client, H, sb


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_agent_loop_approved(plane, provider):
    res, record, human_client, H, sb = _run_with_decision(plane, provider, "approve")
    assert res.stopped == "done" and res.steps == 4
    assert [c["name"] for c in res.tool_calls] == ["list_dir", "read_file", "exec"]
    assert "old-report.md" in res.tool_calls[0]["result"]
    assert "오래된 보고서" in res.tool_calls[1]["result"]
    assert '"approval": "approved"' in res.tool_calls[2]["result"] and "removed" in res.tool_calls[2]["result"]
    assert "removed" in res.final_text
    # API 형식 확인: 키 헤더, 모델 이름, 도구 정의, 시스템 프롬프트
    first = record[0]
    assert first["body"]["model"] == "test-model"
    if provider == "openai":
        assert first["headers"]["authorization"] == "Bearer sk-test-123"
        assert first["body"]["messages"][0]["role"] == "system"
        assert {t["function"]["name"] for t in first["body"]["tools"]} == {"list_dir", "read_file", "exec"}
        ids = [m["tool_call_id"] for m in record[-1]["body"]["messages"] if m["role"] == "tool"]
        assert ids == ["call_0", "call_1", "call_2"]
    else:
        assert first["headers"]["x-api-key"] == "sk-test-123"
        assert "샌드박스" in first["body"]["system"]
        assert {t["name"] for t in first["body"]["tools"]} == {"list_dir", "read_file", "exec"}
    # 감사 로그에 에이전트 요청·승인·실행이 남고 체인이 온전하다
    events = [e["event"] for e in human_client.get("/audit", headers=H).json()]
    assert events.count("tool_request") >= 4 and "approval_decision" in events and "snapshot" in events
    assert human_client.get("/audit/verify", headers=H).json()["ok"]


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_agent_loop_denied(plane, provider):
    res, record, human_client, H, sb = _run_with_decision(plane, provider, "deny")
    assert '"approval": "denied"' in res.tool_calls[2]["result"]
    assert "거절" in res.final_text
    ls = human_client.post(f"/sandboxes/{sb['id']}/tools/list_dir", json={"args": {"path": "/workspace"}},
                           headers=H).json()
    assert "old-report.md" in ls["result"]["listing"]


def test_agent_token_cannot_be_human(capsys, monkeypatch):
    from agentbox.cli import main

    monkeypatch.setenv("AGENTBOX_LLM_MODEL", "m")
    with pytest.raises(SystemExit) as e:
        main(["agent", "hi", "--sandbox", "sb_x", "--token", "hum_abcdefghijklmnopqrstuvwx"])
    assert "사람 토큰" in str(e.value)


def test_make_chat_requires_model():
    with pytest.raises(ValueError):
        ag.make_chat(ag.LLMConfig(provider="openai", model=""))
