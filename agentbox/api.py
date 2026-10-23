"""HTTP API (컨트롤 플레인).

토큰은 두 종류다 (NF-2, AP-3).
- 사람 토큰: 샌드박스 관리, 승인·거절, 감사 로그 조회.
- 에이전트 토큰: 샌드박스마다 따로 발급. 자기 샌드박스의 도구 호출과 자기 승인 요청의 상태 조회만.
  승인 API(POST /approvals/{id})는 에이전트 토큰으로 부르면 403이다.
- 브라우저(웹 UI, 화면)는 사람 토큰 또는 1회용 티켓으로 로그인해 세션 쿠키를 받는다.
  쿠키는 웹 UI·화면·파일 넣기/받기·승인 캡처 경로에서만 받고, JSON 관리 API는 헤더 토큰만 받는다.
"""

from __future__ import annotations

import asyncio
import secrets
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import desktop as D
from .approvals import ApprovalStore
from .audit import AuditLog
from .config import Settings
from .desktop_ws import relay
from .policy import Policy
from .sandbox import SandboxError, SandboxManager
from .service import AUDIT_BURST_WAIT, AgentBox, ServiceError
from . import web


@dataclass
class Principal:
    kind: str                 # "human" | "agent"
    sandbox_id: str | None = None
    session: str | None = None  # 브라우저 세션으로 들어온 사람 (hs_…)
    scope: str = "*"            # 브라우저 세션의 범위: '*' 또는 화면 링크의 샌드박스 id


class CreateSandbox(BaseModel):
    source_dir: str | None = None    # 비우면 빈 원본 폴더 (파일은 /sandboxes/{id}/files로 넣는다)
    template: str = "cli"


class ToolCall(BaseModel):
    args: dict[str, Any] = {}


class Decision(BaseModel):
    decision: str             # "approve" | "deny"


class Restore(BaseModel):
    snapshot_id: str


class _NoFraming:
    """쿠키로 로그인한 화면을 다른 출처가 iframe에 넣고 승인 버튼을 누르게 하지 못하게 한다 (보안 검수 run-3 v14).
    샌드박스 화면이 띄우는 데스크톱 iframe은 같은 출처라 그대로 된다."""
    HEADERS = [(b"x-frame-options", b"SAMEORIGIN"), (b"content-security-policy", b"frame-ancestors 'self'")]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *self.HEADERS]
            await send(message)

        await self.app(scope, receive, send_with_headers)


def build(settings: Settings | None = None) -> tuple[FastAPI, AgentBox, str]:
    settings = settings or Settings()
    settings.home.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(settings.db_path)
    human_token = settings.human_token()
    audit.register_secret(human_token)
    box = AgentBox(
        audit=audit,
        policy=Policy.load(settings.policy_path),
        sandboxes=SandboxManager(settings, settings.db_path),
        approvals=ApprovalStore(settings.db_path),
        desktop=D.DesktopControl(idle=settings.takeover_idle, db_path=settings.db_path,
                                 token_gen=D.token_gen(human_token)),
        approval_timeout=settings.approval_timeout,
        captures=settings.home / "captures",
    )
    box.recover_takeovers()
    novnc_dir = settings.home / "novnc"
    # 도구 호출은 사람 API와 다른 스레드 풀에서 돈다. exec는 제한 시간 내내 스레드를 붙잡으므로,
    # 같은 풀을 쓰면 에이전트가 승인·삭제 같은 사람 API를 멈춰 세울 수 있다.
    tool_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="agentbox-tool")

    @asynccontextmanager
    async def lifespan(_app):
        yield
        tool_pool.shutdown(wait=False, cancel_futures=True)
        box.close()

    app = FastAPI(title="agentbox", version="0.1.0", lifespan=lifespan)
    app.state.box = box
    app.add_middleware(_NoFraming)

    def principal(authorization: str = Header(default="")) -> Principal:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Authorization: Bearer <token> 필요")
        token = authorization.split(" ", 1)[1].strip()
        if secrets.compare_digest(token, human_token):
            return Principal("human")
        sid = box.sandboxes.sandbox_for_token(token)
        if sid:
            return Principal("agent", sid)
        raise HTTPException(401, "알 수 없는 토큰")

    def human_only(p: Principal = Depends(principal)) -> Principal:
        if p.kind != "human":
            raise HTTPException(403, "사람 토큰만 쓸 수 있는 API")
        return p

    def same_origin(headers) -> bool:
        origin = headers.get("origin")
        return not origin or urlsplit(origin).netloc == headers.get("host")

    def secure_cookie(request: Request) -> bool:
        return settings.secure_cookie or request.url.scheme == "https"

    def screen_principal(request: Request, authorization: str = Header(default="")) -> Principal:
        """브라우저 경로 전용: Authorization 헤더 또는 브라우저 세션 쿠키."""
        if authorization:
            return principal(authorization)
        got = box.desktop.session_scope(request.cookies.get(D.COOKIE))
        if not got:
            raise HTTPException(401, "세션 없음. 'agentbox ui'로 로그인 링크를 받을 것")
        if not same_origin(request.headers):
            raise HTTPException(403, "다른 출처의 요청")
        return Principal("human", session=got[0], scope=got[1])

    def screen_human(p: Principal = Depends(screen_principal)) -> Principal:
        """웹 UI 전체 권한. 화면 링크로 받은 세션은 그 샌드박스 화면 말고는 쓸 수 없다."""
        if p.kind != "human":
            raise HTTPException(403, "사람만 쓸 수 있는 경로")
        if p.scope != "*":
            raise HTTPException(403, f"이 세션은 샌드박스 {p.scope} 화면 전용. 'agentbox ui'로 로그인할 것")
        return p

    def desktop_human(sid: str, p: Principal = Depends(screen_principal)) -> Principal:
        """그 샌드박스의 화면 경로. 웹 UI 세션과 그 샌드박스의 화면 링크 세션이 쓸 수 있다."""
        if p.kind != "human":
            raise HTTPException(403, "사람만 쓸 수 있는 경로")
        if p.scope not in ("*", sid):
            raise HTTPException(403, f"이 세션은 샌드박스 {p.scope} 화면 전용")
        return p

    def guard(fn):
        try:
            return fn()
        except ServiceError as e:
            raise HTTPException(e.status, e.message) from e
        except SandboxError as e:
            raise HTTPException(400, str(e)) from e

    # ---- 샌드박스 --------------------------------------------------------
    @app.post("/sandboxes", status_code=201)
    def create_sandbox(body: CreateSandbox, p: Principal = Depends(human_only)):
        rec, token = guard(lambda: box.create_sandbox(body.source_dir, body.template))
        return {**rec, "agent_token": token}

    @app.get("/sandboxes")
    def list_sandboxes(p: Principal = Depends(human_only)):
        return box.sandboxes.list()

    @app.get("/sandboxes/{sid}")
    def get_sandbox(sid: str, p: Principal = Depends(principal)):
        if p.kind == "agent" and p.sandbox_id != sid:
            raise HTTPException(403, "다른 샌드박스")
        return guard(lambda: box.sandboxes.get(sid))

    @app.post("/sandboxes/{sid}/pause")
    def pause(sid: str, p: Principal = Depends(human_only)):
        return guard(lambda: box.pause_sandbox(sid))

    @app.post("/sandboxes/{sid}/resume")
    def resume(sid: str, p: Principal = Depends(human_only)):
        return guard(lambda: box.resume_sandbox(sid))

    @app.post("/sandboxes/{sid}/snapshots", status_code=201)
    def snapshot(sid: str, p: Principal = Depends(human_only)):
        return guard(lambda: box.snapshot_sandbox(sid))

    @app.get("/sandboxes/{sid}/snapshots")
    def list_snapshots(sid: str, p: Principal = Depends(human_only)):
        return box.sandboxes.list_snapshots(sid)

    @app.post("/sandboxes/{sid}/restore")
    def restore(sid: str, body: Restore, p: Principal = Depends(human_only)):
        return guard(lambda: box.restore_sandbox(sid, body.snapshot_id))

    @app.delete("/sandboxes/{sid}")
    def delete(sid: str, p: Principal = Depends(human_only)):
        guard(lambda: box.delete_sandbox(sid))
        return {"deleted": sid}

    # ---- 도구 ----------------------------------------------------------
    @app.post("/sandboxes/{sid}/tools/{tool}")
    async def call_tool(sid: str, tool: str, body: ToolCall, p: Principal = Depends(principal)):
        if p.kind == "agent" and p.sandbox_id != sid:
            raise HTTPException(403, "이 에이전트 토큰은 다른 샌드박스용")
        out = await asyncio.get_running_loop().run_in_executor(
            tool_pool, lambda: guard(lambda: box.call_tool(sid, tool, body.args, actor=p.kind)))
        return JSONResponse(out.body, status_code=out.status)

    # ---- 승인 ----------------------------------------------------------
    @app.get("/approvals")
    def list_approvals(status: str | None = Query(default=None), sandbox_id: str | None = None,
                       p: Principal = Depends(human_only)):
        box.expire_stale()
        return box.approvals.list(status=status, sandbox_id=sandbox_id)

    @app.get("/approvals/{aid}")
    def get_approval(aid: str, p: Principal = Depends(principal)):
        box.expire_stale()
        apr = box.approvals.get(aid)
        if not apr:
            raise HTTPException(404, "승인 요청 없음")
        if p.kind == "agent":
            if apr["sandbox_id"] != p.sandbox_id:
                raise HTTPException(403, "다른 샌드박스의 승인 요청")
            # 에이전트에게는 결정과 결과만 준다.
            return {k: apr.get(k) for k in ("id", "status", "result", "decided_at")}
        return apr

    @app.get("/approvals/{aid}/capture.png")
    def approval_capture(aid: str, p: Principal = Depends(screen_human)):
        f = box.capture_path(aid)
        if not f:
            raise HTTPException(404, "화면 캡처 없음")
        return FileResponse(f, media_type="image/png", headers={"Cache-Control": "private, max-age=3600"})

    @app.post("/approvals/{aid}")
    def decide(aid: str, body: Decision, p: Principal = Depends(principal)):
        if p.kind != "human":
            # 시도 자체도 기록한다.
            try:
                audit.append(actor="agent", event="approval_forbidden", sandbox_id=p.sandbox_id,
                             payload={"approval_id": aid})
            except Exception:
                pass
            raise HTTPException(403, "에이전트 토큰으로는 승인할 수 없음")
        if body.decision not in ("approve", "deny"):
            raise HTTPException(400, "decision은 approve 또는 deny")
        return guard(lambda: box.decide(aid, body.decision == "approve", actor="human"))

    # ---- 감사 ----------------------------------------------------------
    @app.get("/audit")
    def list_audit(sandbox_id: str | None = None, after_id: int = 0, limit: int = 500,
                   p: Principal = Depends(human_only)):
        box.bursts.close_idle(wait=AUDIT_BURST_WAIT)
        return audit.list(sandbox_id=sandbox_id, after_id=after_id, limit=min(limit, 5000))

    @app.get("/audit/verify")
    def verify(p: Principal = Depends(human_only)):
        return audit.verify().as_dict()

    # ---- 파일 넣기·결과함 (UX-3, UX-4) ---------------------------------
    @app.post("/sandboxes/{sid}/files", status_code=201)
    async def put_files(sid: str, files: list[UploadFile] = File(...), p: Principal = Depends(screen_human)):
        limit = settings.max_upload_bytes
        out = []
        for f in files:
            data = await f.read(limit + 1)
            if len(data) > limit:
                raise HTTPException(413, f"파일이 너무 큼: {f.filename} (최대 {limit} bytes)")
            out.append(await run_in_threadpool(
                lambda d=data, n=f.filename or "": guard(lambda: box.import_file(sid, n, d, p.session))))
        return out

    @app.get("/sandboxes/{sid}/outbox")
    def outbox(sid: str, p: Principal = Depends(screen_human)):
        return guard(lambda: box.sandboxes.outbox_list(sid))

    @app.get("/sandboxes/{sid}/outbox/{name}")
    def outbox_file(sid: str, name: str, p: Principal = Depends(screen_human)):
        data = guard(lambda: box.export_file(sid, name, p.session))
        quoted = quote(name)
        return Response(data, media_type="application/octet-stream", headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quoted}", "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff"})

    # ---- 화면 보기·인수 (UX-1, UX-2) -----------------------------------
    @app.post("/sandboxes/{sid}/desktop/ticket", status_code=201)
    def desktop_ticket(sid: str, p: Principal = Depends(human_only)):
        guard(lambda: box.sandboxes._desktop(sid))
        box.log_human("desktop_ticket_issued", sid, {"ttl_s": box.desktop.ticket_ttl})
        t = box.desktop.issue_ticket(sid)
        return {"ticket": t, "path": f"/sandboxes/{sid}/desktop?ticket={t}", "expires_in": box.desktop.ticket_ttl}

    @app.get("/sandboxes/{sid}/desktop")
    def desktop_page(sid: str, request: Request, ticket: str | None = None):
        if ticket:
            got = box.desktop.redeem(ticket, sid)
            if not got:
                raise HTTPException(403, "티켓이 없거나 만료됨 (1회용, 60초)")
            cookie, session = got
            box.log_human("desktop_session_start", sid, {"session": session})
            r = RedirectResponse(f"/sandboxes/{sid}/desktop", status_code=303)
            D.set_cookie(r, cookie, int(box.desktop.session_ttl), secure_cookie(request))
            return r
        if not box.desktop.session(request.cookies.get(D.COOKIE), sid):
            raise HTTPException(401, "세션 없음. 'agentbox desktop <id>'로 링크를 받을 것")
        rec = guard(lambda: box.sandboxes.get(sid))
        guard(lambda: box.sandboxes._desktop(sid))
        return HTMLResponse(D.page(sid, rec["runtime"]), headers={"Cache-Control": "no-store"})

    @app.get("/sandboxes/{sid}/desktop/state")
    def desktop_state(sid: str, p: Principal = Depends(screen_principal)):
        if (p.kind == "agent" and p.sandbox_id != sid) or p.scope not in ("*", sid):
            raise HTTPException(403, "다른 샌드박스")
        guard(lambda: box.sandboxes.get(sid))
        return box.desktop.state(sid, p.session)

    @app.post("/sandboxes/{sid}/desktop/takeover")
    def desktop_takeover(sid: str, p: Principal = Depends(desktop_human)):
        if not p.session:
            raise HTTPException(400, "화면 인수는 브라우저 세션에서만 (입력 연결이 그 세션에 묶인다)")
        return guard(lambda: box.takeover(sid, p.session))

    @app.post("/sandboxes/{sid}/desktop/handback")
    def desktop_handback(sid: str, p: Principal = Depends(desktop_human)):
        # 사람 토큰(Authorization)으로 부르면 어느 세션이든 강제로 돌려준다.
        return guard(lambda: box.handback(sid, p.session))

    @app.websocket("/sandboxes/{sid}/desktop/ws")
    async def desktop_ws(ws: WebSocket, sid: str, mode: str = "view"):
        cookie = ws.cookies.get(D.COOKIE)
        session = box.desktop.session(cookie, sid)
        if not session or not same_origin(ws.headers) or mode not in ("view", "control"):
            await ws.close(code=4401)
            return
        if not box.desktop.may_connect(sid, session, mode):
            await ws.close(code=4403)
            return
        await relay(ws, box, sid, session, mode, cookie)

    @app.get("/static/novnc/{path:path}")
    def novnc(path: str):
        root = novnc_dir.resolve()
        if not box.sandboxes.extract_novnc(novnc_dir):
            raise HTTPException(404, "noVNC 파일 없음 (데스크톱 이미지가 빌드되지 않음)")
        f = (root / path).resolve()
        if not f.is_relative_to(root) or not f.is_file():
            raise HTTPException(404)
        return FileResponse(f)

    web.register(app, box, settings, human_token, guard=guard, browser_human=screen_human, human_only=human_only,
                 same_origin=same_origin)

    @app.get("/healthz")
    def health():
        return {"ok": True, "runtime": box.sandboxes.runtime, "image": settings.image,
                "templates": sorted(settings.templates()), "dev_only": box.sandboxes.runtime == "runc"}

    return app, box, human_token


def create_app() -> FastAPI:
    """uvicorn agentbox.api:create_app --factory"""
    return build()[0]
