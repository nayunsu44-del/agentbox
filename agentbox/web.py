"""웹 UI (UX-1 ~ UX-6). FastAPI 템플릿 + HTMX.

- 로그인: 사람 토큰을 붙여 넣거나 'agentbox ui'가 주는 1회용 링크. 세션 쿠키(HttpOnly, SameSite=Strict)를 받는다.
- 첫 화면: 템플릿으로 샌드박스 만들기, 샌드박스 목록, 모든 승인 대기.
- 샌드박스 화면: 데스크톱 보기·인수(noVNC iframe), 끌어다 놓기로 파일 넣기, 결과함 내려받기,
  승인 요청(시스템이 계산한 요약 + 요청 시점 화면 캡처), 스냅샷, 감사 로그 타임라인과 해시 체인 검증.
- 승인 화면에는 에이전트가 쓴 설명을 보여주지 않는다. 실제 도구 인자와 시스템이 계산한 영향만 보여준다.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from docker.errors import APIError
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import approvals as A
from . import desktop as D
from .display import escape_controls
from .sandbox import SandboxError
from .service import AUDIT_BURST_WAIT, AgentBox, ServiceError

HERE = Path(__file__).parent
ACTORS = {"agent": "AI", "human": "사람", "system": "시스템"}
# HTML 이스케이프는 < > & 따옴표만 바꾼다. 양방향(bidi) 재배치 문자가 남으면 브라우저가 글자 순서를 바꿔 보여서,
# 승인 화면의 명령이 실제와 다르게 읽힌다 (보안 검수 run-3 v13). 터미널의 cli._safe와 같은 문자를 같은 모양으로
# 바꾸되, 줄바꿈과 탭은 화면에서 그대로 보여도 되니 남긴다 (display.escape_controls).
def _shown(value: Any) -> Any:
    """템플릿의 모든 {{ }} 출력에 거는 마무리. 에이전트·컨테이너가 정한 문자열이 어디에 찍히든 같이 막는다."""
    if isinstance(value, str):
        return escape_controls(value, keep_newlines=True)
    return value


def _short(v: Any, n: int = 160) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def describe(e: dict[str, Any]) -> str:
    """감사 항목 한 줄 요약 (타임라인용)."""
    p, ev = e["payload"], e["event"]
    if ev == "tool_request":
        return _short(p.get("args"))
    if ev == "policy_decision":
        return f"{p.get('action')}" + (f" ({p['rule_id']})" if p.get("rule_id") else "")
    if ev == "approval_requested":
        aff = (p.get("preview") or {}).get("affected") or []
        return f"{p.get('approval_id')} · 영향 {len(aff)}건" + (" · 화면 캡처" if p.get("capture") else "")
    if ev == "approval_decision":
        return f"{p.get('approval_id')} → {p.get('decision')}"
    if ev == "approval_expired":
        return f"{p.get('approval_id')} → 기한 지나 거부 ({p.get('timeout_s')}초)"
    if ev == "snapshot":
        return str(p.get("snapshot_id", ""))
    if ev == "tool_result":
        if "exit_code" in p:
            err = (p.get("stderr_head") or "").strip()
            return f"exit {p.get('exit_code')}" + (f" · {_short(err, 100)}" if err else "")
        return _short({k: v for k, v in p.items() if k != "request"})
    if ev == "gui_processes_stopped":
        procs = p.get("processes") or []
        return _short(f"GUI 구간({p.get('snapshot_id')}부터)에서 띄운 프로세스 {p.get('count', len(procs))}개 멈춤: "
                      + ", ".join(str(x.get("args", "")) for x in procs[:3]), 240)
    if ev == "gui_burst_open_failed":
        return _short(f"GUI 구간({p.get('snapshot_id')}부터)의 기준을 못 읽어 바뀐 파일을 기록하지 못함: {p.get('error')}", 240)
    if ev == "gui_burst_close_failed":
        return _short(f"GUI 구간({p.get('snapshot_id')}부터)을 끝까지 확인하지 못함 ({p.get('reason')}): {p.get('error')}", 240)
    if ev == "gui_changes":
        n = p.get("counts") or {}
        s = (f"GUI 구간({p.get('snapshot_id')}부터) 바뀐 파일: 추가 {n.get('added', 0)} · 변경 {n.get('modified', 0)}"
             f" · 삭제 {n.get('deleted', 0)}")
        if p.get("deleted"):
            s += " · 삭제됨: " + ", ".join(p["deleted"][:5]) + (" …" if n.get("deleted", 0) > 5 else "")
        return _short(s, 240)
    if ev in ("file_imported", "file_exported", "file_import_request"):
        return f"{p.get('name')} · {p.get('bytes')} bytes · sha256 {str(p.get('sha256', ''))[:16]}…"
    return _short({k: v for k, v in p.items() if k not in ("request",)})


def register(app: FastAPI, box: AgentBox, settings, human_token: str, *, guard: Callable,
             browser_human: Callable, human_only: Callable, same_origin: Callable) -> None:
    import secrets

    tpl = Jinja2Templates(directory=str(HERE / "templates"))
    tpl.env.globals.update(actors=ACTORS, describe=describe, runtime=box.sandboxes.runtime)
    tpl.env.filters["short"] = _short
    tpl.env.finalize = _shown

    def session_of(request: Request) -> str | None:
        return box.desktop.session(request.cookies.get(D.COOKIE))

    def render(request: Request, name: str, **ctx: Any) -> Response:
        """주기적으로 다시 받는 조각은 내용이 그대로면 204를 준다 (htmx는 204면 바꿔 끼우지 않는다).
        그래야 사람이 누르려던 승인 버튼이 누르는 순간 새 버튼으로 바뀌지 않는다."""
        r = tpl.TemplateResponse(request, name, ctx, headers={"Cache-Control": "no-store"})
        v = hashlib.sha256(r.body).hexdigest()[:16]
        if request.method == "GET" and request.headers.get("x-ab-have") == v:
            return Response(status_code=204, headers={"X-AB-Version": v, "Cache-Control": "no-store"})
        r.headers["X-AB-Version"] = v
        return r

    def start_session(request: Request, target: str, how: str) -> RedirectResponse:
        cookie, session = box.desktop.new_session()
        box.log_human("ui_login", None, {"session": session, "method": how})
        r = RedirectResponse(target, status_code=303)
        D.set_cookie(r, cookie, int(box.desktop.session_ttl),
                     settings.secure_cookie or request.url.scheme == "https")
        return r

    # ---- 로그인 -----------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def root(request: Request):
        return RedirectResponse("/ui" if session_of(request) else "/login", status_code=303)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request, ticket: str | None = None):
        if ticket:
            if not box.desktop.redeem(ticket, "*"):
                return render(request, "login.html", error="링크가 없거나 만료됨 (1회용, 60초)")
            return start_session(request, "/ui", "ticket")
        return render(request, "login.html", error=None)

    @app.post("/login", include_in_schema=False)
    def login(request: Request, token: str = Form(...)):
        if not same_origin(request.headers):
            raise HTTPException(403, "다른 출처의 요청")
        if not secrets.compare_digest(token.strip(), human_token):
            try:
                box.log_human("ui_login_failed", None, {})
            except ServiceError:
                pass
            return render(request, "login.html", error="사람 토큰이 아님 (에이전트 토큰으로는 들어갈 수 없음)")
        return start_session(request, "/ui", "token")

    @app.post("/logout", include_in_schema=False)
    def logout(request: Request):
        if not same_origin(request.headers):
            raise HTTPException(403, "다른 출처의 요청")
        s = box.end_ui_session(request.cookies.get(D.COOKIE))
        if s:
            box.log_best_effort(None, None, "ui_logout", {"session": s}, actor="human")
        r = RedirectResponse("/login", status_code=303)
        r.delete_cookie(D.COOKIE)
        return r

    @app.post("/ui/ticket", status_code=201)
    def ui_ticket(p=Depends(human_only)):
        t = box.desktop.issue_ticket("*")
        return {"path": f"/login?ticket={t}", "expires_in": box.desktop.ticket_ttl}

    @app.get("/static/htmx.min.js", include_in_schema=False)
    def htmx():
        return FileResponse(HERE / "static" / "htmx.min.js", media_type="text/javascript",
                            headers={"Cache-Control": "max-age=86400"})

    # ---- 첫 화면 ----------------------------------------------------------
    @app.get("/ui", include_in_schema=False)
    def index(request: Request):
        if not session_of(request):
            return RedirectResponse("/login", status_code=303)
        return render(request, "index.html", templates=sorted(settings.templates()))

    @app.get("/ui/sandboxes", include_in_schema=False)
    def sandboxes_frag(request: Request, p=Depends(browser_human)):
        return render(request, "_sandboxes.html", sandboxes=box.sandboxes.list())

    @app.post("/ui/sandboxes", include_in_schema=False)
    def create(request: Request, template: str = Form("desktop"), source_dir: str = Form(""),
               p=Depends(browser_human)):
        try:
            rec, token = box.create_sandbox(source_dir.strip() or None, template, p.session)
        except (SandboxError, ServiceError) as e:
            return render(request, "_error.html", message=str(e))
        url = str(request.base_url).rstrip("/")
        env = {"AGENTBOX_URL": url, "AGENTBOX_SANDBOX_ID": rec["id"], "AGENTBOX_AGENT_TOKEN": token}
        mcp = {"mcpServers": {"agentbox": {"command": "python3", "args": ["-m", "agentbox.mcp_server"], "env": env}}}
        r = render(request, "_created.html", sb=rec, token=token, mcp=json.dumps(mcp, indent=2, ensure_ascii=False),
                   claude=" ".join(f"-e {k}={v}" for k, v in env.items()))
        r.headers["HX-Trigger"] = "sandboxes-changed"
        return r

    @app.get("/ui/notify", include_in_schema=False)
    def notify(request: Request, p=Depends(browser_human)):
        box.expire_stale()
        return render(request, "_notify.html", pending=box.approvals.list(status=A.PENDING))

    # ---- 샌드박스 화면 ----------------------------------------------------
    @app.get("/ui/sandboxes/{sid}", include_in_schema=False)
    def sandbox_page(request: Request, sid: str):
        if not session_of(request):
            return RedirectResponse("/login", status_code=303)
        try:
            sb = box.sandboxes.get(sid)
        except SandboxError:
            raise HTTPException(404, "샌드박스 없음")
        return render(request, "sandbox.html", sb=sb, desktop=box.sandboxes.template_of(sid).desktop,
                      max_upload=settings.max_upload_bytes)

    def approvals_view(request: Request, sandbox_id: str | None, error: str | None = None) -> HTMLResponse:
        box.expire_stale()
        pending = box.approvals.list(status=A.PENDING, sandbox_id=sandbox_id)
        done = [a for a in box.approvals.list(sandbox_id=sandbox_id) if a["status"] != A.PENDING][-5:][::-1]
        return render(request, "_approvals.html", pending=pending, done=done, sandbox_id=sandbox_id or "",
                      timeout=box.approval_timeout, error=error)

    @app.get("/ui/approvals", include_in_schema=False)
    def approvals_frag(request: Request, sandbox_id: str | None = None, p=Depends(browser_human)):
        return approvals_view(request, sandbox_id)

    @app.post("/ui/approvals/{aid}/{decision}", include_in_schema=False)
    def decide(request: Request, aid: str, decision: str, sandbox_id: str = "", p=Depends(browser_human)):
        if decision not in ("approve", "deny"):
            raise HTTPException(400, "approve 또는 deny")
        error = None
        try:
            box.decide(aid, decision == "approve", actor="human", session=p.session)
        except ServiceError as e:
            error = e.message
        r = approvals_view(request, sandbox_id or None, error)
        r.headers["HX-Trigger"] = "audit-changed"
        return r

    @app.get("/ui/sandboxes/{sid}/outbox", include_in_schema=False)
    def outbox_frag(request: Request, sid: str, p=Depends(browser_human)):
        try:
            files = box.sandboxes.outbox_list(sid)
        except SandboxError as e:
            return render(request, "_error.html", message=str(e))
        except APIError:
            # 스냅샷(docker commit)이 컨테이너를 잠깐 멈춘 사이. 지금 보이는 목록을 그대로 둔다.
            return Response(status_code=204, headers={"Cache-Control": "no-store"})
        return render(request, "_outbox.html", sid=sid, files=files)

    @app.get("/ui/sandboxes/{sid}/snapshots", include_in_schema=False)
    def snapshots_frag(request: Request, sid: str, p=Depends(browser_human)):
        return render(request, "_snapshots.html", sid=sid, snaps=box.sandboxes.list_snapshots(sid)[::-1])

    @app.post("/ui/sandboxes/{sid}/snapshots", include_in_schema=False)
    def take_snapshot(request: Request, sid: str, p=Depends(browser_human)):
        guard(lambda: box.snapshot_sandbox(sid, p.session))
        r = snapshots_frag(request, sid, p)
        r.headers["HX-Trigger"] = "audit-changed"
        return r

    @app.post("/ui/sandboxes/{sid}/restore/{snap_id}", include_in_schema=False)
    def restore(request: Request, sid: str, snap_id: str, p=Depends(browser_human)):
        guard(lambda: box.restore_sandbox(sid, snap_id, p.session))
        r = snapshots_frag(request, sid, p)
        r.headers["HX-Trigger"] = "audit-changed"
        return r

    @app.post("/ui/sandboxes/{sid}/delete", include_in_schema=False)
    def delete(request: Request, sid: str, p=Depends(browser_human)):
        guard(lambda: box.delete_sandbox(sid, p.session))
        return Response("", headers={"HX-Redirect": "/ui"})

    # ---- 감사 로그 타임라인 (UX-6) -----------------------------------------
    @app.get("/ui/audit", include_in_schema=False)
    def audit_frag(request: Request, sandbox_id: str | None = None, p=Depends(browser_human)):
        box.close_idle_gui_bursts(wait=AUDIT_BURST_WAIT)
        rows, total = box.audit.recent(sandbox_id=sandbox_id, limit=400)
        return render(request, "_audit.html", rows=rows, total=total, broken=None)

    @app.get("/ui/verify", include_in_schema=False)
    def verify_frag(request: Request, sandbox_id: str | None = None, p=Depends(browser_human)):
        v = box.audit.verify()
        here = None
        if v.broken_at is not None and sandbox_id:
            here = box.audit.belongs_to(v.broken_at, sandbox_id)
        box.log_best_effort(sandbox_id, None, "audit_verified", {"ok": v.ok, "checked": v.checked,
                                                                 "broken_at": v.broken_at, "session": p.session},
                            actor="human")
        return render(request, "_verify.html", v=v, here=here)
