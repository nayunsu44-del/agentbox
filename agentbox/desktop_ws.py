"""화면 웹소켓 중계: 브라우저의 noVNC(RFB)와 컨테이너 안 x11vnc 사이에서 바이트를 그대로 옮기고, 연결·종료를 감사 로그에 남긴다.

인증(세션 쿠키, 출처, 연결 권한)은 api.py의 라우트가 먼저 끝낸다. 여기서는 인증된 세션과 모드를 받아 중계만 한다.
api를 import하지 않고, AgentBox는 인자로 받는다.
"""

from __future__ import annotations

import asyncio

from fastapi import WebSocket
from starlette.concurrency import run_in_threadpool

from .sandbox import SandboxError
from .service import AgentBox, ServiceError


async def relay(ws: WebSocket, box: AgentBox, sid: str, session: str, mode: str, cookie: str | None) -> None:
    # SQLite·감사 기록·Docker 호출은 이벤트 루프에서 하지 않는다. DB 쓰기 잠금을 다른 연결이 쥐고 있으면(정리 명령,
    # 큰 감사 조회 등) 기다리는 동안 모든 HTTP 요청이 멈췄다 (보안 검수 run-5)
    try:
        argv = await run_in_threadpool(box.sandboxes.vnc_command, sid, view_only=mode == "view")
        await run_in_threadpool(box.log_human, "desktop_connect", sid, {"session": session, "mode": mode})
    except (SandboxError, ServiceError):
        await ws.close(code=1011)
        return
    await ws.accept(subprotocol="binary" if "binary" in ws.scope.get("subprotocols", []) else None)
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL)
    loop = asyncio.get_running_loop()

    def kill() -> None:
        if proc.returncode is None:
            proc.kill()

    def close_from_any_thread() -> None:
        try:
            loop.call_soon_threadsafe(kill)
        except RuntimeError:  # 루프가 이미 닫힘 = 이 연결도 이미 끝남
            pass

    conn = box.desktop.add_conn(sid, session, mode, close_from_any_thread)
    if not box.desktop.may_connect(sid, session, mode):  # 그 사이에 돌려줬으면
        kill()
    up = down = 0

    async def browser_to_vnc() -> None:
        nonlocal up
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                return
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            up += len(data)
            proc.stdin.write(data)
            await proc.stdin.drain()
            if mode == "control":
                box.desktop.touch(sid, len(data))

    async def vnc_to_browser() -> None:
        nonlocal down
        while chunk := await proc.stdout.read(65536):
            down += len(chunk)
            await ws.send_bytes(chunk)

    ended = None

    async def session_watch() -> None:
        """세션은 연결할 때만 확인한다. 열린 채로 만료되거나 지워지면 끊고, 그 세션의 인수도 돌려준다."""
        nonlocal ended
        while True:
            await asyncio.sleep(box.desktop.recheck)
            if not await run_in_threadpool(box.desktop.session, cookie, sid):
                ended = "session_ended"
                lease = box.desktop.lease(sid)
                if lease and lease.session == session:
                    try:
                        await run_in_threadpool(box.handback, sid, session, "session_ended")
                    except ServiceError:
                        pass
                return

    started = loop.time()
    # 넷 중 하나라도 끝나면 연결을 닫는다 (x11vnc가 죽었는데 출력 EOF가 늦게 오는 경우 포함).
    tasks = [asyncio.create_task(browser_to_vnc()), asyncio.create_task(vnc_to_browser()),
             asyncio.create_task(proc.wait()), asyncio.create_task(session_watch())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # 감사 기록은 스레드에서 한다(이벤트 루프를 막지 않게). 정리 중의 await는 취소될 수 있으니 shield로 감싸고,
        # 취소되더라도 아래 등록 해제와 정리는 한다. 기록이 끝난 뒤에 등록을 지워, 연결이 사라졌으면 기록도 있다.
        payload = {"session": session, "mode": mode, "conn": conn.id, "seconds": round(loop.time() - started, 1),
                   "client_bytes": up, "server_bytes": down, **({"reason": ended} if ended else {})}
        logged = loop.run_in_executor(None, lambda: box.log_best_effort(sid, None, "desktop_disconnect", payload,
                                                                        actor="human"))
        try:
            await asyncio.shield(logged)
        finally:
            box.desktop.drop_conn(conn)
            for t in tasks:
                t.cancel()
            kill()
            try:
                await asyncio.wait_for(proc.wait(), 5)
                await ws.close(code=4000)
            except Exception:
                pass
