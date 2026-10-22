"""터미널 도구: 서버 실행, 샌드박스 관리, 터미널 승인, 감사 로그 조회·검증.

  agentbox serve [--tls-cert C --tls-key K | --behind-tls-proxy]   컨트롤 플레인 실행
  agentbox create <원본 폴더> [--template desktop]   샌드박스 생성, 에이전트 토큰과 MCP 설정 출력
  agentbox ui [--base-url URL]                      웹 UI 로그인 링크 (1회용, 60초)
  agentbox desktop <ID> [--base-url URL]            브라우저 화면 링크 (1회용, 60초)
  agentbox approve                     승인 요청을 기다렸다가 터미널에서 승인·거절
  agentbox audit [--sandbox ID]        감사 로그 타임라인
  agentbox verify                      해시 체인 검증
  agentbox snapshots <ID> / restore <ID> <SNAP> / list / delete <ID>
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from typing import Any

import httpx

from .config import Settings

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = CYAN = RESET = ""

# C0·DEL·C1 제어 문자와 양방향(bidi) 재배치 문자. 터미널이 해석하면 커서 이동·줄 지우기·글자 순서
# 뒤집기로 화면에 보이는 내용을 바꿀 수 있다.
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _safe(s: Any) -> str:
    """에이전트가 정한 문자열을 터미널에 그대로 찍지 않는다. 제어 문자는 \\x1b처럼 보이게 바꾼다."""
    return _UNSAFE.sub(lambda m: f"\\x{ord(m[0]):02x}" if ord(m[0]) < 0x100 else f"\\u{ord(m[0]):04x}", str(s))


def _url() -> str:
    return os.environ.get("AGENTBOX_URL", "http://127.0.0.1:8765").rstrip("/")


def _client() -> httpx.Client:
    token = Settings().human_token()
    return httpx.Client(base_url=_url(), headers={"Authorization": f"Bearer {token}"}, timeout=120)


def _check(r: httpx.Response) -> Any:
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail")
        except ValueError:
            msg = r.text
        sys.exit(f"{RED}오류 {r.status_code}: {msg}{RESET}")
    return r.json()


# ---- 명령 -----------------------------------------------------------------

def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def bind_problem(host: str, tls: bool, behind_tls_proxy: bool) -> str | None:
    """평문 HTTP로 127.0.0.1 밖에 열면 사람 토큰·쿠키·화면이 그대로 지나간다. 문제가 있으면 이유를 돌려준다."""
    if is_loopback(host) or tls or behind_tls_proxy:
        return None
    return (f"{host}에 TLS 없이 열 수 없음. 사람 토큰, 세션 쿠키, 에이전트 토큰, 화면, 파일이 평문으로 지나가고 "
            "승인 카드를 중간에서 바꿀 수 있다. --tls-cert/--tls-key를 주거나 TLS 프록시 뒤라면 "
            "--behind-tls-proxy를 쓸 것 (deploy/의 docker compose 참고)")


def cmd_serve(a: argparse.Namespace) -> None:
    import uvicorn

    from .api import build

    if bool(a.tls_cert) != bool(a.tls_key):
        sys.exit(f"{RED}--tls-cert와 --tls-key는 함께 줘야 함{RESET}")
    tls = bool(a.tls_cert)
    behind = a.behind_tls_proxy or os.environ.get("AGENTBOX_BEHIND_TLS_PROXY", "") in ("1", "true", "yes")
    problem = bind_problem(a.host, tls, behind)
    if problem and not a.insecure:
        sys.exit(f"{RED}{problem}{RESET}\n  그래도 열려면 --insecure (권장하지 않음)")
    if problem:
        print(f"{RED}{BOLD}경고: --insecure로 평문 HTTP를 {a.host}에 연다.{RESET} {problem}", file=sys.stderr)
    s = Settings()
    s.secure_cookie = s.secure_cookie or tls or behind
    app, box, token = build(s)
    scheme = "https" if tls else "http"
    print(f"{BOLD}agentbox 컨트롤 플레인{RESET}  {scheme}://{a.host}:{a.port}"
          + ("  (TLS 프록시 뒤)" if behind else ""))
    print(f"  격리 런타임: {box.sandboxes.runtime}   이미지: {s.image}")
    print(f"  감사 DB: {s.db_path}")
    print(f"  사람 토큰: {s.home / 'human_token'} (파일에 저장됨)")
    extra: dict[str, Any] = {}
    if tls:
        extra.update(ssl_certfile=a.tls_cert, ssl_keyfile=a.tls_key)
    if behind:
        # 프록시가 붙여 준 X-Forwarded-Proto로 https를 알아본다. 이 포트는 프록시에게만 열어 둘 것.
        extra.update(proxy_headers=True, forwarded_allow_ips=os.environ.get("AGENTBOX_TRUSTED_PROXIES", "*"))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning", **extra)


def cmd_create(a: argparse.Namespace) -> None:
    with _client() as c:
        src = os.path.abspath(a.source) if a.source else None
        sb = _check(c.post("/sandboxes", json={"source_dir": src, "template": a.template}))
    print(f"{GREEN}샌드박스 생성됨{RESET}: {BOLD}{sb['id']}{RESET}  "
          f"(템플릿 {sb['template']}, 런타임 {sb['runtime']}, 네트워크 차단)")
    if sb["runtime"] == "runc":
        print(f"  {YELLOW}! 격리 런타임이 runc다. 개발 전용 (호스트 커널을 그대로 공유).{RESET}")
    print(f"  원본(읽기 전용) /source ← {sb['source_dir']}")
    print("  작업 폴더 /workspace (원본의 복사본)")
    print(f"\n에이전트 토큰 (이 샌드박스 전용): {sb['agent_token']}\n")
    cfg = {
        "mcpServers": {
            "agentbox": {
                "command": sys.executable,
                "args": ["-m", "agentbox.mcp_server"],
                "env": {
                    "AGENTBOX_URL": _url(),
                    "AGENTBOX_SANDBOX_ID": sb["id"],
                    "AGENTBOX_AGENT_TOKEN": sb["agent_token"],
                },
            }
        }
    }
    print(f"{DIM}MCP 클라이언트 설정 예:{RESET}")
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
    if a.env_file:
        with open(a.env_file, "w") as f:
            f.write(f"AGENTBOX_SANDBOX_ID={sb['id']}\nAGENTBOX_AGENT_TOKEN={sb['agent_token']}\n")
        os.chmod(a.env_file, 0o600)
        print(f"\n{DIM}{a.env_file}에 저장함{RESET}")


def cmd_list(a: argparse.Namespace) -> None:
    with _client() as c:
        for s in _check(c.get("/sandboxes")):
            print(f"{s['id']}  {s['status']:8}  {s.get('template', 'cli'):7}  {s['runtime']:6}  {s['source_dir']}")


def cmd_ui(a: argparse.Namespace) -> None:
    with _client() as c:
        t = _check(c.post("/ui/ticket"))
    print(f"{(a.base_url or _url()).rstrip('/')}{t['path']}")
    print(f"{DIM}1회용 링크, {int(t['expires_in'])}초 안에 열 것.{RESET}", file=sys.stderr)


def cmd_desktop(a: argparse.Namespace) -> None:
    with _client() as c:
        t = _check(c.post(f"/sandboxes/{a.sandbox}/desktop/ticket"))
    base = (a.base_url or _url()).rstrip("/")
    print(f"{base}{t['path']}")
    print(f"{DIM}1회용 링크, {int(t['expires_in'])}초 안에 열 것. 열면 이 브라우저에 세션이 생긴다.{RESET}", file=sys.stderr)


def _show_approval(apr: dict[str, Any]) -> None:
    pv = apr.get("preview") or {}
    print()
    print(f"{YELLOW}{BOLD}━━ 승인 요청 {apr['id']} ━━{RESET}  샌드박스 {apr['sandbox_id']}  ({apr['created_at']})")
    print(f"{DIM}맞은 규칙:{RESET} {_safe(apr.get('rule_id'))} — {_safe(apr.get('rule_reason'))}")
    print(f"{DIM}작업 폴더:{RESET} {_safe(pv.get('cwd', '/workspace'))}")
    if apr["tool"] == "exec":
        # 줄마다 따로 찍고 줄 수를 보여, 빈 줄로 진짜 명령을 화면 밖으로 밀어내지 못하게 한다.
        lines = str(apr["args"].get("command")).split("\n")
        print(f"{BOLD}실제로 실행될 명령{f' ({len(lines)}줄)' if len(lines) > 1 else ''}:{RESET}")
        for line in lines:
            print(f"    {CYAN}{_safe(line)}{RESET}")
    else:
        shown = {k: v for k, v in apr["args"].items() if k != "content"}
        print(f"{BOLD}실제로 실행될 도구:{RESET}")
        print(f"    {CYAN}{_safe(apr['tool'])} {_safe(json.dumps(shown, ensure_ascii=False))}{RESET}")
    aff = pv.get("affected") or []
    print(f"{BOLD}시스템이 계산한 영향 ({len(aff)}건):{RESET}")
    for item in aff[:50]:
        color = RED if item["effect"] == "삭제" or "보낼" in item["effect"] else DIM
        print(f"    {color}{_safe(item['effect']):<12}{RESET} {_safe(item['path'])}")
    if len(aff) > 50:
        print(f"    {DIM}… 외 {len(aff) - 50}건{RESET}")
    for n in pv.get("notes") or []:
        print(f"  {YELLOW}! {_safe(n)}{RESET}")
    print(f"{DIM}(에이전트가 쓴 설명은 보여주지 않는다. 승인하면 실행 직전에 스냅샷을 만든다.){RESET}")


def cmd_approve(a: argparse.Namespace) -> None:
    seen: set[str] = set()
    print(f"{DIM}승인 요청을 기다리는 중… (Ctrl+C로 종료){RESET}")
    with _client() as c:
        while True:
            pending = _check(c.get("/approvals", params={"status": "pending"}))
            todo = [p for p in pending if p["id"] not in seen]
            if not todo:
                if a.once:
                    return
                time.sleep(1.0)
                continue
            for apr in todo:
                seen.add(apr["id"])
                _show_approval(apr)
                if a.auto:
                    ans = a.auto
                    print(f"승인할까요? [y/N] {ans} (자동)")
                else:
                    ans = input(f"{BOLD}승인할까요? [y/N] {RESET}").strip().lower()
                decision = "approve" if ans in ("y", "yes", "ㅛ") else "deny"
                r = c.post(f"/approvals/{apr['id']}", json={"decision": decision})
                if r.status_code == 409:
                    print(f"{DIM}이미 결정됐거나 기한이 지남{RESET}")
                    continue
                res = _check(r)
                if res["status"] == "executed":
                    out = res.get("result") or {}
                    print(f"{GREEN}승인 → 스냅샷 {res.get('snapshot_id')} 생성 후 실행함 (exit {out.get('exit_code')}){RESET}")
                    for line in (out.get("stderr") or "").splitlines()[:10]:
                        print(f"    {DIM}{_safe(line)}{RESET}")
                elif res["status"] == "denied":
                    print(f"{RED}거절 → 실행하지 않음{RESET}")
                elif res["status"] == "expired":
                    print(f"{RED}기한이 지나 이미 거부됨 → 실행하지 않음{RESET}")
                else:
                    print(f"{RED}{_safe(res['status'])}: {_safe(res.get('result'))}{RESET}")


def cmd_audit(a: argparse.Namespace) -> None:
    with _client() as c:
        params = {"sandbox_id": a.sandbox} if a.sandbox else {}
        rows = _check(c.get("/audit", params=params | {"limit": 5000}))
    icons = {"agent": "AI ", "human": "사람", "system": "SYS"}
    for e in rows:
        p = e["payload"]
        detail = ""
        if e["event"] == "tool_request":
            detail = json.dumps(p.get("args"), ensure_ascii=False)
        elif e["event"] == "policy_decision":
            detail = f"{p.get('action')} {('(' + p['rule_id'] + ')') if p.get('rule_id') else ''}"
        elif e["event"] == "approval_requested":
            detail = f"{p.get('approval_id')} 영향 {len((p.get('preview') or {}).get('affected') or [])}건"
        elif e["event"] == "approval_decision":
            detail = f"{p.get('approval_id')} → {p.get('decision')}"
        elif e["event"] in ("human_takeover", "human_handback", "desktop_connect", "desktop_disconnect",
                            "desktop_session_start"):
            detail = " ".join(f"{k}={v}" for k, v in p.items())
        elif e["event"] == "tool_blocked":
            detail = f"{p.get('reason')} {p.get('session', '')}"
        elif e["event"] in ("snapshot",):
            detail = p.get("snapshot_id", "")
        elif e["event"] == "gui_changes":
            n = p.get("counts") or {}
            detail = (f"{p.get('snapshot_id')}부터 +{n.get('added', 0)} ~{n.get('modified', 0)} "
                      f"-{n.get('deleted', 0)} " + " ".join(p.get("deleted") or [])[:80])
        elif e["event"] == "tool_result":
            if "exit_code" in p:
                detail = f"exit {p.get('exit_code')}" + (f"  {p.get('stderr_head', '').strip()[:80]}" if p.get("stderr_head") else "")
            else:
                detail = p.get("path") or ""
        else:
            detail = json.dumps(p, ensure_ascii=False)[:100]
        detail = _safe(" ".join(str(detail).split())[:140])
        ts = e["ts"][11:23]
        print(f"{DIM}{e['id']:>4} {ts}{RESET} {icons.get(e['actor'], e['actor']):<4} "
              f"{BOLD}{e['event']:<20}{RESET} {e['tool'] or '':<9} {detail}")


def cmd_verify(a: argparse.Namespace) -> None:
    with _client() as c:
        v = _check(c.get("/audit/verify"))
    if v["ok"]:
        print(f"{GREEN}해시 체인 온전함{RESET}: 항목 {v['checked']}개 모두 확인")
    else:
        print(f"{RED}해시 체인 깨짐{RESET}: 항목 #{v['broken_at']} — {v['reason']}")
        sys.exit(1)


def cmd_snapshots(a: argparse.Namespace) -> None:
    with _client() as c:
        for s in _check(c.get(f"/sandboxes/{a.sandbox}/snapshots")):
            print(f"{s['id']}  {s['created_at']}  {s['reason']}  {s['image']}")


def cmd_restore(a: argparse.Namespace) -> None:
    with _client() as c:
        _check(c.post(f"/sandboxes/{a.sandbox}/restore", json={"snapshot_id": a.snapshot}))
    print(f"{GREEN}{a.sandbox}를 {a.snapshot} 시점으로 되돌림{RESET}")


def cmd_delete(a: argparse.Namespace) -> None:
    with _client() as c:
        _check(c.delete(f"/sandboxes/{a.sandbox}"))
    print(f"삭제됨: {a.sandbox}")


def cmd_agent(a: argparse.Namespace) -> None:
    from . import agent as ag

    sid, token = a.sandbox, a.token
    if a.env_file:
        for line in open(a.env_file, encoding="utf-8"):
            k, _, v = line.strip().partition("=")
            if k == "AGENTBOX_SANDBOX_ID" and not sid:
                sid = v
            elif k == "AGENTBOX_AGENT_TOKEN" and not token:
                token = v
    if not (sid and token):
        sys.exit("샌드박스 id와 에이전트 토큰이 필요함 (--sandbox/--token 또는 --env-file)")
    if token.startswith("hum_"):
        sys.exit(f"{RED}사람 토큰을 에이전트에 주면 에이전트가 스스로 승인할 수 있다. 에이전트 토큰(agt_…)을 쓸 것.{RESET}")

    cfg = ag.LLMConfig.from_env()
    if a.provider:
        cfg.provider = a.provider
        if not os.environ.get("AGENTBOX_LLM_BASE_URL") and not a.base_url:
            cfg.base_url = "https://api.anthropic.com" if a.provider == "anthropic" else "https://api.openai.com/v1"
        if not os.environ.get("AGENTBOX_LLM_API_KEY"):
            cfg.api_key = os.environ.get("ANTHROPIC_API_KEY" if a.provider == "anthropic" else "OPENAI_API_KEY", "")
    if a.base_url:
        cfg.base_url = a.base_url
    if a.model:
        cfg.model = a.model

    def log(kind: str, msg: str) -> None:
        if kind == "say":
            print(f"{CYAN}[에이전트]{RESET} {msg}", flush=True)
        elif kind == "call":
            print(f"{DIM}  → {msg}{RESET}", flush=True)
        elif kind == "result":
            lines = msg.splitlines()
            head = "\n".join(lines[:6]) + (f"\n… ({len(lines) - 6}줄 더)" if len(lines) > 6 else "")
            print(f"{DIM}{head}{RESET}", flush=True)

    tools = ag.ToolClient(_url(), sid, token,
                          on_pending=lambda aid: print(f"{YELLOW}  … 승인 대기 {aid} ('agentbox approve'에서 결정){RESET}",
                                                       flush=True))
    try:
        chat = ag.make_chat(cfg)
    except ValueError as e:
        sys.exit(f"{RED}{e}{RESET}")
    print(f"{DIM}LLM: {cfg.provider} {cfg.model} @ {cfg.base_url}   샌드박스: {sid}{RESET}")
    print(f"{CYAN}[사용자]{RESET} {a.task}")
    res = ag.run(a.task, chat, tools, max_steps=a.max_steps, log=log)
    if res.stopped == "max_steps":
        print(f"{YELLOW}최대 {a.max_steps}단계에 도달해 멈춤{RESET}")
    print(f"{DIM}도구 호출 {len(res.tool_calls)}회, LLM 호출 {res.steps}회{RESET}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="agentbox", description="망 안의 에이전트 컴퓨터 — 최소 증명 데모")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="컨트롤 플레인 실행")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--tls-cert", help="TLS 인증서 (PEM). --tls-key와 함께")
    s.add_argument("--tls-key", help="TLS 개인 키 (PEM)")
    s.add_argument("--behind-tls-proxy", action="store_true",
                   help="TLS는 앞단 프록시(Caddy 등)가 맡는다. 쿠키에 Secure를 붙인다")
    s.add_argument("--insecure", action="store_true",
                   help="TLS 없이 127.0.0.1 밖에 연다 (경고만 하고 허용, 권장하지 않음)")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("create", help="샌드박스 생성")
    s.add_argument("source", nargs="?", help="원본 폴더 (비우면 빈 폴더, 파일은 웹 UI로 넣는다)")
    s.add_argument("--template", default="cli", help="cli (기본) 또는 desktop (화면·GUI 도구)")
    s.add_argument("--env-file", help="샌드박스 id와 에이전트 토큰을 저장할 파일")
    s.set_defaults(fn=cmd_create)

    sub.add_parser("list", help="샌드박스 목록").set_defaults(fn=cmd_list)

    s = sub.add_parser("ui", help="웹 UI 로그인 링크 (1회용)")
    s.add_argument("--base-url", help="브라우저에서 보이는 컨트롤 플레인 주소 (기본 AGENTBOX_URL)")
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("desktop", help="브라우저 화면 링크 (1회용)")
    s.add_argument("sandbox")
    s.add_argument("--base-url", help="브라우저에서 보이는 컨트롤 플레인 주소 (기본 AGENTBOX_URL)")
    s.set_defaults(fn=cmd_desktop)

    s = sub.add_parser("approve", help="터미널 승인")
    s.add_argument("--once", action="store_true", help="대기 중인 요청만 처리하고 종료")
    s.add_argument("--auto", choices=["y", "n"], help="녹화·테스트용 자동 응답")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("audit", help="감사 로그 타임라인")
    s.add_argument("--sandbox")
    s.set_defaults(fn=cmd_audit)

    sub.add_parser("verify", help="해시 체인 검증").set_defaults(fn=cmd_verify)

    s = sub.add_parser("snapshots")
    s.add_argument("sandbox")
    s.set_defaults(fn=cmd_snapshots)

    s = sub.add_parser("restore")
    s.add_argument("sandbox")
    s.add_argument("snapshot")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("delete")
    s.add_argument("sandbox")
    s.set_defaults(fn=cmd_delete)

    s = sub.add_parser("agent", help="LLM API로 에이전트 실행")
    s.add_argument("task", help="에이전트에게 줄 지시")
    s.add_argument("--sandbox", default=os.environ.get("AGENTBOX_SANDBOX_ID", ""))
    s.add_argument("--token", default=os.environ.get("AGENTBOX_AGENT_TOKEN", ""),
                   help="에이전트 토큰 (사람 토큰 아님)")
    s.add_argument("--env-file", help="'agentbox create --env-file'로 저장한 파일")
    s.add_argument("--provider", choices=["openai", "anthropic"])
    s.add_argument("--base-url")
    s.add_argument("--model")
    s.add_argument("--max-steps", type=int, default=30)
    s.set_defaults(fn=cmd_agent)

    a = p.parse_args(argv)
    try:
        a.fn(a)
    except KeyboardInterrupt:
        print()
    except httpx.ConnectError:
        sys.exit(f"{RED}컨트롤 플레인({_url()})에 연결할 수 없음. 먼저 'agentbox serve'를 실행할 것.{RESET}")


if __name__ == "__main__":
    main()
