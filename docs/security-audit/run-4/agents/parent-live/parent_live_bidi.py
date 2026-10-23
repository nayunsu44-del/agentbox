"""parent-live N5: does a residual Bidi_Control code point (U+061C ALM) make the approval card read as a different command?

Real control plane from the audited tree (in-process, real Docker CLI sandbox, loopback uvicorn), a dummy
human token, and Playwright Chromium (the only engine installed here). Each payload is sent as an agent
exec, lands as a pending approval, and the /ui/approvals card is rendered and screenshotted. Every
approval is denied afterwards and the sandbox is deleted.

usage: python3 parent_live_bidi.py <src-audited> <home> <outdir>
"""
import json, os, sys, threading, time
SRC, HOME, OUTDIR = sys.argv[1:4]
sys.path.insert(0, SRC)
TOKEN = "hum_" + "p" * 40
os.environ.update(AGENTBOX_HOME=HOME, AGENTBOX_HUMAN_TOKEN=TOKEN, AGENTBOX_IMAGE="buildpack-deps:noble-curl")
import uvicorn
from playwright.sync_api import sync_playwright
from agentbox.api import build
from agentbox.config import Settings

ALM, LS, ZWSP = "؜", " ", "​"
PAYLOADS = {
    "alm_redirect": f"cat /workspace/notes.txt {ALM}>{ALM} /workspace/outbox/copy.txt",
    "alm_redirect_spaces": f"cat /workspace/notes.txt {ALM} > {ALM} /workspace/outbox/copy.txt",
    "alm_pipe_args": f"sort /workspace/a.txt {ALM}-o{ALM} /workspace/b.txt",
    "line_separator": f"echo ok{LS}; rm -rf /workspace/data",
    "zwsp_in_flag": f"rm -r{ZWSP}f /workspace/tmp",
}
app, box, human = build(Settings())
rec, agent_tok = box.create_sandbox(None, "cli")
sid = rec["id"]
results = {}
cfg = uvicorn.Config(app, host="127.0.0.1", port=8765, log_level="warning")
srv = uvicorn.Server(cfg)
th = threading.Thread(target=srv.run, daemon=True)
th.start()
while not srv.started:
    time.sleep(0.1)
try:
    ids = {}
    for name, cmd in PAYLOADS.items():
        o = box.call_tool(sid, "exec", {"command": cmd})
        ids[name] = o.body.get("approval_id")
        results[name] = {"command_repr": repr(cmd), "status": o.status, "approval_id": ids[name]}
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
        pg = b.new_page(viewport={"width": 1100, "height": 1400})
        pg.goto("http://127.0.0.1:8765/login")
        pg.fill("input[name=token]", TOKEN)
        pg.press("input[name=token]", "Enter")
        pg.wait_for_load_state("networkidle")
        pg.goto("http://127.0.0.1:8765/ui/approvals")
        pg.wait_for_load_state("networkidle")
        for name, aid in ids.items():
            card = pg.locator(f".card:has-text('{aid}')").first
            pre = card.locator("pre").first
            results[name]["pre_innerText_repr"] = repr(pre.inner_text())
            pre.screenshot(path=f"{OUTDIR}/bidi-{name}.png")
        pg.screenshot(path=f"{OUTDIR}/bidi-page.png", full_page=True)
        b.close()
finally:
    for aid in ids.values():
        if aid:
            try:
                box.decide(aid, False, "human", "*")
            except Exception:
                pass
    box.delete_sandbox(sid)
    srv.should_exit = True
    open(f"{OUTDIR}/bidi-render.json", "w").write(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
