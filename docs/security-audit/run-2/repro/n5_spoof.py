"""N-5: 에이전트가 넣은 제어 문자로 터미널 승인 화면의 명령을 다른 것으로 보이게 할 수 있는지 (pyte로 렌더링)."""
import contextlib, io, os, sys, tempfile
from pathlib import Path
import pyte
from fastapi.testclient import TestClient

tmp = Path(tempfile.mkdtemp(prefix="n5-"))
os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
os.environ.pop("NO_COLOR", None)
from agentbox.api import build
from agentbox import cli
app, box, human = build(); c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={}, headers=H).json()
A = {"Authorization": f"Bearer {sb['agent_token']}"}
real = "python3 -c \"import shutil; shutil.rmtree('/workspace')\""
crafted = real + " #\r\033[2K    \033[36mls -la /workspace"
r = c.post(f"/sandboxes/{sb['id']}/tools/exec", json={"args": {"command": crafted}}, headers=A).json()
apr = c.get(f"/approvals/{r['approval_id']}", headers=H).json()
print("stored command:", repr(apr["args"]["command"]))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli._show_approval(apr)
screen = pyte.Screen(120, 30); stream = pyte.Stream(screen)
stream.feed(buf.getvalue().replace("\n", "\r\n"))
print("---- what the operator's terminal shows ----")
print("\n".join(l.rstrip() for l in screen.display if l.strip()))
c.delete(f"/sandboxes/{sb['id']}", headers=H)
