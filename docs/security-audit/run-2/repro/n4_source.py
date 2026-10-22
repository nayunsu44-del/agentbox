"""N-4: 사람이 데이터 폴더를 포함하는 폴더를 원본으로 주면, 에이전트가 사람 토큰을 읽어 자기 승인을 할 수 있는지."""
import os, tempfile
from pathlib import Path
from fastapi.testclient import TestClient

proj = Path(tempfile.mkdtemp(prefix="n4-proj-"))
os.chdir(proj)                                   # 운영자가 프로젝트 폴더에서 serve (AGENTBOX_HOME 기본값 ./data)
os.environ.pop("AGENTBOX_HOME", None); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
(proj / "report.md").write_text("# 보고서\n")
from agentbox.api import build
app, box, human = build(); c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
tok = proj / "data" / "human_token"
print(f"data dir: {box.sandboxes.settings.home}, human_token mode {oct(tok.stat().st_mode & 0o777)} uid {tok.stat().st_uid}")
other = c.post("/sandboxes", json={}, headers=H).json()      # 다른 샌드박스 (빈 원본 → data/sources/<sid>)
c.post(f"/sandboxes/{other['id']}/files", files={"file": ("secret-of-other.txt", b"other sandbox data")}, headers=H)
sb = c.post("/sandboxes", json={"source_dir": "."}, headers=H)   # 원본 = 프로젝트 폴더 (data 포함)
print("create with source_dir='.':", sb.status_code, sb.json().get("detail", ""))
if sb.status_code == 201:
    sb = sb.json(); sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
    def tool(name, **a):
        return c.post(f"/sandboxes/{sid}/tools/{name}", json={"args": a}, headers=A).json()
    r = tool("read_file", path="/workspace/data/human_token")
    leaked = r.get("result", {}).get("content", "").strip()
    print("agent read_file data/human_token ->", "LEAKED" if leaked == human else r)
    print("agent sees other sandbox sources:", tool("exec", command="ls -R /workspace/data/sources")["result"]["stdout"][:300])
    pend = tool("exec", command="rm -f /workspace/report.md")
    print("agent rm -> pending approval", pend.get("approval_id"))
    if leaked == human:
        r = c.post(f"/approvals/{pend['approval_id']}", json={"decision": "approve"},
                   headers={"Authorization": f"Bearer {leaked}"})
        print("agent approves its own request with leaked token ->", r.status_code, r.json().get("status"))
    c.delete(f"/sandboxes/{sid}", headers=H)
c.delete(f"/sandboxes/{other['id']}", headers=H)
