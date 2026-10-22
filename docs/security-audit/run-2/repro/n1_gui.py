"""N-1: GUI 도구만으로 터미널을 열어 /workspace 파일을 승인·스냅샷 없이 지울 수 있는지."""
import base64, os, sys, tempfile, time
from pathlib import Path
from fastapi.testclient import TestClient

tmp = Path(tempfile.mkdtemp(prefix="n1-"))
os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; src.mkdir(); (src / "victim.txt").write_text("important\n")
from agentbox.api import build
app, box, human = build(); c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src), "template": "desktop"}, headers=H).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
out = Path(sys.argv[1]) if len(sys.argv) > 1 else tmp
def tool(name, **a):
    r = c.post(f"/sandboxes/{sid}/tools/{name}", json={"args": a}, headers=A)
    return r.status_code, r.json()
def shot(name):
    st, j = tool("screenshot")
    (out / name).write_bytes(base64.b64decode(j["result"]["png_base64"]))
time.sleep(8)                         # Xfce 세션이 뜰 때까지
shot("n1-0-desktop.png")
print("key ctrl+alt+t:", tool("key", keys="ctrl+alt+t")[0])
time.sleep(4)
shot("n1-1-after-shortcut.png")
print("type:", tool("type", text="id > /workspace/outbox/gui-id.txt; rm -f /workspace/victim.txt")[0])
print("key Return:", tool("key", keys="Return")[0])
time.sleep(2)
shot("n1-2-after-command.png")
st, j = tool("list_dir", path="/workspace")
print("workspace now:\n" + j["result"]["listing"])
st, j = tool("read_file", path="/workspace/outbox/gui-id.txt")
print("gui-id.txt:", j.get("result", {}).get("content", j))
print("approvals:", len(c.get("/approvals", headers=H).json()), " snapshots:", len(box.sandboxes.list_snapshots(sid)))
ev = [e["event"] + ("/" + e["tool"] if e["tool"] else "") for e in c.get("/audit", headers=H).json() if e["sandbox_id"] == sid]
print("audit trail tools:", sorted(set(ev)))
snaps = box.sandboxes.list_snapshots(sid)
if snaps:  # GUI 구간 스냅샷(수정 후)으로 되돌리면 지운 파일이 돌아오는지
    c.post(f"/sandboxes/{sid}/restore", json={"snapshot_id": snaps[0]["id"]}, headers=H)
    st, j = tool("list_dir", path="/workspace")
    print(f"after restore to {snaps[0]['id']} ({snaps[0]['reason']}):\n" + j["result"]["listing"])
c.delete(f"/sandboxes/{sid}", headers=H)
