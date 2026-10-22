"""N-3 증폭: 에이전트가 새 파일로 /workspace를 키운 뒤 작은 파일을 덮어쓰면 스냅샷마다 전체가 복사되는지."""
import os, secrets, shutil, subprocess, sys, tempfile
from pathlib import Path
from fastapi.testclient import TestClient

BIG, OVR = int(sys.argv[1]), int(sys.argv[2])   # 새 1MB 파일 수, 덮어쓰기 횟수
tmp = Path(tempfile.mkdtemp(prefix="n3a-"))
os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; src.mkdir(); (src / "small.txt").write_text("x\n")
from agentbox.api import build
app, box, human = build(); c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
def tool(name, **args):
    return c.post(f"/sandboxes/{sid}/tools/{name}", json={"args": args}, headers=A)
def disk():
    return int(subprocess.check_output(["du", "-sb", "/var/lib/docker"]).split()[0])
st = {}
for i in range(BIG):   # 새 파일: 승인·스냅샷 없음
    r = tool("write_file", path=f"/workspace/blob{i}", content=secrets.token_hex(512 * 1024 - 1))
    st[r.status_code] = st.get(r.status_code, 0) + 1
print(f"new 1MB files x{BIG}: {st}")
d0 = disk()
st = {}
for i in range(OVR):   # 작은 파일 덮어쓰기: 매번 docker commit
    r = tool("write_file", path="/workspace/small.txt", content=f"{i}\n")
    st[r.status_code] = st.get(r.status_code, 0) + 1
d1 = disk()
print(f"overwrite small.txt x{OVR}: {st}; /var/lib/docker grew {(d1 - d0) / 1e6:.0f} MB "
      f"(~{(d1 - d0) / OVR / 1e6:.1f} MB per snapshot for a 2-byte change)")
c.delete(f"/sandboxes/{sid}", headers=H)
print(f"after sandbox delete: /var/lib/docker still +{(disk() - d0) / 1e6:.0f} MB")
