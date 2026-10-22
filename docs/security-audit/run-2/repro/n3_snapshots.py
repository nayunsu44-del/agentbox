"""N-3: 에이전트 토큰만으로 같은 파일을 N번 덮어쓸 때 스냅샷 이미지가 쌓이는지 본다."""
import os
import sys
import tempfile
import time
from pathlib import Path

import docker
from fastapi.testclient import TestClient

N = int(sys.argv[1]) if len(sys.argv) > 1 else 200

tmp = Path(tempfile.mkdtemp(prefix="n3-"))
os.environ["AGENTBOX_HOME"] = str(tmp / "data")
os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"
src.mkdir()
(src / "f.txt").write_text("seed\n")

from agentbox.api import build  # noqa: E402

app, box, human = build()
c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
d = docker.from_env()


def snaps():
    return [i for i in d.images.list(name="agentbox-snap") if any(sid in t for t in i.tags)]


statuses = {}
t0 = time.time()
for i in range(N):
    r = c.post(f"/sandboxes/{sid}/tools/write_file",
               json={"args": {"path": "/workspace/f.txt", "content": f"v{i}\n" * 1000}}, headers=A)
    statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
el = time.time() - t0
imgs = snaps()
print(f"write_file x{N}: status={statuses} elapsed={el:.1f}s ({el / N * 1000:.0f} ms/call)")
print(f"snapshot images for {sid}: {len(imgs)}")
du = d.df()
snap_bytes = sum(x.get("Size", 0) for x in du["Images"] if any("agentbox-snap" in t for t in (x.get("RepoTags") or [])))
print(f"docker df agentbox-snap total Size: {snap_bytes / 1e6:.1f} MB")
approvals = c.get("/approvals", headers=H).json()
print(f"approvals created: {len(approvals) if isinstance(approvals, list) else approvals}")

c.delete(f"/sandboxes/{sid}", headers=H)
print(f"after DELETE /sandboxes/{sid}: snapshot images left = {len(snaps())}")
