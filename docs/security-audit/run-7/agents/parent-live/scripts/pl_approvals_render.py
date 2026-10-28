"""parent-live: 20 pending CLAUDE.md-family write approvals x 1 MiB through the real API and real sandbox, then time GET /ui/approvals."""
import os, tempfile, pathlib, time
from fastapi.testclient import TestClient
tmp = pathlib.Path(tempfile.mkdtemp()); os.environ["AGENTBOX_HOME"] = str(tmp / "data"); os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; src.mkdir(); (src / "a.txt").write_text("x")
from agentbox.api import build
app, box, human = build(); c = TestClient(app); H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json(); sid = sb["id"]; A = {"Authorization": f"Bearer {sb['agent_token']}"}
content = "\x01" * (1024 * 1024)
codes = []
for i in range(21):
    r = c.post(f"/sandboxes/{sid}/tools/write_file", json={"args": {"path": f"/workspace/d{i}/CLAUDE.md", "content": content}}, headers=A)
    codes.append(r.status_code)
print("write_file statuses:", codes)
for path in ("/ui/approvals", f"/ui/approvals?sandbox_id={sid}"):
    for n in range(2):
        t = time.monotonic(); r = c.get(path, headers=H); dt = time.monotonic() - t
        print(f"GET {path} try{n}: status={r.status_code} bytes={len(r.content)} seconds={dt:.2f}")
c.delete(f"/sandboxes/{sid}", headers=H)
