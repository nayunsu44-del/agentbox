"""N-2: 허용 목록 명령 하나로 컨트롤 플레인 메모리(RSS)가 얼마나 오르는지 본다."""
import os, sys, tempfile, threading, time
from pathlib import Path
from fastapi.testclient import TestClient

T = sys.argv[1]
CMD = sys.argv[2] if len(sys.argv) > 2 else "cat /dev/zero"
tmp = Path(tempfile.mkdtemp(prefix="n2-"))
os.environ.update(AGENTBOX_HOME=str(tmp / "data"), AGENTBOX_EXEC_TIMEOUT=T)
os.environ.pop("AGENTBOX_HUMAN_TOKEN", None)
src = tmp / "src"; src.mkdir()
from agentbox.api import build
app, box, human = build(); c = TestClient(app)
H = {"Authorization": f"Bearer {human}"}
sb = c.post("/sandboxes", json={"source_dir": str(src)}, headers=H).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}

def rss():
    for line in open("/proc/self/status"):
        if line.startswith("VmRSS"):
            return int(line.split()[1]) * 1024
peak, stop = [rss()], False
def sample():
    while not stop:
        peak.append(rss()); time.sleep(0.05)
base = rss()
th = threading.Thread(target=sample, daemon=True); th.start()
t0 = time.time()
try:
    r = c.post(f"/sandboxes/{sid}/tools/exec", json={"args": {"command": CMD}}, headers=A)
    tail = r.json().get("result", {}).get("stdout", "")[-40:]
    res = f"HTTP {r.status_code} status={r.json().get('status')} stdout_tail={tail!r}"
except MemoryError:
    res = "MemoryError in control plane"
stop = True; th.join()
print(f"cmd={CMD!r} timeout={T}s elapsed={time.time() - t0:.1f}s -> {res}")
print(f"control-plane RSS: base {base / 1e6:.0f} MB, peak {max(peak) / 1e6:.0f} MB (+{(max(peak) - base) / 1e6:.0f} MB)")
c.delete(f"/sandboxes/{sid}", headers=H)
