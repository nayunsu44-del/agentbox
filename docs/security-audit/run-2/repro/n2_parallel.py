"""N-2: 같은 에이전트 토큰으로 exec를 동시에 N개 보내 컨트롤 플레인 RSS를 본다 (실제 uvicorn 서버)."""
import os, subprocess, sys, tempfile, threading, time
from pathlib import Path
import httpx

N, T = int(sys.argv[1]), sys.argv[2]
CMD = sys.argv[3] if len(sys.argv) > 3 else "cat /dev/zero"
tmp = Path(tempfile.mkdtemp(prefix="n2p-"))
env = {**os.environ, "AGENTBOX_HOME": str(tmp / "data"), "AGENTBOX_EXEC_TIMEOUT": T,
       "AGENTBOX_HUMAN_TOKEN": "hum_test_n2"}
srv = subprocess.Popen(["prlimit", "--as=12000000000", sys.executable, "-m", "agentbox", "serve", "--port", "8799"],
                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, cwd=os.getcwd())
B = "http://127.0.0.1:8799"
for _ in range(100):
    try:
        httpx.get(B + "/sandboxes", timeout=1); break
    except Exception:
        time.sleep(0.2)
H = {"Authorization": "Bearer hum_test_n2"}
sb = httpx.post(B + "/sandboxes", json={"source_dir": None}, headers=H, timeout=60).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
pid = int(subprocess.check_output(["pgrep", "-f", "agentbox serve --port 8799"]).split()[-1])
def rss():
    try:
        return int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]) * 1024
    except Exception:
        return 0
base, peak, out = rss(), [0], []
def one():
    try:
        r = httpx.post(f"{B}/sandboxes/{sid}/tools/exec", json={"args": {"command": CMD}}, headers=A, timeout=600)
        out.append(r.status_code)
    except Exception as e:
        out.append(type(e).__name__)
ths = [threading.Thread(target=one) for _ in range(N)]
t0 = time.time()
[t.start() for t in ths]
while any(t.is_alive() for t in ths):
    peak.append(rss()); time.sleep(0.1)
print(f"N={N} cmd={CMD!r} timeout={T}s elapsed={time.time() - t0:.0f}s results={out} server_alive={srv.poll() is None}")
print(f"server RSS: base {base / 1e6:.0f} MB, peak {max(peak) / 1e6:.0f} MB (+{(max(peak) - base) / 1e6:.0f} MB)")
try:
    httpx.delete(f"{B}/sandboxes/{sid}", headers=H, timeout=60)
finally:
    srv.terminate(); srv.wait()
