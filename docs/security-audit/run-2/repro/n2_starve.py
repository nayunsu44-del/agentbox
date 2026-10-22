"""N-2 파생: 출력 없는 허용 명령(tail -f /dev/null) N개로 스레드 풀을 묶으면 사람 API가 멈추는지."""
import os, subprocess, sys, tempfile, threading, time
from pathlib import Path
import httpx

N, T = int(sys.argv[1]), sys.argv[2]
tmp = Path(tempfile.mkdtemp(prefix="n2s-"))
env = {**os.environ, "AGENTBOX_HOME": str(tmp / "data"), "AGENTBOX_EXEC_TIMEOUT": T, "AGENTBOX_HUMAN_TOKEN": "hum_t"}
srv = subprocess.Popen([sys.executable, "-m", "agentbox", "serve", "--port", "8798"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
B, H = "http://127.0.0.1:8798", {"Authorization": "Bearer hum_t"}
for _ in range(100):
    try:
        httpx.get(B + "/sandboxes", timeout=1); break
    except Exception:
        time.sleep(0.2)
sb = httpx.post(B + "/sandboxes", json={"source_dir": None}, headers=H, timeout=60).json()
sid, A = sb["id"], {"Authorization": f"Bearer {sb['agent_token']}"}
def hold():
    httpx.post(f"{B}/sandboxes/{sid}/tools/exec", json={"args": {"command": "tail -f /dev/null"}},
               headers=A, timeout=600)
ths = [threading.Thread(target=hold) for _ in range(N)]
[t.start() for t in ths]
time.sleep(3)
t0 = time.time()
r = httpx.get(B + "/approvals", headers=H, timeout=600)
print(f"N={N} holders, timeout={T}s: human GET /approvals -> {r.status_code} after {time.time() - t0:.1f}s")
[t.join() for t in ths]
httpx.delete(f"{B}/sandboxes/{sid}", headers=H, timeout=60); srv.terminate(); srv.wait()
