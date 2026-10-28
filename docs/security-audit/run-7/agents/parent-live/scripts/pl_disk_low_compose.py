"""parent-live: control plane in a container with only docker.sock + AGENTBOX_HOME mounted (compose topology)."""
import os, shutil
from pathlib import Path
os.environ["AGENTBOX_HOME"] = "/var/lib/agentbox"
from agentbox.config import Settings
from agentbox.sandbox import SandboxManager
from agentbox.service import AgentBox
s = Settings()
sm = SandboxManager(s, s.db_path)
print("DockerRootDir (daemon) =", sm.docker_root, "exists in control-plane container:", Path(str(sm.docker_root)).exists())
try: print("disk_usage(docker_root) =", shutil.disk_usage(sm.docker_root))
except OSError as e: print("disk_usage(docker_root) raised", type(e).__name__, e)
home_free = shutil.disk_usage(s.db_path.parent).free
s.min_free_bytes = home_free - 1   # db partition has enough space; only a Docker-root term could flip disk_low
box = AgentBox(sm, s) if False else None
from agentbox import service as S
class Fake: pass
f = Fake(); f.sandboxes = sm; f._busy_lock = __import__("threading").Lock(); f._low_disk = False; f.log_best_effort = lambda *a, **k: None
sm.docker_root = Path("/var/lib/docker")
print("disk_low with min_free = home_free-1 :", S.AgentBox.disk_low(f))
s.min_free_bytes = home_free + 1
print("disk_low with min_free = home_free+1 :", S.AgentBox.disk_low(f))
