"""parent-live: compose-style control plane with the daemon data root bind-mounted read-only at /host-docker-root."""
import os, shutil
os.environ["AGENTBOX_HOME"] = "/var/lib/agentbox"
from agentbox.api import build
app, box, human = build()
print("docker_root:", box.sandboxes.docker_root, "| problem:", box.docker_root_problem)
print("free(docker_root) GiB:", round(shutil.disk_usage(box.sandboxes.docker_root).free / 2**30, 1),
      "| free(home) GiB:", round(shutil.disk_usage("/var/lib/agentbox").free / 2**30, 1))
