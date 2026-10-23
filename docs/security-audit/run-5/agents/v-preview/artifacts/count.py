import sys, time
sys.path.insert(0, "/target")
from agentbox.preview import preview_command
for n in (200, 4000):
    c = {"e": 0, "w": 0}
    def ex(p): c["e"] += 1; return [p]
    def wk(p, l): c["w"] += 1; return [p]
    t = time.time()
    r = preview_command("rm -r " + " ".join(["d"] * n), 200, ex, wk)
    print(n, c, len(r["affected"]), round(time.time() - t, 3))
