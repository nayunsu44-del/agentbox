"""v09: does the default policy allow an approval-free exec that holds many pids for exec_timeout?"""
import sys, subprocess, time
sys.path.insert(0, "/target")
from agentbox.policy import Policy, simple_programs
import agentbox, pathlib
pol = Policy.load(pathlib.Path(agentbox.__file__).parent / "default_policy.yaml") if hasattr(Policy, "load") else None
n = 1000
cmd = "tail -f /dev/null & " * n + "tail -f /dev/null"
print("command length:", len(cmd), "| simple_programs:", simple_programs(cmd))
if pol is not None:
    d = pol.decide("exec", {"command": cmd})
    print("default policy decision:", d.action, d.rule_id)
# bounded local check of the process-lifetime assumption (same wrapper shape as SandboxManager.exec, small N, 3 s)
small = "tail -f /dev/null & " * 5 + "tail -f /dev/null"
t0 = time.monotonic()
p = subprocess.Popen(["timeout", "-k", "1", "3", "bash", "-c", "umask 002\n" + small])
time.sleep(1.0)
during = subprocess.run(["sh", "-c", "ps -eo pid=,comm= | grep -c ' tail$'"], capture_output=True, text=True).stdout.strip()
p.wait()
time.sleep(0.5)
after = subprocess.run(["sh", "-c", "ps -eo pid=,comm= | grep -c ' tail$'"], capture_output=True, text=True).stdout.strip()
states = subprocess.run(["sh", "-c", "ps -eo stat=,comm= | grep ' tail$' | cut -c1 | sort | uniq -c | tr -s ' ' | tr '\\n' ';'"], capture_output=True, text=True).stdout.strip()
print("tail process states after timeout (Z = zombie, i.e. killed but not yet reaped by this harness's PID 1):", states)
print(f"tail processes during exec: {during} | exit code {p.returncode} after {time.monotonic()-t0:.1f}s | tail processes after timeout: {after}")
