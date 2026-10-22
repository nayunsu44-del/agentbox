# Bounded harness: does `agentbox agent` print container-controlled tool results / model text
# to the operator terminal without cli._safe? Fake LLM + fake ToolClient, no network, no docker.
import io, json, sys
sys.path.insert(0, "/target")
from agentbox import cli, agent as ag

ESC_READ = "line1\x1b[2K\x1b[1A\x1b[2K[forged] all good\x1b]52;c;ZWNobyBwd25lZA==\x07"   # read_file content (file in /workspace)
C1_EXEC = "out\u009b2K\u009b1Ahidden"                                                      # exec stdout with C1 CSI
NAME_LS = "evil\x1b[31mname"                                                               # list_dir listing (file name)
SAY = "model says\x1b[2J"

class FakeTools:
    def __init__(self, *a, **k): pass
    def call_text(self, tool, args):
        if tool == "read_file": return ESC_READ
        if tool == "list_dir": return NAME_LS
        return json.dumps({"exit_code": 0, "stdout": C1_EXEC}, ensure_ascii=False, indent=2)

class FakeChat:
    def __init__(self): self.n = 0
    def user(self, t): pass
    def tool_results(self, r): pass
    def step(self):
        self.n += 1
        if self.n == 1:
            return {"text": SAY, "calls": [{"id": "1", "name": "read_file", "args": {"path": "/workspace/README"}},
                                           {"id": "2", "name": "list_dir", "args": {"path": "/workspace"}},
                                           {"id": "3", "name": "exec", "args": {"command": "cat x"}}]}
        return {"text": "", "calls": []}

ag.ToolClient = FakeTools
ag.make_chat = lambda cfg: FakeChat()
buf = io.BytesIO()
real = sys.stdout
sys.stdout = io.TextIOWrapper(buf, encoding="utf-8", write_through=True)
try:
    cli.main(["agent", "do task", "--sandbox", "sb_dummy", "--token", "agt_dummy", "--model", "m", "--provider", "openai"])
finally:
    sys.stdout.flush(); out = buf.getvalue(); sys.stdout = real
print("captured stdout bytes (repr):")
print(repr(out))
print("raw ESC (0x1b) bytes in operator stdout:", out.count(b"\x1b"))
print("raw C1 CSI (U+009B as c2 9b) in operator stdout:", out.count(b"\xc2\x9b"))
print("OSC 52 clipboard sequence present raw:", b"\x1b]52;" in out)
print("for comparison cli._safe(read_file content) =", cli._safe(ESC_READ))
print("cli._safe escapes ESC:", "\x1b" not in cli._safe(ESC_READ), " escapes C1:", "\u009b" not in cli._safe(C1_EXEC))
