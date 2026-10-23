"""Render `agentbox agent` stdout (real cli.main with fake LLM/tools, from h-wild's harness) in the pyte VT emulator."""
import contextlib, io, runpy, sys
import pyte
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    runpy.run_path("/scratch/l6_base.py")
import json
out = json.loads(buf.getvalue().strip().splitlines()[-1] if buf.getvalue().strip().startswith("{") is False else buf.getvalue())["stdout_repr"]
scr = pyte.Screen(100, 20); st = pyte.Stream(scr); st.feed(out.replace("\n", "\r\n"))
print("raw stdout lines:"); [print("  ", repr(l)) for l in out.splitlines()]
print("rendered terminal screen:"); [print("  |" + l.rstrip()) for l in scr.display if l.strip()]
print("window title set by output:", repr(scr.title))
