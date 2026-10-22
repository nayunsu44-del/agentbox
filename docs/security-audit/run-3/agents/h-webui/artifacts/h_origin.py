# Bounded harness: extract api.build's nested same_origin() verbatim via ast and evaluate request header shapes.
import ast, sys
from urllib.parse import urlsplit
src = open("/target/agentbox/api.py").read()
tree = ast.parse(src)
fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "same_origin")
print("same_origin source (api.py line %d):" % fn.lineno)
print(ast.get_source_segment(src, fn))
ns = {"urlsplit": urlsplit}
exec(compile(ast.Module([fn], []), "api.py", "exec"), ns)
same_origin = ns["same_origin"]
cases = [
    ("same origin https", {"origin": "https://agentbox.example.com", "host": "agentbox.example.com"}),
    ("cross-scheme http page -> https server (different origin)", {"origin": "http://agentbox.example.com", "host": "agentbox.example.com"}),
    ("cross-scheme on explicit port (direct TLS :8765)", {"origin": "http://agentbox.example.com:8765", "host": "agentbox.example.com:8765"}),
    ("sibling same-site origin", {"origin": "https://other.example.com", "host": "agentbox.example.com"}),
    ("other localhost port", {"origin": "http://127.0.0.1:3000", "host": "127.0.0.1:8765"}),
    ("opaque null origin", {"origin": "null", "host": "127.0.0.1:8765"}),
    ("no Origin (no-cors GET subresource)", {"host": "127.0.0.1:8765"}),
]
for name, h in cases:
    print(f"{name:60s} -> accepted={same_origin(h)}")
