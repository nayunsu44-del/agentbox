import time, hashlib, shutil, os, sys
sys.path.insert(0, "/target")
from jinja2 import Environment, FileSystemLoader, select_autoescape
from agentbox.web import _shown, _short, _oneline

src = "/target/agentbox/templates/_approvals.html"
dst_dir = "/scratch/tpl"
os.makedirs(dst_dir, exist_ok=True)
t = open(src, encoding="utf-8").read()
old = '<pre class="instruction-content" style="max-height:480px">{{ a.args.content }}</pre>'
assert old in t
new = ('<pre class="instruction-content" style="max-height:480px">{{ a.args.content[:4096] }}{% if a.args.content | length > 4096 %}\n'
       '…({{ a.args.content | length - 4096 }}자 더)\n{% endif %}</pre><a href="/ui/approvals/{{ a.id }}/content">전체 내용 보기</a>')
open(f"{dst_dir}/_approvals.html", "w", encoding="utf-8").write(t.replace(old, new))

for label, d in (("original", "/target/agentbox/templates"), ("fixed", dst_dir)):
    env = Environment(loader=FileSystemLoader(d), autoescape=select_autoescape(["html"]), finalize=_shown)
    env.filters["short"] = _short
    env.filters["oneline"] = _oneline
    tpl = env.get_template("_approvals.html")
    pending = [{"id": f"apr_{i:012x}", "sandbox_id": "sb_x", "created_at": "2026-01-01T00:00:00Z", "tool": "write_file",
                "rule_id": "r", "rule_reason": "x", "args": {"path": "CLAUDE.md", "content": "\x01" * (1024 * 1024)},
                "preview": {"instruction_file": "claude.md", "affected": [], "notes": []}} for i in range(20)]
    t0 = time.time()
    body = tpl.render(pending=pending, done=[], sandbox_id="", timeout=300, error=None).encode()
    hashlib.sha256(body).hexdigest()
    print(f"{label}: 20 x 1 MiB U+0001 render+sha256 {time.time()-t0:.3f} s, body {len(body)} bytes",
          "| tail marker present:", "1044480자 더" in body.decode())
