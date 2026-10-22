# Bounded harness: the terminal approver escapes bidi/control characters in agent-chosen exec commands
# (cli._safe), while the web approval card renders a.args.command through HTML autoescape only.
# jinja2/markupsafe are not installed in this sandbox; markupsafe.escape replaces only & < > " ' (same set
# as html.escape(quote=True)), so html.escape is used as the stand-in for the autoescape transform.
import html, re, sys
sys.path.insert(0, "/target")
from agentbox import cli
tpl = open("/target/agentbox/templates/_approvals.html", encoding="utf-8").read()
print("web card sink:", re.search(r"<pre>\{\{ a\.args\.command \}\}</pre>", tpl).group(0))
payload = "echo 'listing done ⁧' ; sh /workspace/x.sh ; echo '⁩'"
print("terminal approver shows:", cli._safe(payload))
esc = html.escape(payload, quote=True)
bidi = [hex(ord(c)) for c in esc if c in "‪‫‬‭‮⁦⁧⁨⁩‎‏"]
print("HTML-escaped text still contains bidi controls:", bidi)
print("cli._safe covers U+061C ARABIC LETTER MARK:", "؜" not in cli._safe("؜"))
