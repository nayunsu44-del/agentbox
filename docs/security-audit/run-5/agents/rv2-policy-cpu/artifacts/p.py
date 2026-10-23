import time, sys, shlex
import agentbox.policy as P
from agentbox.policy import Policy
orig = P._words
def new_words(command, depth=0):
    if depth > 4: return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        tokens = command.split()
    out=[]
    for t in tokens:
        if not t: continue
        cleaned = t.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ")
        out.extend(cleaned.split())
        if any(c.isspace() for c in t) or "`" in t or "$(" in t:
            out.extend(new_words(t, depth + 1))
    return out
deny = Policy({"default":"allow","rules":[{"id":"d","tool":"exec","match":{"commands":["rm","curl"]},"action":"deny"}]})
cmds = ["bash -c 'x;rm y'", "sh -c 'x;rm'", "sh -c 'x;r\"\"m'", "sh -c 'x&&c\"\"url h'", "sh -c 'a|c\"\"url'", "sh -c \"x;r''m -rf /\"", "sh -c 'true;r\\m f'", "eval 'x;rm y'"]
for mode,fn in (("current",orig),("proposed",new_words)):
    P._words = fn
    for c in cmds:
        d = deny.decide('exec',{'command':c})
        print(mode, repr(c), d.action, d.matched, sorted(P.command_names(c))[:8])
# timing with proposed
P._words = new_words
p = Policy.load('/target/agentbox/default_policy.yaml')
for unit in ('x;','x$ ','$(x ','`a` ','a&b ','"a b" ', 'x$(y) ', '`a b` '):
    for size in (8192, 65536):
        c=(unit*(size//len(unit)+1))[:size]
        t=time.perf_counter(); d=p.decide('exec',{'command':c}); e=time.perf_counter()-t
        print('proposed',size,repr(unit), round(e,3), d.action)
P._words = orig
for unit in ('`a b` ','x$(y) '):
    c=(unit*(8192//len(unit)+1))[:8192]
    t=time.perf_counter(); d=p.decide('exec',{'command':c}); e=time.perf_counter()-t
    print('current 8K',repr(unit), round(e,3))
