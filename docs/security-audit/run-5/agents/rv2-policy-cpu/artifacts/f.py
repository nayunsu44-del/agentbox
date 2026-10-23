import time, shlex, random
import agentbox.policy as P
from agentbox.policy import Policy
orig=P._words
_LEX = set(";&|()<>")
def needs_relex(t):
    if not (any(c.isspace() for c in t) or any(c in P._SHELL_PUNCT for c in t)): return False
    if all(c in _LEX for c in t): return False
    return any(c.isspace() or c in _LEX or c in "'\"\\" for c in t)
def new(command, depth=0):
    if depth>4: return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split=True; lex.commenters=""; tokens=list(lex)
    except ValueError: tokens=command.split()
    out=[]
    for t in tokens:
        if not t: continue
        out.extend(t.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ").split())
        if needs_relex(t): out.extend(new(t, depth+1))
    return out
random.seed(7)
alpha = list("ab;&|()<>`$'\" \\{}x\n\t#")
diff=0; N=100000
for i in range(N):
    s=''.join(random.choice(alpha) for _ in range(random.randint(0,24)))
    if set(orig(s)) != set(new(s)): diff+=1; print('DIFF',repr(s)); 
    if diff>3: break
print('fuzz',N,'diff',diff)
frag=["sh -c ","'x;r\"\"m'","\"a b\"","`rm`","$(c\"\"url)","'","\"","\\","x;","&&","|"," ","a\\ b","'a \"b c\" d'"]
for i in range(50000):
    s=''.join(random.choice(frag) for _ in range(random.randint(0,8)))
    if set(orig(s)) != set(new(s)): diff+=1; print('DIFF',repr(s))
    if diff>3: break
print('fuzz2 diff',diff)
deny = Policy({"default":"allow","rules":[{"id":"d","tool":"exec","match":{"commands":["rm","curl"]},"action":"deny"}]})
P._words=new
for c in ["sh -c 'x;r\"\"m'","sh -c 'a|c\"\"url'","bash -c 'x;rm y'"]:
    print('lossless', repr(c), deny.decide('exec',{'command':c}).action)
p = Policy.load('/target/agentbox/default_policy.yaml')
shapes=['x;','x$ ','$(x ','`a` ','a&b ','"a b" ',"'a b' ","'x;y' ",'x$(y) ','`a b` ',"'\"a b\" c' ", "x\\ y "]
for size in (8192,65536):
    for unit in shapes:
        c=unit*(size//len(unit))
        t=time.perf_counter(); p.decide('exec',{'command':c}); print('lossless',size,repr(unit),round(time.perf_counter()-t,3))
P._words=orig
for size in (8192,65536):
    for unit in ["'a b' ","'x;y' ","'\"a b\" c' ","x\\ y "]:
        c=unit*(size//len(unit))
        t=time.perf_counter(); p.decide('exec',{'command':c}); print('current',size,repr(unit),round(time.perf_counter()-t,3))
