import time,shlex
from agentbox.policy import Policy
import agentbox.policy as P
p=Policy.load('/target/agentbox/default_policy.yaml')
def words(command, depth=0):
    if depth>4: return []
    try:
        lex=shlex.shlex(command,posix=True,punctuation_chars=";&|()<>"); lex.whitespace_split=True; lex.commenters=""; tokens=list(lex)
    except ValueError: tokens=command.split()
    out=[]
    for tk in tokens:
        if not tk: continue
        cleaned=tk.replace("$("," ").replace("`"," ").replace("${"," ").replace("}"," ")
        out.extend(cleaned.split())
        if any(c.isspace() for c in tk) or "`" in tk or "$(" in tk:
            out.extend(words(tk,depth+1))
    return out
P._words=words
def t(c):
    s=time.perf_counter(); p.decide('exec',{'command':c}); return round(time.perf_counter()-s,3)
for name,c in (('x;',"x;"*32768),('x$ ',"x$ "*21845),('bt',"`x` "*13000),('$(',"$(x "*16000)):
    print(name,len(c),t(c))
