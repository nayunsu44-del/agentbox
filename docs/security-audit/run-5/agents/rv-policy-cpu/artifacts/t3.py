import sys, time, random, shlex
sys.path.insert(0,"/target")
from agentbox import policy
from agentbox.policy import Policy, command_names, _words as orig_words
PUNCT=set(";&|()<>")
SP=set(";&|()<>`$")
QB=set("'\""+chr(92))
def words3(command, depth=0):
    if depth>4: return []
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split=True; lex.commenters=""
        tokens=list(lex)
    except ValueError:
        tokens=command.split()
    out=[]
    for t in tokens:
        if not t: continue
        cleaned=t.replace("$(", " ").replace("`", " ").replace("${", " ").replace("}", " ")
        out.extend(cleaned.split())
        if all(c in PUNCT for c in t): continue
        if (any(c.isspace() or c in SP for c in t)) and any(c.isspace() or c in PUNCT or c in QB for c in t):
            out.extend(words3(t, depth+1))
    return out
def names(w, cmd):
    ST="'\""+chr(92)+";&|()<>"
    return {x.strip(ST).rsplit("/",1)[-1] for x in w(cmd) if x.strip(ST)}
# fuzz equivalence of word SETS (command_names input)
random.seed(1)
alpha=["rm","curl","x"," ","\t",";","&","|","(",")","<",">","`","$(","$","${","}","'",'"',chr(92),"a","/","-","\n","#","=","$ "]
bad=0
for i in range(300000):
    s="".join(random.choice(alpha) for _ in range(random.randint(1,14)))
    if set(orig_words(s))!=set(words3(s)): bad+=1; ex=s
print("fuzz mismatches (word sets):",bad, repr(ex) if bad else "")
def timeit(w,c):
    s=time.perf_counter(); names(w,c); return time.perf_counter()-s
shapes={"x;":"x;","x$ ":"x$ ","bt":"`x` ","$(":"$(x ","sq":"\"'\" ","bs":"\\\\ ","dq":"\"a b\" ","amp":"a&b "}
for L in (8192,65536):
    for k,u in shapes.items():
        c=u*(L//len(u)); print(L,k,"orig %.3f lossless %.3f"%(timeit(orig_words,c),timeit(words3,c)))
