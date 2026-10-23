import time,sys,threading,asyncio,statistics
from agentbox.policy import Policy
p=Policy.load('/target/agentbox/default_policy.yaml')
def t(cmd):
    s=time.perf_counter(); d=p.decide('exec',{'command':cmd}); return time.perf_counter()-s, d.rule_id
for n in (8192,16384,32768,65536):
    print('x;',n*2,t('x;'*n))
for n in (8192,16384,21845):
    print('x$ ',n*3,t('x$ '*n))
    print('$ ',n*2,t('$ '*n))
# simulate fix: skip pure-punct re-lex
import agentbox.policy as P
orig=P._words
import shlex
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
        if all(c in P._SHELL_PUNCT for c in tk): continue
        if any(c.isspace() for c in tk) or any(c in P._SHELL_PUNCT for c in tk):
            out.extend(words(tk,depth+1))
    return out
P._words=words
print('--- patched words')
for n in (32768,65536):
    print('x;',n*2,t('x;'*n))
for n in (21845,):
    print('x$ ',n*3,t('x$ '*n))
