import time, sys
from agentbox.policy import Policy, _words, command_names
p = Policy.load('/target/agentbox/default_policy.yaml')
for n in (8192,16384,32768,65536):
    c='x;'*n
    t=time.perf_counter(); d=p.decide('exec',{'command':c}); e=time.perf_counter()-t
    print(len(c), round(e,2), d.action, d.rule_id)
for name,unit,n in (('x$ ','x$ ',21845),('bt','`a` ',16384),('dollarparen','$(x ',16384)):
    c=unit*n
    t=time.perf_counter(); d=p.decide('exec',{'command':c}); e=time.perf_counter()-t
    print(name,len(c), round(e,2), d.action, d.rule_id)
# 8 KiB
for unit in ('x;','x$ ','$(x ','`a` ','a&b ', '"a b" '):
    c=(unit*(8192//len(unit)+1))[:8192]
    t=time.perf_counter(); d=p.decide('exec',{'command':c}); e=time.perf_counter()-t
    print('8K',repr(unit), round(e,3))
