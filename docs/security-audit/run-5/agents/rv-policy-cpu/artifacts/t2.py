import sys; sys.path.insert(0,"/scratch")
sys.path.insert(0,"/target")
from agentbox import policy
from agentbox.policy import Policy
import t_patch
deny = Policy({"default":"allow","rules":[{"id":"deny-rm","tool":"exec","match":{"commands":["rm","curl"]},"action":"deny"}]})
cases = ["sh -c 'x;rm'", "sh -c 'x;r\"\"m'", "sh -c 'x;r\\m'", "sh -c \"x;'rm'\"", "bash -c 'x;rm y'", "sh -c 'x&&c\"\"url'", "sh -c 'ls;rm<y'", "sh -c 'a|c\"\"url'", "rm y", "sh -c 'x;rm y'"]
old=[deny.decide('exec',{'command':c}).action for c in cases]
policy._words = t_patch.words2
new=[deny.decide('exec',{'command':c}).action for c in cases]
for c,o,n in zip(cases,old,new): print(repr(c),o,n, "REGRESSION" if o!=n else "")
