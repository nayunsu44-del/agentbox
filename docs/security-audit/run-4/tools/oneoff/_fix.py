import json,sys
sys.path.insert(0,"./tools")
from common import ledger
p="agents/h-policy/raw.txt"
obj=json.load(open(p,encoding="utf-8"))
base=obj["units"][0]
appr={"coverage_id":"x","disposition":"covered",
 "reviewed_paths":["agentbox/api.py","agentbox/service.py","agentbox/approvals.py","agentbox/web.py","agentbox/cli.py","agentbox/templates/_approvals.html"],
 "checks":[{"agent_id":"h-policy","reviewed_paths":["agentbox/api.py","agentbox/service.py","agentbox/approvals.py","agentbox/web.py","agentbox/cli.py","agentbox/templates/_approvals.html"],
  "invariant":"Only a human can decide an approval, the approver cannot alter the executing args, and the displayed object is the stored object.",
  "method":"local",
  "result":"POST /approvals/{aid} rejects agent principals with 403 and audits approval_forbidden (api.py:250-262); the Decision body has only decision (api.py:55-56); decide() executes the stored row (service.py:391,398,421) and ApprovalStore cannot rewrite args after INSERT (approvals.py:49-96). 16 concurrent claims -> exactly 1 winner; expired and denied rows refuse a later approve; a failed approval_decision or snapshot audit marks the row FAILED before any execution (service.py:399-418). Browser decisions need scope * (api.py:365,149-155), so a desktop-link session cannot approve.",
  "artifact":"agents/h-policy/artifacts/h_bind.out"}],
 "candidate_fingerprints":[],"unresolved":[]}
exe={"coverage_id":"y","disposition":"covered",
 "reviewed_paths":["agentbox/policy.py","agentbox/default_policy.yaml","agentbox/sandbox.py","agentbox/sandbox_common.py","agentbox/service.py"],
 "checks":[{"agent_id":"h-policy","reviewed_paths":["agentbox/policy.py","agentbox/default_policy.yaml","agentbox/sandbox.py","agentbox/sandbox_common.py","agentbox/service.py"],
  "invariant":"No command may be classified ALLOW while bash would execute a program outside the read-only allowlist, and the agent string must reach the container without a second host-side shell parse.",
  "method":"local",
  "result":"41-command battery through Policy.decide with default_policy.yaml: rm/curl/sh/bash/find/xargs/sed/python3/dd/env/timeout and every quoted, backslash-escaped, path-prefixed, wrapper-prefixed, pipe/chained and newline-separated composition reaches require_approval; ALLOW appears only for ls, cat, cd+ls, mkdir+touch, grep, tail, printf and the two harmless redirection forms. exec passes the command as a single bash -c argv element via _timed (sandbox.py:411-412, sandbox_common.py:19-21), so there is no host shell join. Hardening: default_policy.yaml:25-27 lists unquoted true/false, which PyYAML parses as booleans so they stringify to True/False and need approval (fail-closed); mkdir/touch are writes inside a rule documented as read-only.",
  "artifact":"agents/h-policy/artifacts/h_policy.out"}],
 "candidate_fingerprints":[],"unresolved":[]}
obj["units"]=[appr,exe,base]
json.dump(obj,open(p,"w",encoding="utf-8"),ensure_ascii=False)
mine=sorted((u for u in ledger() if u.get("agent_id")=="h-policy" and u["status"]=="in_progress"),key=lambda u:u["coverage_id"])
print("ledger units",len(mine))
for u,real in zip(obj["units"],mine):
    u["coverage_id"]=real["coverage_id"]
    u["reviewed_paths"]=sorted({q for c in u["checks"] for q in c.get("reviewed_paths",[])})
json.dump(obj,open(p,"w",encoding="utf-8"),ensure_ascii=False)
