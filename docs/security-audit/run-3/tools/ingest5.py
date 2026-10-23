#!/usr/bin/python3
"""Parent-side intake of one Phase 5 verifier's result (security-audit Phase 5).

usage: ingest5.py <verifier-id> <agent-output-file> <expected-fingerprint>

Accepts exactly one JSON object, with no surrounding prose:
  {"decision": "verified", "fingerprint": "..."}
  {"decision": "replace", "reason": "...", "record": {...}, "artifacts_to_promote": [...]}
A replacement record is validated with the skill's validate-findings.cjs. Malformed results are discarded,
never repaired. Stores the raw result as agents/<id>/result.json and promotes allowlisted artifacts.
Nothing is applied to findings.json or the ledger here.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

RUN = "/home/user/agentbox/docs/security-audit/run-3"
SP = os.environ["AUDIT_SCRATCHPAD"]
SK = f"{SP}/skill/skills/security-audit"
PROMOTE = f"{SP}/promote.py"


def final_message(path):
    """Last SubagentHandback message or assistant text from a JSONL transcript, or the whole file if it is not one."""
    data = open(path, encoding="utf-8").read()
    try:
        lines = [json.loads(l) for l in data.splitlines() if l.strip()]
        if not lines or not all(isinstance(o, dict) and "type" in o for o in lines):
            raise ValueError
    except ValueError:
        return data
    msg = None
    for o in lines:
        c = o.get("message", {}).get("content")
        if o.get("type") == "assistant" and isinstance(c, list):
            for b in c:
                if b.get("type") == "tool_use" and b.get("name") == "SubagentHandback":
                    msg = b["input"].get("message")
                elif b.get("type") == "text" and b.get("text", "").strip():
                    msg = b["text"]
    return msg


def fail(why):
    print("DISCARD:", why)
    sys.exit(1)


def main():
    vid, out, fp = sys.argv[1:4]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", vid):
        fail("bad verifier id")
    raw = final_message(out)
    if not raw:
        fail("no final message found")
    text = raw.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        fail(f"not exactly one JSON object ({e})")
    if not isinstance(obj, dict):
        fail("top level is not an object")
    d = obj.get("decision")
    arts = obj.get("artifacts_to_promote", [])
    if not isinstance(arts, list) or not all(isinstance(a, str) for a in arts):
        fail("artifacts_to_promote must be a list of strings")
    if d == "verified":
        if set(obj) - {"decision", "fingerprint", "artifacts_to_promote"}:
            fail(f"unexpected keys {sorted(set(obj))}")
        if obj.get("fingerprint") != fp:
            fail(f"fingerprint {obj.get('fingerprint')!r} != {fp!r}")
        summary = "verified"
    elif d == "replace":
        if set(obj) - {"decision", "reason", "record", "artifacts_to_promote"} or not {"reason", "record"} <= set(obj):
            fail(f"unexpected/missing keys {sorted(set(obj))}")
        rec = obj["record"]
        if not isinstance(rec, dict) or not isinstance(obj["reason"], str) or not obj["reason"].strip():
            fail("record must be an object and reason a nonempty string")
        with tempfile.TemporaryDirectory(dir=SP) as td:
            p = os.path.join(td, "one.json")
            json.dump([rec], open(p, "w"))
            r = subprocess.run(["node", f"{SK}/validate-findings.cjs", p], capture_output=True, text=True, cwd="/tmp")
            res = (r.stdout + r.stderr).strip().splitlines()
            print("validator:", " | ".join(res[:6]))
            if r.returncode != 0:
                fail("schema/semantic validation failed")
        same = rec.get("fingerprint") == fp
        sev = rec.get("severity", {}).get("overall_severity")
        summary = f"replace -> {rec.get('verdict')} severity={sev} same_fingerprint={same}"
    else:
        fail(f"bad decision {d!r}")
    with open(f"{RUN}/agents/{vid}/result.json", "w", encoding="utf-8") as f:
        f.write(text + "\n")
    if arts:
        r = subprocess.run(["python3", "-I", PROMOTE, vid, *arts], capture_output=True, text=True)
        print((r.stdout + r.stderr).strip())
    print(f"OK {vid}: {summary}")
    if d == "replace":
        print("reason:", obj["reason"][:600])


if __name__ == "__main__":
    main()
