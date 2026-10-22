#!/usr/bin/python3
"""Parent-side intake of one verifier's returned result (security-audit Phase 3).

usage: ingest.py <verifier-id> <agent-output-file> <expected-fingerprint>

  1. extracts the verifier's final message (the `message` of its last SubagentHandback call) from its transcript file
  2. rejects anything that is not exactly one JSON object (prose-wrapped or fenced results are discarded, never repaired)
  3. checks decision/verdict/fingerprint consistency and the artifacts list shape
  4. validates the record against report-schema.json with the skill's validate-findings.cjs (one-record findings file)
  5. stores the raw result as agents/<id>/result.json and promotes allowlisted artifacts with promote.py
Nothing is written to the ledger here; that happens after every Phase 3 verifier has finished (independence).
"""
import json
import os
import re
import subprocess
import sys
import tempfile

RUN = "/home/user/agentbox/docs/security-audit/run-3"
SK = "/tmp/claude-0/-home-user-agentbox/cde56229-bf0c-5d8f-8bbf-3e6a7e748654/scratchpad/skill/skills/security-audit"
PROMOTE = "/tmp/claude-0/-home-user-agentbox/cde56229-bf0c-5d8f-8bbf-3e6a7e748654/scratchpad/promote.py"
DECISIONS = {"confirmed", "needs_validation", "rejected"}


def final_message(path):
    """Last SubagentHandback message or last assistant text from a JSONL transcript;
    a file that is not a JSONL transcript is taken as the verifier's raw final message."""
    msg = None
    with open(path, encoding="utf-8") as f:
        data = f.read()
    try:
        lines = [json.loads(l) for l in data.splitlines() if l.strip()]
        if not all(isinstance(o, dict) and "type" in o for o in lines):
            raise ValueError
    except ValueError:
        return data
    for o in lines:
        c = o.get("message", {}).get("content")
        if o.get("type") == "assistant" and isinstance(c, list):
            for b in c:
                if b.get("type") == "tool_use" and b.get("name") == "SubagentHandback":
                    msg = b["input"].get("message")
                elif b.get("type") == "text" and b.get("text", "").strip():
                    msg = b["text"]
    return msg


def _unused(path):
    msg = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            c = o.get("message", {}).get("content")
            if o.get("type") == "assistant" and isinstance(c, list):
                for b in c:
                    if b.get("type") == "tool_use" and b.get("name") == "SubagentHandback":
                        msg = b["input"].get("message")
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
        fail("no final handback message found")
    text = raw.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        fail(f"not exactly one JSON object ({e})")
    if not isinstance(obj, dict):
        fail("top level is not an object")
    extra = set(obj) - {"decision", "record", "artifacts_to_promote"}
    if extra or "decision" not in obj or "record" not in obj:
        fail(f"unexpected/missing top-level keys: extra={sorted(extra)}")
    d, rec = obj["decision"], obj["record"]
    if d not in DECISIONS:
        fail(f"bad decision {d!r}")
    if not isinstance(rec, dict) or rec.get("verdict") != d:
        fail("record.verdict does not match decision")
    if rec.get("fingerprint") != fp:
        fail(f"fingerprint changed: {rec.get('fingerprint')!r} != {fp!r} (needs a root-cause decision by the parent)")
    arts = obj.get("artifacts_to_promote", [])
    if not isinstance(arts, list) or not all(isinstance(a, str) for a in arts):
        fail("artifacts_to_promote must be a list of strings")
    # schema validation through the skill's own validator
    with tempfile.TemporaryDirectory(dir="/tmp/claude-0/-home-user-agentbox/cde56229-bf0c-5d8f-8bbf-3e6a7e748654/scratchpad") as td:
        p = os.path.join(td, "one.json")
        json.dump([rec], open(p, "w"))
        r = subprocess.run(["node", f"{SK}/validate-findings.cjs", p], capture_output=True, text=True, cwd="/tmp")
        res = (r.stdout + r.stderr).strip().splitlines()
        print("validator:", " | ".join(res[:6]))
        if r.returncode != 0:
            fail("schema/semantic validation failed")
    # keep the raw result for provenance (parent-owned file in the verifier's directory)
    dest = f"{RUN}/agents/{vid}/result.json"
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    promoted = []
    if arts:
        r = subprocess.run(["python3", "-I", PROMOTE, vid, *arts], capture_output=True, text=True)
        print((r.stdout + r.stderr).strip())
        promoted = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("PROMOTED")]
    sev = rec.get("severity", {}).get("overall_severity")
    print(f"OK {vid}: decision={d} severity={sev} trace={len(rec['trace'])} evidence={len(rec['evidence'])} "
          f"artifacts_promoted={len(promoted)}/{len(arts)}")
    print("title:", rec["title"])


if __name__ == "__main__":
    main()
