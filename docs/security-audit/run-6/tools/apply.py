#!/usr/bin/env python3
"""Apply a verifier decision to findings.json and the ledger (run-6).

usage: apply.py 3 <verifier-id> <result-file>     Phase 3 candidate verifier
       apply.py 5 <verifier-id> <result-file>     Phase 5 record verifier
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RUN  # noqa: E402
MATERIAL = ("root_cause", "claimed_root_cause", "trace", "execution", "intended_behavior", "conditions")


def parse(path):
    txt = open(path, encoding="utf-8").read().strip()
    if txt.startswith("```"):
        txt = txt.split("\n", 1)[1] if "\n" in txt else txt
        txt = txt.rsplit("```", 1)[0].strip()
    return json.loads(txt)


def findings():
    p = f"{RUN}/findings.json"
    if not os.path.exists(p):
        return []
    return json.load(open(p, encoding="utf-8"))


def save_findings(recs):
    recs.sort(key=lambda r: r["fingerprint"])
    with open(f"{RUN}/findings.json", "w", encoding="utf-8") as f:
        json.dump(recs, f, ensure_ascii=False, indent=1)
        f.write("\n")


def upsert(recs, rec):
    recs[:] = [r for r in recs if r["fingerprint"] != rec["fingerprint"]] + [rec]


def mark_ledger(fp, vid, decision, reviewed):
    p = f"{RUN}/coverage-ledger.json"
    L = json.load(open(p, encoding="utf-8"))
    touched = 0
    for u in L:
        if fp in u.get("result_fingerprints", []):
            u["x_decision"] = decision
            u["x_decided_by"] = vid
            paths = sorted(set(u.get("reviewed_paths", [])) | set(reviewed))
            u["reviewed_paths"] = paths
            u["local_checks"] = u.get("local_checks", []) + [
                {"agent_id": vid, "method": "source", "artifact": None,
                 "reviewed_paths": reviewed or paths, "note": f"phase3 decision {decision}",
                 "invariant": "Phase 3 verifier re-decided the linked candidate for this unit",
                 "result": f"phase3 decision {decision}"}]
            touched += 1
    with open(p, "w", encoding="utf-8") as f:
        json.dump(L, f, ensure_ascii=False, indent=1)
        f.write("\n")
    return touched


def trace_paths(rec):
    out = set()
    for key in ("trace", "evidence"):
        for item in rec.get(key, []) or []:
            if isinstance(item, dict) and (item.get("file") or item.get("path")):
                out.add(item.get("file") or item["path"])
    return out


def material(old, new):
    why = []
    if old.get("verdict") != new.get("verdict"):
        why.append(f"verdict {old.get('verdict')} -> {new.get('verdict')}")
    for k in MATERIAL:
        if json.dumps(old.get(k), sort_keys=True, ensure_ascii=False) != json.dumps(new.get(k), sort_keys=True, ensure_ascii=False):
            why.append(k)
    so, sn = old.get("severity", {}), new.get("severity", {})
    for k in ("impact", "overall_severity", "likelihood"):
        if so.get(k) != sn.get(k):
            why.append(f"severity.{k}")
    return why


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    phase, vid, path = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        obj = parse(path)
    except Exception as e:
        print(f"DISCARD {vid}: not one JSON object ({e})")
        return 1
    arts = obj.get("artifacts_to_promote", []) or []
    if arts:
        r = subprocess.run([sys.executable, "-I", f"{RUN}/tools/promote.py", vid, *arts],
                           capture_output=True, text=True, encoding="utf-8")
        print((r.stdout + r.stderr).strip())
    recs = findings()
    if phase == "3":
        if obj.get("decision") not in ("confirmed", "needs_validation", "rejected"):
            print(f"DISCARD {vid}: bad decision {obj.get('decision')!r}")
            return 1
        rec = obj.get("record") or {}
        rec["verdict"] = obj["decision"]
        if not rec.get("fingerprint"):
            print(f"DISCARD {vid}: record has no fingerprint")
            return 1
        upsert(recs, rec)
        save_findings(recs)
        n = mark_ledger(rec["fingerprint"], vid, obj["decision"], sorted(trace_paths(rec)))
        os.makedirs(f"{RUN}/agents/{vid}", exist_ok=True)
        with open(f"{RUN}/agents/{vid}/result.json", "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
            f.write("\n")
        print(f"APPLIED phase3 {vid}: {rec['fingerprint']} {obj['decision']} ({n} ledger units)")
        return 0
    if phase == "5":
        fp = obj.get("fingerprint") or (obj.get("record") or {}).get("fingerprint")
        old = next((r for r in recs if r["fingerprint"] == fp), None)
        if old is None:
            print(f"DISCARD {vid}: fingerprint {fp!r} is not in findings.json")
            return 1
        if obj.get("decision") == "verified":
            os.makedirs(f"{RUN}/agents/{vid}", exist_ok=True)
            with open(f"{RUN}/agents/{vid}/result.json", "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=1)
                f.write("\n")
            print(f"VERIFIED phase5 {vid}: {fp}")
            return 0
        if obj.get("decision") != "replace":
            print(f"DISCARD {vid}: bad decision {obj.get('decision')!r}")
            return 1
        new = obj.get("record") or {}
        new.setdefault("fingerprint", fp)
        why = material(old, new)
        os.makedirs(f"{RUN}/agents/{vid}", exist_ok=True)
        with open(f"{RUN}/agents/{vid}/result.json", "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
            f.write("\n")
        if why:
            with open(f"{RUN}/agents/{vid}/pending-replacement.json", "w", encoding="utf-8") as f:
                json.dump(new, f, ensure_ascii=False, indent=1)
                f.write("\n")
            print(f"PARKED material replacement {fp}: {', '.join(why)}; needs a fresh independent verifier")
            return 3
        upsert(recs, new)
        save_findings(recs)
        print(f"APPLIED non-material replacement {vid}: {fp}")
        return 0
    print("phase must be 3 or 5", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
