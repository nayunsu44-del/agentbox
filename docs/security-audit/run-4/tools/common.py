"""Shared helpers for the run-4 prompt generators and intake scripts (parent-side only)."""
import json
import os
import re
import subprocess

RUN = "/home/user/agentbox/docs/security-audit/run-4"
SP = os.environ.get("AUDIT_SCRATCHPAD", "/tmp/claude-0/-home-user-agentbox/bc796aa2-37b4-5f3d-a870-3de255943f83/scratchpad")
SK = f"{SP}/skill/skills/security-audit"
SRC = f"{SP}/src-audited"
SBX = f"{RUN}/tools/sbx"


def block(ref):
    """Copy one attack-class block verbatim: a heading section (## / ###) or a bold-led paragraph."""
    fname, head = ref.split("#", 1)
    text = open(os.path.join(SK, fname), encoding="utf-8").read().splitlines()
    for i, line in enumerate(text):
        if re.fullmatch(r"#{2,3} " + re.escape(head) + r"( \(.*\))?", line):
            level = len(line) - len(line.lstrip("#"))
            body = [line]
            for nxt in text[i + 1:]:
                m = re.match(r"(#+) ", nxt)
                if m and len(m.group(1)) <= level:
                    break
                body.append(nxt)
            return "\n".join(body).strip()
        if line.startswith(f"**{head}**"):
            body = [line]
            for nxt in text[i + 1:]:
                if not nxt.strip():
                    break
                body.append(nxt)
            return "\n".join(body)
    raise KeyError(ref)


def fenced(path, marker):
    """Return the first ```text fenced block that follows `marker` in a skill file."""
    t = open(os.path.join(SK, path), encoding="utf-8").read()
    i = t.index(marker)
    j = t.index("```text\n", i) + len("```text\n")
    return t[j:t.index("```", j)].rstrip("\n")


def schema_branch(verdict):
    s = json.load(open(os.path.join(SK, "report-schema.json"), encoding="utf-8"))
    for b in s["items"]["oneOf"]:
        if b["properties"]["verdict"].get("const") == verdict:
            return json.dumps(b, ensure_ascii=False, indent=1)
    raise KeyError(verdict)


def ledger():
    return json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))


def save_ledger(L):
    L.sort(key=lambda u: u["coverage_id"])
    with open(f"{RUN}/coverage-ledger.json", "w", encoding="utf-8") as f:
        json.dump(L, f, ensure_ascii=False, indent=1)
        f.write("\n")


def make_scratch(aid):
    assert re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", aid)
    scratch = f"{RUN}/agents/{aid}/scratch"
    os.makedirs(scratch, exist_ok=True)
    os.makedirs(f"{RUN}/agents/{aid}/artifacts", exist_ok=True)
    if not os.path.ismount(scratch):  # 256 MiB cap on everything the agent and sandboxed code write
        img = f"{SP}/scratch-img/{aid}.img"
        os.makedirs(os.path.dirname(img), exist_ok=True)
        subprocess.run(["truncate", "-s", "256M", img], check=True)
        subprocess.run(["mkfs.ext4", "-q", "-F", img], check=True)
        subprocess.run(["mount", "-o", "loop,nosuid,nodev", img, scratch], check=True)
        lf = f"{scratch}/lost+found"
        if os.path.isdir(lf):
            os.rmdir(lf)
    os.chown(scratch, 65534, 65534)
    return scratch


def final_message(path):
    """Final assistant text of a subagent transcript (JSONL), or the file itself if it is not JSONL."""
    data = open(path, encoding="utf-8").read()
    try:
        lines = [json.loads(l) for l in data.splitlines() if l.strip()]
        if not all(isinstance(o, dict) and "type" in o for o in lines):
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
