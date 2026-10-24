"""Shared helpers for the run-6 prompt generators and intake scripts (parent-side only)."""
import json
import os
import re
import subprocess

RUN = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
_SP_FILE = f"{RUN}/tools/.scratchpad"
if os.name == "nt":  # Windows host
    SP = os.environ.get("AUDIT_SCRATCHPAD") or (
        open(_SP_FILE, encoding="utf-8").read().strip() if os.path.exists(_SP_FILE) else None
    )
    if not SP:
        raise SystemExit("set AUDIT_SCRATCHPAD to the Windows scratchpad (holds skill/ and src-audited/)")
    SBX = f"{RUN}/tools/sbx.py"  # Windows host: bash sbx cannot run; sbx.py keeps the same container boundary
    SBX_CMD = f"python {SBX}"
    PY = "/usr/bin/python3"  # agentbox-audit-sbx:1 image, Python 3.12
else:  # Linux cloud container
    SP = os.environ.get("AUDIT_SCRATCHPAD", "/tmp/claude-0/-home-user-agentbox/fcd2f048-3e17-52e2-9d78-d39b755653f3/scratchpad")
    SBX = f"{RUN}/tools/sbx"  # bash sbx: host /usr read-only, 256 MiB loop scratch
    SBX_CMD = SBX
    PY = "/usr/bin/python3.13"
SK = f"{SP}/skill/skills/security-audit"
SRC = f"{SP}/src-audited"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(RUN))).replace("\\", "/")
_HOST_ROOT = os.path.dirname(os.path.dirname(_REPO_ROOT)).replace("\\", "/")


def scrub(text: str) -> str:
    """Replace host-specific user paths with <WINDOWS_HOST_ROOT> in git-tracked prompt/artifact files."""
    if os.name != "nt":
        return text
    out = text.replace("\\", "/")
    for prefix in sorted({SP, _HOST_ROOT}, key=len, reverse=True):
        if prefix:
            p = prefix.replace("\\", "/")
            if p == SP:
                out = re.sub(re.escape(p), "<WINDOWS_HOST_ROOT>/scratch/run6", out, flags=re.IGNORECASE)
            else:
                out = re.sub(re.escape(p), "<WINDOWS_HOST_ROOT>", out, flags=re.IGNORECASE)
    return out


def write_prompt(aid: str, text: str) -> None:
    """Write the scrubbed prompt to agents/<aid>/prompt.md (tracked) and the live prompt to scratch (ignored)."""
    os.makedirs(f"{RUN}/agents/{aid}/scratch", exist_ok=True)
    with open(f"{RUN}/agents/{aid}/scratch/prompt_live.md", "w", encoding="utf-8") as f:
        f.write(text)
    with open(f"{RUN}/agents/{aid}/prompt.md", "w", encoding="utf-8") as f:
        f.write(scrub(text))


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
    """Per-agent scratch."""
    assert re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", aid)
    scratch = f"{RUN}/agents/{aid}/scratch"
    os.makedirs(scratch, exist_ok=True)
    os.makedirs(f"{RUN}/agents/{aid}/artifacts", exist_ok=True)
    if os.name != "nt":
        if not os.path.ismount(scratch):
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


SCRATCH_CAP = 256 * 1024 * 1024


def scratch_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            p = os.path.join(root, f)
            try:
                total += os.lstat(p).st_size
            except OSError:
                pass
    return total


def cap_scratch(aid):
    """Report (do not silently delete) an over-cap scratch; the parent decides."""
    scratch = f"{RUN}/agents/{aid}/scratch"
    if not os.path.isdir(scratch):
        return 0
    size = scratch_size(scratch)
    if size > SCRATCH_CAP:
        print(f"OVER-CAP {aid}: {size} > {SCRATCH_CAP}")
    return size


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
