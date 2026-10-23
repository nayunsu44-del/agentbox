#!/usr/bin/python3 -I
"""Build wave-3 hunter prompts for the units critic-2 proposed and the budget deferred (run-3).

usage: gen_hunt.py <scratchpad-dir>

Template: agents/h-gui2/prompt.md. Kept verbatim: architecture, core hunting method, core validation rules,
the structured-result contract and the schema branches. Replaced per hunter: assigned unit and leads,
selected attack-class blocks (copied verbatim from the skill's companion files), excluded blocks,
current candidates and peer-owned IDs, and the paths/sandbox block (audited worktree + sbx5).
"""
import json
import os
import re
import sys

RUN = "/home/user/agentbox/docs/security-audit/run-3"

HUNTERS = {
    # hunter id -> (unit surface prefix, extra parent-provided facts)
    "h-preview": ("approval card impact table", ""),
    "h-queue": ("agent tool calls that require approval", ""),
    "h-autostart": ("GUI-burst writes outside /workspace", """
Parent-observed facts about the shipped desktop image `agentbox-desktop:0.1` (from `docker run --network none` on this host earlier in this run; you cannot run Docker yourself):
- Installed: xdotool, python3 (ctypes finds libX11.so.6), perl, tclsh/wish (Tk 8.6.14), xfce4-terminal, xauth. NOT installed: xprop, wmctrl, xterm, zenity, gcc, crontab, at.
- `id desktop`: uid 1001, groups desktop(1001), agent(1000). /home/desktop is mode 700 owned by desktop. /etc/xdg/autostart has xfsettingsd.desktop and xscreensaver.desktop; /etc/xdg/xfce4 has panel, xfconf, xinitrc, helpers.rc.
- Agent GUI tools (key/type/click) can open xfce4-terminal as uid 1001 (run-2 N-1, partially mitigated by burst snapshot, gui_changes and stray kill)."""),
}


def block(sk, ref):
    fname, head = ref.split("#", 1)
    text = open(os.path.join(sk, fname), encoding="utf-8").read().splitlines()
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


def section(text, start, stop):
    i = text.index(start)
    return text[i:text.index(stop, i)]


def main():
    sp = sys.argv[1]
    sk = f"{sp}/skill/skills/security-audit"
    tpl = open(f"{RUN}/agents/h-gui2/prompt.md", encoding="utf-8").read()
    arch = section(tpl, "# architecture.md (verbatim)", "# Assigned coverage units")
    method = section(tpl, "# Core hunting method", "# Exclusions and peer-owned units")
    contract = tpl[tpl.index("## Structured hunter result"):]
    ledger = json.load(open(f"{RUN}/coverage-ledger.json", encoding="utf-8"))
    findings = json.load(open(f"{RUN}/findings.json", encoding="utf-8"))
    meta = json.load(open(f"{RUN}/run-metadata.json", encoding="utf-8"))
    lead = meta["new_unvalidated_leads"][0]
    for hid, (prefix, facts) in HUNTERS.items():
        unit = next(u for u in ledger if u["surface"].startswith(prefix))
        view = {k: unit[k] for k in ("coverage_id", "surface", "boundary", "subsystem", "attack_class", "starting_paths",
                                     "ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks", "prior_status")}
        reason = unit["unresolved"][0] if unit["unresolved"] else unit.get("x_critic_reason", "")
        blocks = [unit["attack_class"]] if unit["attack_class"].startswith("ATTACK-CLASSES.md#") else []
        blocks += unit["selected_companion_blocks"]
        sel = "\n\n".join(f"<!-- {b} -->\n{block(sk, b)}" for b in blocks)
        excl = "\n".join(f"- `{e['block']}`: {e['reason']}" for e in unit["excluded_blocks"])
        cands = "\n".join(f"- {r['fingerprint']} ({r['verdict']}): {r['title']}" for r in findings)
        cands += f"\n- {lead['fingerprint_proposal']} (parent-observed lead under separate validation): {lead['summary']}"
        peers = "\n".join(f"- {u['coverage_id']}" for u in ledger if u["coverage_id"] != unit["coverage_id"])
        scratch = f"{RUN}/agents/{hid}/scratch"
        os.makedirs(scratch, exist_ok=True)
        os.chown(scratch, 65534, 65534)
        sbx = f"{sp}/sbx5"
        out = f"""You are hunter `{hid}` in a defensive security audit of agentbox. Your goal is to find source-grounded security invariant failures in your assigned coverage unit, and you must return exactly one JSON object matching the structured-result contract at the end of this prompt.

{arch}# Assigned coverage units

{json.dumps(view, ensure_ascii=False, indent=1)}

## Parent-provided reconnaissance leads (unverified; settle each one either way, do not assume)

This unit was proposed by the post-wave-2 coverage critic and deferred for budget; it is now assigned to you in wave 3. Critic's reason:
- {reason.split(': ', 1)[-1]}
{facts}

For anything that needs the live Docker-backed control plane or the desktop image, make the claim as precise as possible and give an exact local validation plan; the parent will run it in Docker.

# Selected attack-class blocks (verbatim)

{sel}

# Excluded blocks

{excl}

{method}# Exclusions and peer-owned units

Carried same-source prior confirmed exclusions: none.

Current records and leads (do not re-report these root causes; report only new root causes or new variants with independent conditions):
{cands}

Peer-owned coverage IDs (do not duplicate; report a different boundary under `uncovered`):
{peers}

# Your paths, sandbox and result contract

- Agent ID: `{hid}`. Audited source (read-only): `{sp}/src-audited/` (git worktree at 8e4db9e; agentbox/, images/, deploy/, tests/ identical to source_ref 0e4b958). Read source there with Read/Grep/Glob or read-only shell; report repository-relative paths and line numbers of that tree. `/home/user/agentbox` is the working branch with later fixes; do not use it for lines. Never edit target files, ledger, architecture, findings, or another agent's directory.
- Your scratch directory (the ONLY place you may write): `{scratch}/`. Retained artifacts: `{RUN}/agents/{hid}/artifacts/` — parent-owned, never write there.
- Approved OS-enforced sandbox for ANY target-controlled execution (importing agentbox modules, running unit tests, harnesses): `{sbx} {hid} <cmd...>`. Inside it: audited source at `/target` (read-only, on PYTHONPATH), your scratch at `/scratch` (cwd, writable), no network, no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s. Use `/usr/bin/python3.13`. Example: write `{scratch}/h.py`, then run `{sbx} {hid} /usr/bin/python3.13 /scratch/h.py > {scratch}/h.out 2>&1`. For pytest: `/usr/bin/python3.13 -m pytest -p no:cacheprovider --basetemp=/scratch/pt -q /target/tests/test_unit.py`.
- Never run agentbox code outside `sbx5`. Never use the Docker daemon, start servers, or contact the network. If a claim needs the real Docker-backed control plane or the desktop image at runtime, say so: the parent will reproduce it live during validation. Record such a claim as a candidate with `proposed_verdict: "needs_validation"` and an exact local validation plan, or as `confirmed` only if your sandboxed harness alone demonstrates the boundary result.
- Promotion allowlist: list every scratch-relative file you want retained in a top-level `"artifacts_to_promote": ["h.out", ...]` array in your JSON (max 256 KiB each, 1 MiB total, regular files only). The parent promotes them after you finish; reference them in checks as `agents/{hid}/artifacts/<file>`. If you have no local check, use `method: "source"` and `artifact: null`.
- Time box: aim to finish within roughly 40 tool calls. Stop each line of investigation once the invariant is settled.

{contract}"""
        open(f"{RUN}/agents/{hid}/prompt.md", "w", encoding="utf-8").write(out)
        print(hid, len(out), "blocks", len(blocks))


if __name__ == "__main__":
    main()
