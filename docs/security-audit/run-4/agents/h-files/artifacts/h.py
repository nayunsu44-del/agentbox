import json, os, sys
sys.path.insert(0, "/target")
from pathlib import Path
from agentbox.sandbox import overlaps, safe_path, clean_name, _source_mount, SandboxManager, SandboxError

out = {}

# --- filesystem case-sensitivity probe (decides whether the case-variant alias is real here) ---
probe = Path("/scratch/probe"); (probe / "CaseDir").mkdir(parents=True, exist_ok=True)
out["fs_case_insensitive"] = (probe / "casedir").is_dir()
out["probe_stat_same_inode"] = os.stat(probe / "CaseDir").st_ino == os.stat(probe / "casedir").st_ino

tmp = Path("/scratch/fixture")
proj = tmp / "Users" / "Me" / "proj"
(proj / "data").mkdir(parents=True, exist_ok=True)
other = tmp / "other"; other.mkdir(parents=True, exist_ok=True)
data = proj / "data"
out["ov_ancestor_of_data"] = overlaps(proj, data)
out["ov_same"] = overlaps(data, data)
out["ov_below_data"] = overlaps(data / "x", data)
out["ov_unrelated"] = overlaps(other, data)
out["ov_missing_path"] = overlaps(Path("/scratch/nope/zzz"), data)

# case-variant spelling of the same directory, exactly the run-3 bypass shape (no monkeypatching)
alias = tmp / "users" / "me" / "proj"
out["alias_paths_identical_strings"] = (str(alias) == str(proj))
try:
    out["alias_samefile_true"] = os.path.samefile(alias, proj)
except OSError as e:
    out["alias_samefile_true"] = repr(e)
out["ov_case_variant_unaltered"] = overlaps(alias, data)

# unstat-able alias: samefile raises -> same() returns False (fail-open branch)
locked = tmp / "locked"; (locked / "data").mkdir(parents=True, exist_ok=True)
lnk = tmp / "lnk"; 
try: lnk.symlink_to(locked)
except OSError as e: out["symlink_err"] = repr(e)
os.chmod(locked, 0o000)
try:
    out["ov_unstatable_alias"] = overlaps(lnk / "data", locked / "data")
except OSError as e:
    out["ov_unstatable_alias"] = "raised " + repr(e)
os.chmod(locked, 0o755)

sp = {}
for c in ["/workspace/a", "a", "", "   ", "/workspace/../etc/passwd", "//workspace/x",
          "/workspaceevil", "/source/x", "/workspace/../source/y", "/workspace/./a/../b",
          "x/../../etc/passwd", "/source", "/workspace", "/WORKSPACE/x"]:
    try: sp[c] = safe_path(c)
    except SandboxError: sp[c] = "REJECT"
out["safe_path"] = sp

wp = {}
for c in ["/source/x", "/workspace", "/workspace/a", "/workspace/../source/y"]:
    try: wp[c] = SandboxManager._workspace_path(None, c)
    except SandboxError: wp[c] = "REJECT"
out["workspace_path"] = wp

names = [".", "..", "a/b", "a\\b", "a\x00b", "a\nb", "\u202eexe.txt", "-rf", '"q"', "...",
         ".hidden", "a b", "a" * 200, "a" * 201]
cn = []
for n in names:
    try: cn.append({"name": n[:16], "len": len(n), "result": clean_name(n)[:16]})
    except SandboxError: cn.append({"name": n[:16], "len": len(n), "result": "REJECT"})
out["clean_name"] = cn

m = _source_mount("/srv/proj")
out["mount"] = {"target": m.get("Target"), "read_only": m.get("ReadOnly"),
                "bind_options": m.get("BindOptions"), "type": m.get("Type")}

print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
Path("/scratch/h.out").write_text("# h-files run-4 local check: agentbox/sandbox.py overlaps()/safe_path()/_workspace_path()/clean_name()/_source_mount()\n"
                                  "# command: python tools/sbx.py h-files /usr/bin/python3 /scratch/h.py  (uid 65534, no net, /target ro)\n"
                                  + json.dumps(out, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
print("WROTE /scratch/h.out")
