import io
for p in ("tools/gen3.py", "tools/gen5.py"):
    s = open(p, encoding="utf-8").read()
    if "fence = chr(96) * 3" not in s:
        s = s.replace("from common import", "fence = chr(96) * 3\n\nfrom common import", 1)
        open(p, "w", encoding="utf-8").write(s)
    print(p, "patched" if "fence = chr(96) * 3" in s else "MISSING")
