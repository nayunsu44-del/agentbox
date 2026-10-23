import json
p = f"run-metadata.json"
m = json.load(open(p, encoding="utf-8"))
m["phase"] = "phase6_reports"
m["run_status"] = "complete_with_deferred_units"
m["status_note"] = ("Every one of the 30 coverage units closed (21 covered, 9 candidate). 13 candidates went through Phase 3 and 12 "
                    "retained records through Phase 5. Two units proposed by the post-wave coverage critic are recorded as deferred "
                    "because the remaining budget is reserved for validation, so the run is disclosed as an explicit early stop for "
                    "those two boundaries, not as complete coverage.")
m["agents_spent"] = 46
m["budget_final"] = ("Cap 50. Spent 46: reconnaissance 4 (previous session), 13 hunters, 1 post-wave coverage critic, 13 Phase 3 "
                     "candidate verifiers, 12 Phase 5 record verifiers plus 3 retries of verifiers that failed or were re-run, and "
                     "2 non-material Phase 5 replacements applied without a second verifier. The final-clean critic and the two "
                     "critic-proposed units were not run for budget reasons.")
m["deviations"] = [
    "Four hunters (h-policy, h-queue, h-gui-race, h-preauth) did not write result.json; the parent transcribed their closing "
    "messages and remapped coverage ids from the ledger, so those result.json files are parent-written.",
    "v06 ran without its prompt.md (the generator failed first and was regenerated afterwards); it reconstructed the contract from "
    "the sibling v05 brief and said so in its record.",
    "Phase 5 r03 and r09 returned replace with corrections they certified as non-material (path prefixes, ordering wording, one "
    "observation sentence). tools/apply5_nonmaterial.py applied them without a second verifier and this deviation is disclosed "
    "in REPORT.md section 7.",
    "tools/sbx.py and tools/promote.py replace the Linux-only bash sbx and loop-mounted scratch; the enforcement boundary is the "
    "same, the 256 MiB scratch cap is replaced by common.cap_scratch plus the per-file and per-agent promotion caps.",
    "v05 reported that an out-of-scope write instruction arrived in its turn and refused it; nothing outside its scratch was "
    "written. Recorded as evidence that the audit boundary held.",
]
json.dump(m, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(p, "a", encoding="utf-8").write(chr(10))
print("metadata updated")
