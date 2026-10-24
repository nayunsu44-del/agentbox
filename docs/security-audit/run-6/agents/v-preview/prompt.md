You are candidate verifier `v-preview` in run-6 of a defensive security audit of agentbox. You did not write the candidate below and you did not hunt it.

# Audited source and version

Read-only audited source: `<WINDOWS_HOST_ROOT>/scratch/run6/src-audited/` — a git worktree of `main` at commit `530b29e` (after fix PRs #24 and #25). Every path and line you cite must exist in THAT tree.

# Candidate (proposed by a hunter; you did not write it)

```json
{
 "proposed_verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
 "title": "Approval impact preview misreports rm targets under brace and tilde expansion as nonexistent",
 "description": "The human approval preview card computes file impact by tokenizing the command with shlex and passing operands to container callbacks (_expand and _walk). In sandbox.py:_expand, the pattern is evaluated in container /bin/sh (dash), where brace expansion (e.g. {a,b}.txt, {1..100}) and positional parameter tilde expansion (~/file) are not performed. When _expand tests existence via [ -e /"$p/" ], no file literally named /"{a,b}.txt/" or /"/workspace/~/file/" exists, returning an empty match list. preview_command (preview.py:110-111) maps this to {'path': op, 'effect': '삭제 시도 (현재 존재하지 않음)'} and appends no warning note. When the human approves the action believing the target does not exist, sandbox.py:425 executes the command via /bin/bash, which performs full brace and tilde expansion and deletes the real files.",
 "root_cause": "The preview command parsing and container path expansion logic diverges from the execution shell. preview_command in preview.py tokenizes commands with POSIX shlex and delegates expansion to _expand, which invokes /bin/sh (dash) with positional argument $1. POSIX dash does not support brace expansion and does not expand tildes within variable expansions, returning empty matches for {a,b} and ~ operands. Furthermore, preview.py:88 warns only on $, `, <, and eval, failing to flag brace or tilde characters. The system erroneously asserts that targets do not exist rather than warning that shell expansion could not be calculated.",
 "intended_behavior": "Approval impact preview should either execute expansion using the same shell (bash) and environment as execution, or detect shell-specific expansion constructs such as { and ~ and add an explicit warning note (notes) that the exact affected files could not be computed automatically, prompting the operator to inspect the raw command before approval.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/service.py",
   "line": 318,
   "scope": "AgentBox._call_tool",
   "description": "Agent submits an exec tool request with rm command using brace or tilde expansion."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 354,
   "scope": "AgentBox._call_tool",
   "description": "Policy routes destructive command to require_approval and invokes _preview."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 595,
   "scope": "SandboxManager.preview",
   "description": "Delegates to preview_command with container _expand and _walk callbacks."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 109,
   "scope": "preview_command",
   "description": "Loops over rm operands and calls expand(op) for brace/tilde pattern."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 578,
   "scope": "SandboxManager._expand",
   "description": "Runs /bin/sh (dash) script where $1 does not expand braces or tildes, returning empty list."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 111,
   "scope": "preview_command",
   "description": "Appends '삭제 시도 (현재 존재하지 않음)' to affected list with no warning note."
  },
  {
   "kind": "sink",
   "file": "agentbox/templates/_approvals.html",
   "line": 14,
   "scope": "approvals.html template",
   "description": "Operator is presented with an approval card stating target does not exist, and upon approval bash deletes real files."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/preview.py",
   "line": 111,
   "description": "preview_command maps empty expand(op) result to '삭제 시도 (현재 존재하지 않음)' without warning note."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 578,
   "description": "_expand executes via /bin/sh (dash) script where positional $1 lacks brace and tilde expansion."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 425,
   "description": "exec runs under /bin/bash where brace and tilde expansions take place upon execution."
  }
 ],
 "conditions": [
  {
   "kind": "authorization_role",
   "description": "Agent must have token to call tools on its sandbox."
  },
  {
   "kind": "user_interaction",
   "description": "Human operator must approve the pending exec request based on the inaccurate impact card."
  }
 ],
 "execution": {
  "attacker_perspective": "Agent issues exec tool call: POST /sandboxes/{sid}/tools/exec with command 'rm {a,b}.txt' where 'a.txt' and 'b.txt' exist in /workspace.",
  "payloads": [
   "rm {a,b}.txt",
   "rm ~/test_agentbox_audit_tilde.txt"
  ],
  "instructions": [
   "Create files 'a.txt' and 'b.txt' in /workspace.",
   "Run preview_command('rm {a,b}.txt', 200, expand, walk) using container _expand.",
   "Observe that preview card lists 'affected': [{'path': '{a,b}.txt', 'effect': '삭제 시도 (현재 존재하지 않음)'}] and empty 'notes'.",
   "Execute 'bash -c /"umask 002//nrm {a,b}.txt/"' as in sandbox.py:425 and observe that 'a.txt' and 'b.txt' are deleted."
  ],
  "observed_result": "Preview reported affected: [{'path': '{a,b}.txt', 'effect': '삭제 시도 (현재 존재하지 않음)'}], notes: []. Bash execution deleted both a.txt and b.txt, leaving remaining files: []."
 },
 "remediation": {
  "strategy": "In preview.py:88, include '{' and '~' in the check for shell substitution/expansion constructs, or update _expand to use bash with nullglob or flag unexpanded braces so that notes warns the operator that file impact could not be automatically calculated.",
  "code_changes": [
   {
    "file_name": "agentbox/preview.py",
    "fixed_code": "    if any(s in command for s in (/"$/", /"`/", /"<(/", /"eval /", /"{/", /"~/")):/n        notes.append(/"변수·명령 치환이나 중괄호·틸드 확장이 있어 실제로 무엇이 실행될지 자동 계산이 정확하지 않을 수 있음. 명령 원문을 확인할 것./")"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "low",
   "reason": "Requires prompt-injected agent to use brace or tilde expansion in rm command and human operator to rely on nonexistent status on card."
  },
  "impact": {
   "score": "low",
   "reason": "Action-binding card misreports existence of target files to the human operator before destructive deletion."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Demonstrated through exact sandboxed reproduction matching container shell and preview implementation."
 }
}
```

# Linked coverage-unit checks

```json
[
 {
  "coverage_id": "Approval-preview%20truthfulness%20after%20the%20F4%20change%3A%20preview_command%20%28rm%20operand%20expansion%20via%20_expand%2C%20recursive%20_walk%2C%20curl%20upload%20detection%2C%20_split_segments%20and%20_WRAPPERS%20handling%29%20versus%20what%20the%20approved%20shell%20command%20really%20does::Human%20approval%20binding%3A%20the%20card%20the%20human%20decides%20on%20is%20computed%20by%20a%20separate%20shell-parse%20and%20container%20glob%2Ffind%2C%20not%20by%20the%20executing%20shell.%20The%20run-4%20F4%20fix%20replaced%20newline%20output%20with%20NUL-separated%20records%20and%20head%20-z%2C%20and%20no%20run-5%20unit%20re-checks%20the%20card%20against%20real%20behaviour.%20Cases%20to%20test%3A%20brace%20and%20tilde%20expansion%2C%20dotfile%20globs%2C%20rm%20-f%2F--no-preserve-root%2C%20operands%20after%20%27--%27%2C%20symlinks%2C%20names%20with%20newlines%20or%20leading%20%27-%27%2C%20commands%20the%20preview%20marks%20%27no%20effect%20computed%27%2C%20and%20the%20200-item%20display%20truncation%20hiding%20later%20deletions.::agentbox%2Fpreview.py%23preview_command%2F_split_segments%20%2B%20agentbox%2Fsandbox.py%23_expand%2F_walk%2Fpreview%20%2B%20agentbox%2Fservice.py%23_preview%2Fdecide%20%2B%20agentbox%2Ftemplates%2F_approvals.html::Action-confirmation%20and%20approval%20binding%20%28preview%20does%20not%20match%20execution%29",
  "surface": "Approval-preview truthfulness after the F4 change: preview_command (rm operand expansion via _expand, recursive _walk, curl upload detection, _split_segments and _WRAPPERS handling) versus what the approved shell command really does",
  "boundary": "Human approval binding: the card the human decides on is computed by a separate shell-parse and container glob/find, not by the executing shell. The run-4 F4 fix replaced newline output with NUL-separated records and head -z, and no run-5 unit re-checks the card against real behaviour. Cases to test: brace and tilde expansion, dotfile globs, rm -f/--no-preserve-root, operands after '--', symlinks, names with newlines or leading '-', commands the preview marks 'no effect computed', and the 200-item display truncation hiding later deletions.",
  "local_checks": [
   {
    "agent_id": "h-preview-argcap",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "Approval preview accurately reports the files that will be deleted by the executing shell command (/bin/bash), and warns if shell expansion or substitution semantics differ.",
    "method": "local",
    "result": "Discrepancy confirmed: _expand runs in /bin/sh (dash) where brace expansion ({a,b}) and positional parameter tilde expansion (~/file) are not performed, causing preview_command to falsely report '삭제 시도 (현재 존재하지 않음)' with no warning notes, while executing shell (/bin/bash) deletes the existing files.",
    "artifact": "agents/h-preview-argcap/artifacts/h.out"
   },
   {
    "agent_id": "h-preview-argcap",
    "reviewed_paths": [
     "agentbox/service.py",
     "agentbox/templates/_approvals.html"
    ],
    "invariant": "Approval card shown to human operator conveys accurate action-confirmation semantics and alerts operator whenever preview calculations cannot compute the exact impact.",
    "method": "source",
    "result": "templates/_approvals.html renders preview.affected table and preview.notes. Because preview_command appends no note when matches is empty, the operator sees '현재 존재하지 않음' for brace/tilde targets without any warning that shell expansion failed.",
    "artifact": null
   },
   {
    "agent_id": "h-preview-argcap",
    "reviewed_paths": [
     "agentbox/default_policy.yaml"
    ],
    "invariant": "Commands involving rm, curl, or destructive operations are routed through human approval queue.",
    "method": "source",
    "result": "Rules rm-curl-needs-approval and exec-needs-approval route commands containing rm or not in read-only whitelist to require_approval, where approval card is generated by preview_command.",
    "artifact": null
   },
   {
    "agent_id": "parent-live",
    "reviewed_paths": [
     "agentbox/preview.py",
     "agentbox/sandbox.py"
    ],
    "invariant": "Live disposable Docker sandbox verification of SandboxManager.preview vs SandboxManager.exec for brace and tilde expansion",
    "method": "local",
    "result": "On a live container, sb.preview(sid, 'rm {a,b}.txt') and sb.preview(sid, 'rm ~/tilde_target.txt') both return effect='삭제 시도 (현재 존재하지 않음)' with notes=[], while sb.exec deletes a.txt, b.txt, and ~/tilde_target.txt.",
    "artifact": "agents/parent-live/artifacts/preview_brace_tilde_live.out"
   }
  ]
 }
]
```

# Prior-run record with the same fingerprint

```json
{
 "verdict": "confirmed",
 "fingerprint": "agentbox/sandbox.py:preview:_expand-word-splits-operands-and-line-splits-paths-so-affected-list-misreports-rm-targets",
 "title": "Approval impact table misreports rm targets whose paths contain whitespace or newlines (an existing file is shown as nonexistent)",
 "description": "For a gated exec the /"system-computed impact/" table is produced by SandboxManager._expand / _walk and preview_command. _expand hands the already-unquoted rm operand to sh as $1 and iterates over $1 unquoted, so the operand is word-split on IFS and each fragment is pathname-expanded before the [ -e ] existence test; results are newline-framed and re-split in Python, and _walk frames find output the same way. preview_command turns an empty match list into /"삭제 시도 (현재 존재하지 않음)/" and every returned line into a /"삭제/" row. The rm itself later runs through bash -c with the original quoting, so the computed path set and the executed path set differ: an agent whose workspace target contains a space obtains approval for a deletion the card describes as an apparent no-op, or for a card that lists unrelated decoy files, while the real file is deleted. Reproduced with the verbatim scripts: the card for a lone rm of an existing /"final report.docx/" showed exactly one row, /"삭제 시도 (현재 존재하지 않음)/", and no note.",
 "root_cause": "The preview path transport is not a lossless representation of a filesystem path. sandbox.py:559 iterates $1 unquoted under the default IFS, so an operand that shlex already unquoted (preview.py:33-44) is re-split into words and each word is expanded again before the existence test; matches are framed with printf /"%s//n/" and re-split by splitlines() (sandbox.py:562), and _walk's find | head output is split the same way (sandbox.py:565-569). preview.py:90-91 maps an empty expansion to the /"does not currently exist/" row and preview.py:96-98 maps each returned line to a deletion row, so a split operand both hides the real target and can manufacture paths the command will never touch. The executed command keeps its quoting (sandbox.py:411), so the card and the effect diverge.",
 "intended_behavior": "The affected list shown beside the approval must name exactly the paths the stored command will act on, so approving the card is equivalent to approving the effect: a path that exists must never be reported as nonexistent, and a path must never be listed as deleted unless the command deletes it.",
 "trace": [
  {
   "kind": "entrypoint",
   "file": "agentbox/api.py",
   "line": 215,
   "scope": "POST /sandboxes/{sid}/tools/{tool}",
   "description": "The agent posts tool=exec with body.args.command under its own sandbox token."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 318,
   "scope": "AgentBox._call_tool",
   "description": "For a REQUIRE_APPROVAL decision (default_policy.yaml:12-16 routes rm to require_approval) the preview is computed while the approval is created, before any human sees it."
  },
  {
   "kind": "propagation",
   "file": "agentbox/service.py",
   "line": 215,
   "scope": "AgentBox._preview",
   "description": "exec previews delegate to SandboxManager.preview with the raw command string."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 573,
   "scope": "SandboxManager.preview",
   "description": "preview_command runs with expand=_expand and walk=_walk bound to the running container."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 89,
   "scope": "preview_command rm branch",
   "description": "Each rm operand (quotes already consumed by _split_segments, preview.py:33-44) is expanded once through the container callback."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 559,
   "scope": "SandboxManager._expand",
   "description": "The operand is passed as $1 and iterated unquoted, so the shell word-splits it on IFS and globs the fragments before [ -e /"$p/" ]; the surviving words are what get tested."
  },
  {
   "kind": "propagation",
   "file": "agentbox/sandbox.py",
   "line": 562,
   "scope": "SandboxManager._expand return",
   "description": "Matches are framed one per line and re-split with splitlines(), so a name containing a newline arrives as two or more fake paths."
  },
  {
   "kind": "propagation",
   "file": "agentbox/preview.py",
   "line": 90,
   "scope": "preview_command affected rows",
   "description": "An empty expansion becomes the /"삭제 시도 (현재 존재하지 않음)/" row and each returned line becomes a deletion row; the result is stored with the approval and rendered as the system-computed impact."
  },
  {
   "kind": "sink",
   "file": "agentbox/sandbox.py",
   "line": 411,
   "scope": "SandboxManager.exec after approval",
   "description": "After the human approves, decide() snapshots (service.py:412) and _run_tool passes the stored command unchanged (service.py:126) to exec, which runs it verbatim through bash -c; the quoting is intact there, so the file the table called nonexistent is actually deleted."
  }
 ],
 "evidence": [
  {
   "file": "agentbox/sandbox.py",
   "line": 559,
   "description": "for p in $1 - the operand is expanded without quotes under the default IFS, so a space splits it and each fragment is globbed; reproduced with only the cd target retargeted."
  },
  {
   "file": "agentbox/preview.py",
   "line": 91,
   "description": "An empty match list becomes the /"삭제 시도 (현재 존재하지 않음)/" row - the false no-op statement for an existing but split path, produced with notes=[]."
  },
  {
   "file": "agentbox/preview.py",
   "line": 97,
   "description": "Matched paths become /"삭제/" rows, so split words (decoy names that exist) are presented as the deletion set."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 562,
   "description": "out.splitlines() turns one filename containing a newline into several rows; expand(/"*/") over fixtures /"a//nb/" and ok.txt returned [a, b, ok.txt]."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 565,
   "description": "_walk frames find output line by line (splitlines at 569), so a recursive rm over /"dir with space/inner//nname.txt/" reports /"dir with space/inner/" and /"name.txt/" instead of the real path."
  },
  {
   "file": "agentbox/sandbox.py",
   "line": 411,
   "description": "The approved command runs as a single bash -c argument, so shell quoting is honoured and the computed set diverges from the executed set."
  },
  {
   "file": "agentbox/service.py",
   "line": 412,
   "description": "decide() snapshots before execution, which bounds the impact to low."
  },
  {
   "file": "agentbox/preview.py",
   "line": 125,
   "description": "The per-segment note added for run-3 v17 shows the module already treats /"the table may be incomplete/" as security-relevant; the split-path case produces no note at all."
  },
  {
   "file": "agentbox/templates/_approvals.html",
   "line": 14,
   "description": "The table renders the not-existing row without the deletion highlight (only effect == 삭제 gets class del), so the sole row on the card looks like a failed no-op; the raw command is shown above it at line 8."
  },
  {
   "file": "agentbox/display.py",
   "line": 18,
   "description": "Control characters are escaped for display, so the defect is in the computed path set, not in the rendering."
  }
 ],
 "conditions": [
  {
   "kind": "authentication_level",
   "description": "A sandbox agent token (or prompt-injected code running as uid 1000 inside that sandbox) submits the rm; the default policy routes rm to require_approval, so the approval card is the only control between it and the deletion."
  },
  {
   "kind": "user_interaction",
   "description": "A human opens the pending approval in the /ui/approvals card or agentbox approve and presses approve, relying on the system-computed impact table rather than re-reading the raw command."
  },
  {
   "kind": "data_state",
   "description": "The rm operand names an existing /workspace path containing whitespace (space or tab) or a newline; the agent can produce that state itself, since creating a new file with write_file needs no approval."
  },
  {
   "kind": "system_configuration",
   "description": "Stock default_policy.yaml, where exec commands containing rm route to require_approval (default_policy.yaml:12-16)."
  }
 ],
 "execution": {
  "attacker_perspective": "The sandbox agent wants to delete /workspace/final report.docx but wants the card not to say so, so it submits exec rm /"final report.docx/". The card describes the target as /"삭제 시도 (현재 존재하지 않음)/" - an apparently already-failed no-op - and with decoy names present it lists files that will not be touched, while the approved command deletes the real file.",
  "payloads": [
   "rm /"final report.docx/"",
   "decoy fixtures final and report.docx in the same directory",
   "rm over a workspace containing a file named /"a//nb/"",
   "rm -r over /"dir with space/"//"inner//nname.txt/"",
   "rm notes.txt; mv important /tmp/important (run-3 v17 revalidation)"
  ],
  "instructions": [
   "Create fixtures in the approved sandbox (tools/sbx.py v06, no network, read-only /target, writes only /scratch): a directory holding one file literally named final report.docx plus notes.txt.",
   "Copy the sandbox.py:559 and sandbox.py:565 scripts verbatim, changing only cd /workspace to the fixture directory (the sandbox has no /workspace and uid 65534 cannot create one), and wrap them exactly as sandbox.py:560-562 / 567-569 do (decode, splitlines) to build the expand and walk callbacks.",
   "Import agentbox.preview from /target (PYTHONPATH) and call preview_command('rm /"final report.docx/"', 200, expand, walk); compare the affected rows and notes with os.path.exists on the real file.",
   "Repeat with decoy files final and report.docx present, and with fixtures named /"a//nb/" and /"a//tb.txt/" for the expand path and /"dir with space/inner//nname.txt/" for the walk path.",
   "Re-run the run-3 v17 case rm notes.txt; mv important /tmp/important and check that its per-segment note still appears.",
   "Show the sink: run sh -c 'rm /"final report.docx/"' in the fixture directory (the quoting sandbox.py:411 hands to bash) and confirm the file the table called nonexistent is gone."
  ],
  "observed_result": "Case B: affected=[{path: /"final report.docx/", effect: /"삭제 시도 (현재 존재하지 않음)/"}], notes=[], real target exists: true. Case C (decoys present): affected=[{path: /"final/", effect: /"삭제/"}, {path: /"report.docx/", effect: /"삭제/"}] while the real target still exists and is never listed. Newline case: expand(/"*/") -> [/"a/", /"b/", /"ok.txt/"] for files /"a//nb/" and ok.txt, and the old find framing returned [/"dir with space/", /"dir with space/inner/", /"name.txt/"]. Sink: sh -c 'rm /"final report.docx/"' exited 0 and the directory went from [final report.docx, notes.txt] to [notes.txt]. Case A (revalidation): /"rm notes.txt; mv important /tmp/important/" produced the rm row AND the per-segment note, so the run-3 omission defect is fixed. The proposed fix was also executed against the same fixtures: with IFS= and NUL framing expand returned [/"final report.docx/"] and a single /"a//nb/", and find -print0 | head -z kept /"dir with space/inner//nname.txt/" whole. Everything ran inside tools/sbx.py v06."
 },
 "remediation": {
  "strategy": "Make both preview transports lossless. In _expand, disable IFS word splitting (IFS=) so the operand is tested as one word while pathname expansion still happens, and frame results with NUL instead of newline; in _walk, use find -print0 with head -z and split on NUL. Then one match is one path: the /"does not currently exist/" row is emitted only when the path really is absent, and no row names a path the command will not touch. Add a regression test that pushes names containing a space, a tab and a newline through both the non-recursive and the recursive branch and asserts the returned list equals the fixture paths.",
  "code_changes": [
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "def _expand(self, c, pattern: str) -> list[str]:/n    /"/"/"컨테이너 안에서 glob만 펼친다. 명령 치환은 일어나지 않는다./"/"/"/n    script = ('cd /workspace; IFS=; for p in $1; do if [ -e /"$p/" ] || [ -L /"$p/" ]; then printf /"%s////0/" /"$p/"; fi; done')/n    res = c.exec_run([/"sh/", /"-c/", script, /"_/", pattern], user=AGENT_UID, demux=True)/n    out = (res.output[0] or b/"/").decode(/"utf-8/", errors=/"replace/")/n    return [p for p in out.split(/"//0/") if p]"
   },
   {
    "file_name": "agentbox/sandbox.py",
    "fixed_code": "def _walk(self, c, path: str, limit: int) -> list[str]:/n    res = c.exec_run([/"sh/", /"-c/", 'cd /workspace; case /"$1/" in -*) set -- /"./$1/" /"$2/";; esac; find /"$1/" -print0 2>/dev/null | head -z -n /"$2/"',/n                      /"_/", path, str(limit)],/n                     user=AGENT_UID, demux=True)/n    out = (res.output[0] or b/"/").decode(/"utf-8/", errors=/"replace/")/n    return [p for p in out.split(/"//0/") if p]"
   }
  ]
 },
 "severity": {
  "likelihood": {
   "score": "medium",
   "reason": "The mechanics are deterministic for any rm operand naming a /workspace path with whitespace or a newline, and the agent can create such a name itself with an ungated write_file before requesting the rm, so the condition is attacker-chosen rather than accidental; exploitation still needs the approver to rely on the table instead of the raw command displayed immediately above it, and only rm and curl reach this preview."
  },
  "impact": {
   "score": "low",
   "reason": "What is lost is informed consent on the card, not a boundary: the effect is a deletion inside the requesting agent's own /workspace, the resource class the rm approval governs, decide() snapshots immediately before execution so the files are recoverable, and the decoy rows are misleading text rather than an additional capability."
  },
  "overall_severity": "low"
 },
 "confidence": {
  "score": "high",
  "reason": "Every cited line was re-read in 9805d91, the divergence was reproduced inside the approved sandbox with the verbatim _expand/_walk scripts (only the cd target substituted) and the verbatim preview_command, the sink step confirms the stored command keeps its quoting and really deletes the file, and the proposed fix was executed against the same fixtures."
 }
}
```

# Parent-live evidence

- `agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/preview_brace_tilde_live.out` (at `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/parent-live/artifacts/docs/security-audit/run-6/agents/parent-live/artifacts/preview_brace_tilde_live.out`)

# Architecture facts (summary; re-check every line you rely on)

# agentbox architecture summary (run-6)
Source ref: `530b29e` (`main`, after fix PRs #24 and #25). Profile `standard`, focused follow-up, budget 30 (all subagents `flash`). This file is the run-4/run-5 architecture plus a parent-written delta in section 0 covering every file changed since `346df29` (PRs #24 and #25: 13 non-test files in `agentbox/` and `deploy/`) and the run-5 delta from `9805d91` to `346df29`. No reconnaissance agent was spent in run-6: the parent inspected the full diff `346df29..530b29e`. **Line numbers in section 0.1 are exact at `530b29e`; section 0.2 has `346df29` numbers; sections 1-8 are `9805d91` numbers.**
## 0.1 Run-6 delta (changes in PRs #24 and #25, exact line numbers at `530b29e`)
- **Pre-read credential gate and anonymous body cap (`api.py`, `config.py`, `cli.py`, `deploy/`, PR #25 — run-5 N1 fix).**
  - `api.py:52-54`: `_UPLOAD_PATH = re.compile(r"/sandboxes/[^/]+/files")`, `_ANON_BODY_PATHS = {"/login"}`, `_ANON_BODY_MAX = 64 * 1024`.
  - `api.py:57-128` `_BodyLimit`: takes `authenticated` callback (`api.py:63-65`, wired at `api.py:185-201`). Rejects invalid/over-20-digit/over-cap `Content-Length` with 413 (`api.py:84-86`). Computes `has_body = (length is not None and int(length) > 0) or b"transfer-encoding" in headers` (`api.py:87`). If `has_body` and `scope["path"] in _ANON_BODY_PATHS`, lowers `cap = min(cap, _ANON_BODY_MAX)` (64 KiB) and rechecks `Content-Length` (`api.py:88-91`). Otherwise, if `has_body and self.authenticated and not await run_in_threadpool(self.authenticated, headers)`, rejects with 401 before reading any body (`api.py:92-95`). Streamed bodies remain capped at `cap` in `limited_receive` (`api.py:98-115`).
  - `api.py:185-199` `authenticated(headers)`: checks `Authorization: Bearer <token>` via `secrets.compare_digest` against `human_token` or `box.sandboxes.sandbox_for_token(token) is not None`, else parses `Cookie` with `http.cookies.SimpleCookie` and checks `box.desktop.session_scope(got.value)` for `D.COOKIE`. Route-level authorization (`human_only`, sandbox ownership, `same_origin`) still runs in route dependencies.
  - `config.py:68`: `max_connections` (`AGENTBOX_MAX_CONNECTIONS`, default 256; 0 disables); `cli.py:126-127` passes `limit_concurrency=s.max_connections` to `uvicorn.run`.
  - `deploy/Caddyfile:8-15`: `@upload path_regexp ^/sandboxes/[^/]+/files$` gets `AGENTBOX_PROXY_MAX_BODY` (256MB), `@other` gets `AGENTBOX_PROXY_MAX_JSON` (8MiB). `deploy/docker-compose.yml:20`: `mem_limit: ${AGENTBOX_MEM_LIMIT:-2g}`.
- **Desktop lock split and WebSocket threadpool offload (`desktop.py`, `desktop_ws.py`, `api.py`, PR #24 — run-5 F4 fix).**
  - `desktop.py:93-94`: `DesktopControl` splits `self._lock` (in-memory `_leases`, `_conns`, `_gui_locks`) from `self._db_lock` (SQLite `self._db`). Documented lock order when acquiring both: `_db_lock -> _lock`.
  - Ticket and session methods (`issue_ticket:116`, `redeem:124`, `start_session:139`, `end_session:147`, `session_scope:153`) take only `_db_lock`.
  - Lease and connection methods that touch both (`take:194`, `release:215`, `leftover_leases:235`, `forget_lease:246`, `close_all:299`) take `_db_lock` then `_lock`. In-memory-only methods (`lease`, `touch`, `is_stale`, `gui_lock`, `may_connect`, `add_conn`, `drop_conn`, `conns`, `end_session_conns`) take only `_lock`.
  - `api.py:441`: `desktop_ws` runs `await run_in_threadpool(box.desktop.session, cookie, sid)` before `same_origin(ws.headers)` (`api.py:442`, `same_origin` at `api.py:221-223`).
  - `desktop_ws.py:21-22`: `relay` runs `vnc_command` and `log_human("desktop_connect")` via `run_in_threadpool`. Periodic session recheck (`desktop_ws.py:76`) also uses `run_in_threadpool`. `finally` block (`desktop_ws.py:93-113`) runs `log_best_effort("desktop_disconnect")` on default executor inside `await asyncio.shield(logged)` before `box.desktop.drop_conn(conn)`.
- **GUI burst under takeover lease (`service.py`, PR #24 — run-5 F2 fix).**
  - `service.py:265-284` `_snapshot`: for `tool in GUI_INPUT`, after `sandboxes.snapshot`, acquires `with self._gui_locked(sid, "GUI 구간 열기"):`, runs `self._check_control(sid)`; only if no `HumanControl` is raised does it call `bursts.mark_snapshot(sid)` and `bursts.open(sid, snap["id"])`. Always appends the `snapshot` audit record (`service.py:280-281`), then if `human` was caught calls `self.bursts.reset_timers(sid)` and raises `human` (`service.py:282-284`).
  - `service.py:396-397`: `call_tool` catches `HumanControl` from `_snapshot` and delegates to `_human_blocked` (`service.py:411-419`, returns 423 and logs `tool_blocked`).
  - `service.py:498-514` `decide`: before `_snapshot`, if `tool in GUI_INPUT` and active lease or `_takeover_pending(sid)`, finishes approval as `FAILED` without taking a snapshot or opening a burst; also catches `HumanControl` from `_snapshot` (`service.py:511-514`).
- **Tool argument length cap, policy re-lex skip, and preview caps (`service.py`, `policy.py`, `preview.py`, `sandbox.py`, PR #24 — run-5 F1/F5/F6 fixes).**
  - `service.py:49`: `TOOL_ARG_MAX = 16 * 1024`. In `_call_tool` (`service.py:323-329`), before `tool_request` audit and `policy.decide`, rejects any arg `k != "content"` whose `len(v if isinstance(v, str) else json.dumps(v, default=str)) > TOOL_ARG_MAX` with 413 (`argument_too_long`).
  - `service.py:357-362`: in the `REQUIRE_APPROVAL` branch, applies `preview = bound_payload(preview)` before storing the pending approval row, and re-checks `if actor == "agent" and self.disk_low():` raising 507 before `_capture` and `approvals.create`.
  - `policy.py:27, 40-49, 73`: `_LEX_PUNCT = set(";&|()<>")`; `_relex_changes(t)` returns `False` for tokens consisting solely of `_LEX_PUNCT` or tokens with no whitespace, `_LEX_PUNCT`, quotes, or backslashes (e.g. `'x$'`), avoiding redundant recursive `_words(t, depth + 1)` calls.
  - `preview.py:70-71`: `PREVIEW_CALLS_MAX = 40`, `NOTES_MAX = 50`. `preview_command` (`preview.py:74-160`) deduplicates `rm` operands via `dict.fromkeys(operands)` (`:105`), caps total `expand`/`walk` calls at 40 via `budget()`, appends a Korean note when `skipped > 0` (`:154-156`), and truncates `notes` to `NOTES_MAX` plus a summary note (`:157-159`).
  - `sandbox.py:39, 104-106, 578-594`: `_PREVIEW_TIMEOUT = 10`; `_expand` and `_walk` wrap their container `sh -c` in `_timed(_PREVIEW_TIMEOUT, ...)` and call `_preview_ok(res)` (raises `SandboxError` on exit code 124 or 137).
- **Retention prune post-COMMIT archive safety (`retention.py`, PR #24 — run-5 F3 fix).**
  - `retention.py:104-108`: unlinks partial archive if `_write_archive` raises before the transaction.
  - `retention.py:131-145`: on exception inside the transaction block, rolls back only `if conn.in_transaction`; in the outer handler, queries `SELECT 1 FROM audit_anchor WHERE archive = ? AND archive_sha256 = ?` (defaulting `committed = True` on `sqlite3.Error`) and only unlinks the archive if `not committed`.
## 0.2 Run-5 delta (changes in PRs #16-#23, `346df29` line numbers)
- **Body cap (F1 fix, PR #16)**, **Audit cap (F3 fix, PR #16)**, **GUI gate (F2) and quota recheck (F7, PR #17)**, **Lifecycle lock (F6), F4 NUL-separated preview `_expand`/`_walk`, F5 single-flight `extract_novnc`, F8 login failure rate limit (PR #18)**, **Control-character filter `display.escape_controls` Cc/Cf/Zl/Zp (N5, PR #19)**, **Disk guard `disk_low` and finished-approval compaction (N2 stage 1, PR #20)**, **Host CLI `agentbox prune` and `audit_anchor` (N2 stage 2, PR #21)**, **Window owner via XRes `XResQueryClientIds` (N4, PR #22)**.
- **LLM-provider data path (PR #23)**: documented owner-accepted limitation; out of scope for hunting.
## 1. Product, principals, protected resources
agentbox is a self-hosted FastAPI + SQLite control plane. It gives AI agents Docker sandboxes, routes risky tool calls through a human approval queue, and keeps a hash-chained audit log. Desktop templates add Xvfb/Xfce/x11vnc/noVNC so a human can watch or take over the screen.
- **Human token** `hum_…` (one shared admin secret, `config.py`): full JSON API (`api.py` `principal`).
- **Browser cookie session**, scope `*` (login form or one-time `*` ticket): full UI. Sessions and tickets carry a `gen` fingerprint of the human token, so rotation revokes them (`desktop.py`).
- **Desktop-link session**, scope = one sandbox id: only that sandbox's desktop page/state/takeover/handback/WS (`api.py` `desktop_human`).
- **Agent token** `agt_…` per sandbox (hash stored): tools on its own sandbox, read own sandbox/approval/desktop state. Lowest-trust network principal; the threat model assumes a prompt-injected agent.
- **Code inside the sandbox**: uid 1000 `agent` (exec, file tools) and uid 1001 `desktop` (X session, GUI tools, x11vnc; in the agent group). Every container output (exec stdout, `ps`, `xdotool`, `find -printf` manifest, outbox listing, `ls`, preview `_expand`/`_walk`, screenshot bytes, RFB stream) is attacker data to the control plane.
- **Unauthenticated network clients**: `/`, `/login` (GET/POST; failed POST writes an audit row), `/static/htmx.min.js`, `/static/novnc/*` (`api.py`, may create a container via `extract_novnc`), `/healthz`, ticket redemption, FastAPI `/docs`.
- **MCP stdio server / `agent.py` loop**: hold an agent token; trust the local launcher.
Protected resources: the human token and approval authority; host filesystem and Docker daemon (the control plane holds `docker.sock` = host root); other sandboxes; `/workspace` restore points (snapshots before destructive actions and per GUI burst); audit-log integrity and secret masking; control-plane availability (thread pools, memory, SQLite, host disk via `docker commit`).
## 2. Comparable baseline
No source-grounded comparable product. Components: MCP (FastMCP/MCPServer stdio), RFB via x11vnc `-inetd` + socat + noVNC, gVisor/Kata named as preferred runtimes. A runc sandbox shares the host kernel.
## 3. Stack, deployment, offline limits
Python ≥3.11; fastapi, uvicorn, websockets, jinja2, docker SDK, pyyaml, mcp. Modes: `agentbox serve` (127.0.0.1 default; `bind_problem` and `runtime_problem` gates; `runtime_problem` rejects only the literal `"runc"`), compose + Caddy with `--behind-tls-proxy` and `forwarded_allow_ips="*"` by default, and the bare `create_app` factory (`api.py`) that skips the serve-time gates. Container flags (`sandbox.py`): `network_mode=none`, non-recursive read-only `/source` bind, `cap_drop ALL` + CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID, no-new-privileges, mem/cpu/pids limits, no userns, default seccomp. The desktop start script resets `/home/desktop` on every start and restore (v19 fix).
Host for this run: Windows 11 with Docker Desktop WSL2 Linux engine 29.9.2, runtimes `runc`/`io.containerd.runc.v2`, images `ubuntu:24.04`, `buildpack-deps:noble-curl`, `agentbox-desktop:0.1`, `agentbox-audit-sbx:1`. Agent-run code goes through `tools/sbx.py` (no network, read-only target at `/target`, writable `/scratch`, uid 65534, 512 MiB, 64 pids, 120 s). Docker-free tests: `tests/test_unit.py`, `test_m2_unit.py`, `test_m4_unit.py`, `test_m5_unit.py`, `test_retention.py`. Anything needing the real daemon is a parent-live check.
## 4. Entry surfaces and important paths
- **Tools**: `POST /sandboxes/{sid}/tools/{tool}` → `AgentBox.call_tool` (per-sandbox concurrency 4, `_snap_locks`) → `_call_tool` (16 KiB arg cap `TOOL_ARG_MAX` → audit with capped args `_logged_args` → `policy.decide` → quota → approval with bounded preview & `disk_low` recheck or `_snapshot` → `_run_tool`) on the 32-thread `tool_pool`. Pending approvals capped at 20.
- **Approvals**: `POST /approvals/{aid}` / `POST /ui/approvals/...` (human) → `decide`: atomic claim, GUI lease check, snapshot, run stored args. Preview (`preview.py` `preview_command` with `_expand`/`_walk` callbacks, 40-call budget, 10 s timeout per call) and capture run before the approval exists.
- **Lifecycle**: `pause_sandbox/resume_sandbox/snapshot_sandbox/restore_sandbox/delete_sandbox` serialized per san

# Relevant companion blocks (verbatim)

<!-- AI-AND-LLM.md#Action-confirmation and approval binding -->
**Action-confirmation and approval binding**
A user approves one described action but execution can use changed arguments, a different resource, a different principal, or a later model turn. An action-binding defect also exists when attacker-controlled content causes a side effect under a victim's valid authority without the victim's intentional request or approval, even if generic authorization permits the victim to perform it. Review whether intent or confirmation binds the normalized tool name, complete argument object, requester, target, amount, expiry, and batch membership. Check retries and resumed sessions: an approval must not authorize a mutated or duplicate side effect.

# Verifier instructions (verbatim)

```text
You did not write this candidate. Try to refute it from repository source and bounded
local evidence. Do not contact deployed endpoints or external/shared services. Run
target-controlled code only inside the approved OS-enforced sandbox: no external
network, empty allowlisted environment, read-only target and tools, scratch-only
writes, and explicit low resource and wall-clock limits. If any control is unavailable,
do not execute; retain the exact missing capability as a needs_validation blocker.
Treat every scratch entry as target-controlled after execution. After the sandbox and
all its processes terminate, only trusted parent-side code may promote a predeclared
scratch-relative file, following the promotion procedure block included verbatim in
this prompt. You and target code never write retained artifacts. If promotion is
unavailable or fails, do not use that file as evidence.

1. Verify every trace and evidence file, positive line number, scope, and description.
   Confirm the first entry is a real lower-trust entrypoint and the last is the
   claimed sink or boundary effect.
2. Reconstruct the strongest source-visible validation, identity, authorization,
   normalization, lifecycle, framework, and containment controls on the path.
   Where the architecture summary names a comparable baseline, note whether it
   shares the pattern — as calibration, never as grounds to dismiss.
3. For a proposed confirmed candidate, independently reproduce the minimum observed
   result when possible. Verify inputs, interface shape, conditions, and affected
   dummy principal/resource. Do not infer a stronger result or continue after it.
4. Verify that likelihood, impact, confidence, and the proposed source fix match only
   what the evidence establishes.
5. For a proposed needs_validation candidate, decide whether the blocker is genuinely
   outside source/local observation. If source refutes the trace, reject it. If the
   missing fact remains decisive, keep needs_validation and make the local and
   owner-observed plans exact and non-destructive.
6. Preserve the fingerprint for the same source-derived root cause across every state.

Return exactly one JSON object and no surrounding prose:
{"decision": "confirmed|needs_validation|rejected", "record": { ... }}
where record exactly matches the decision's verdict branch of the schema included
in this prompt. A corrected record replaces the hunter's wording.
```

# Artifact promotion procedure (verbatim)

```text
Artifact promotion procedure (trusted parent-side code only):
Reference only for you: the parent performs these steps; you never perform them.

Before execution, the parent opens and retains trusted, non-inheritable directory
descriptors for the agent's scratch/ and artifacts/ roots, and records an allowlist
of expected scratch-relative artifact files plus explicit per-file and cumulative
byte limits. Never pass those descriptors to the agent or sandbox. After the sandbox
and all its processes terminate, trusted parent-side code promotes each allowlisted
file separately:

1. Validate the declared relative path: reject absolute, empty, `.`, `..`, or
   symlinked components.
2. Walk each parent component from the retained scratch-root descriptor with
   no-follow directory-relative operations; never reopen by path.
3. Open the leaf no-follow and nonblocking.
4. Verify with `fstat` that it is a regular file with link count exactly one and
   within the recorded per-file and cumulative byte limits.
5. Enforce those limits again while reading from that descriptor.
6. Copy exactly the verified size, repeat `fstat`, and reject a changed identity,
   type, link count, or size.
7. For the destination, walk every parent component from the retained
   artifacts-root descriptor with no-follow directory-relative operations; require
   each existing component to be a real directory, and create any missing directory
   exclusively before reopening and verifying it no-follow.
8. Create the leaf exclusively without following links, verify that the opened
   destination is a regular file with link count exactly one, and copy from the
   verified source descriptor without reopening either path.
9. Use equivalent race-safe APIs on non-POSIX systems.
10. Never recursively copy or glob scratch, extract an archive into artifacts, or
    open or promote a symlink, FIFO, socket, device, directory, hard-linked file,
    changing file, or file that exceeds its bound.
11. If any check is unavailable, cannot be enforced, or fails, discard the scratch
    entry; if it is decisive evidence, retain `needs_validation` with the exact
    promotion blocker.
```

# Execution boundary and paths

- Agent ID `v-preview`. Write ONLY in `<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/agents/v-preview/scratch/`. Never edit target files, the ledger, findings, architecture or another agent's directory.
- Run target-controlled code only through `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-preview <cmd...>`. Inside: the audited source is /target (read-only, on PYTHONPATH), your scratch is /scratch (cwd, writable), there is no network and no Docker socket, uid 65534, 512 MiB, 1 CPU, 64 pids, 32 MiB files, 120 s wall clock, empty allowlisted environment. Use `/usr/bin/python3` (fastapi, docker SDK, httpx, jinja2, pyyaml, mcp, pyte, pytest importable).
- Unit tests need cwd=/target: `python "<WINDOWS_HOST_ROOT>/projects/agentbox/docs/security-audit/run-6/tools/sbx.py" v-preview /usr/bin/sh -c "cd /target && /usr/bin/python3 -m pytest -p no:cacheprovider --capture=sys -q tests/test_m5_unit.py"`.
- A fact that needs the real Docker-backed control plane, the desktop image at runtime, or a deployment the audit does not own stays a `needs_validation` blocker with an exact plan unless resolved by parent-live evidence above. Do not contact deployed endpoints.
- If you produce a local artifact, list it in a top-level `"artifacts_to_promote": [...]` field beside `decision` and `record` (scratch-relative, <=256 KiB each, 1 MiB total). The parent promotes it after you finish; cite it in `record.evidence` as `agents/v-preview/artifacts/<file>`.
- Your final message must be ONLY the JSON object `{"decision": ..., "record": {...}}` plus that optional field. No prose, no code fence.

# report-schema.json branches (verbatim)

## `confirmed`

```json
{
 "type": "object",
 "description": "A source-grounded vulnerability that was independently demonstrated.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "confirmed"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
   "description": "A stable source-derived identifier that does not change between validation states."
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "intended_behavior": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "conditions": {
   "type": "array",
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "authentication_level",
       "authorization_role",
       "user_interaction",
       "system_configuration",
       "network_routing",
       "environmental_dependency",
       "data_state",
       "timing_dependency",
       "third_party_dependency"
      ]
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "execution": {
   "type": "object",
   "description": "Target-neutral reproduction in the target's native interface.",
   "properties": {
    "attacker_perspective": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "payloads": {
     "type": "array",
     "minItems": 1,
     "uniqueItems": true,
     "items": {
      "type": "string"
     }
    },
    "instructions": {
     "type": "array",
     "minItems": 1,
     "items": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "observed_result": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "attacker_perspective",
    "payloads",
    "instructions",
    "observed_result"
   ],
   "additionalProperties": false
  },
  "remediation": {
   "type": "object",
   "properties": {
    "strategy": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "code_changes": {
     "type": "array",
     "items": {
      "type": "object",
      "properties": {
       "file_name": {
        "type": "string",
        "minLength": 1
       },
       "fixed_code": {
        "type": "string"
       }
      },
      "required": [
       "file_name",
       "fixed_code"
      ],
      "additionalProperties": false
     }
    }
   },
   "required": [
    "strategy"
   ],
   "additionalProperties": false
  },
  "severity": {
   "type": "object",
   "properties": {
    "likelihood": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "impact": {
     "type": "object",
     "properties": {
      "score": {
       "type": "string",
       "enum": [
        "informational",
        "low",
        "medium",
        "high",
        "critical"
       ]
      },
      "reason": {
       "type": "string",
       "minLength": 1,
       "visibleContent": true
      }
     },
     "required": [
      "score",
      "reason"
     ],
     "additionalProperties": false
    },
    "overall_severity": {
     "type": "string",
     "enum": [
      "informational",
      "low",
      "medium",
      "high",
      "critical"
     ]
    }
   },
   "required": [
    "likelihood",
    "impact",
    "overall_severity"
   ],
   "additionalProperties": false
  },
  "confidence": {
   "type": "object",
   "properties": {
    "score": {
     "type": "string",
     "enum": [
      "low",
      "medium",
      "high"
     ]
    },
    "reason": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "required": [
    "score",
    "reason"
   ],
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "root_cause",
  "intended_behavior",
  "trace",
  "evidence",
  "conditions",
  "execution",
  "remediation",
  "severity",
  "confidence"
 ],
 "additionalProperties": false
}
```

## `needs_validation`

```json
{
 "type": "object",
 "description": "A source-grounded candidate whose decisive validation is blocked.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "needs_validation"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$"
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "claimed_root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "blockers": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "string",
    "minLength": 1,
    "visibleContent": true
   }
  },
  "validation_plan": {
   "type": "object",
   "properties": {
    "local": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    },
    "deployment": {
     "type": "string",
     "minLength": 1,
     "visibleContent": true
    }
   },
   "additionalProperties": false
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "claimed_root_cause",
  "trace",
  "evidence",
  "blockers",
  "validation_plan"
 ],
 "additionalProperties": false
}
```

## `rejected`

```json
{
 "type": "object",
 "description": "A source-grounded candidate refuted during validation.",
 "properties": {
  "verdict": {
   "type": "string",
   "const": "rejected"
  },
  "fingerprint": {
   "type": "string",
   "minLength": 1,
   "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$"
  },
  "title": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "description": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "claimed_root_cause": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  },
  "trace": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "kind": {
      "type": "string",
      "enum": [
       "entrypoint",
       "propagation",
       "sink"
      ]
     },
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "scope": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "kind",
     "file",
     "line",
     "scope",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "evidence": {
   "type": "array",
   "minItems": 1,
   "uniqueItems": true,
   "items": {
    "type": "object",
    "properties": {
     "file": {
      "type": "string",
      "minLength": 1
     },
     "line": {
      "type": "integer",
      "minimum": 1
     },
     "description": {
      "type": "string",
      "minLength": 1,
      "visibleContent": true
     }
    },
    "required": [
     "file",
     "line",
     "description"
    ],
    "additionalProperties": false
   }
  },
  "reason": {
   "type": "string",
   "minLength": 1,
   "visibleContent": true
  }
 },
 "required": [
  "verdict",
  "fingerprint",
  "title",
  "description",
  "claimed_root_cause",
  "trace",
  "evidence",
  "reason"
 ],
 "additionalProperties": false
}
```
