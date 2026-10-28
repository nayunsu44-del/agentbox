# run-7 확정 상세

`findings.json`의 확정(`confirmed`) 레코드를 한국어로 옮긴 문서다. 판정, 심각도, 근거는 JSON과 같으며, 항목마다 아래에 영어 레코드 원문(기준)을 접어 두었다. 줄 번호는 감사 기준 `3580df0`을 따른다. 보고 전용이며 수정은 소유자가 정한다.

## F1. [중간] 지시 파일 쓰기 승인 카드가 에이전트가 정한 크기의 내용 전체를 상한 없이 2초마다 다시 그린다

- 지문: `agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll`
- 심각도: 가능성 높음 · 영향 중간 · 종합 **중간**. 신뢰도: high
- 경로: `agentbox/service.py:359`(진입점), `agentbox/service.py:433`(전파), `agentbox/web.py:251`(전파), `agentbox/web.py:148`(전파), `agentbox/templates/_approvals.html:13`(도달점)

**설명.** 에이전트는 샌드박스마다 지시 파일 쓰기 승인 대기를 20개(`PENDING_APPROVALS_MAX`)까지 만들 수 있다. 대기 행은 쓸 내용(`content`)을 그대로 담는다. `content`는 16KiB 인자 상한(`TOOL_ARG_MAX`)에서 빠지고, `max_write_bytes`(1MiB)는 승인 뒤 실제로 쓸 때만 확인한다. 그래서 카드 하나의 내용은 JSON 본문 상한 8MiB까지 커질 수 있다. `_approvals.html:13`은 단발 F1 수정에 따라 이 내용을 자르지 않고 `<pre>`에 모두 찍는다. `_shown`(`escape_controls`)은 U+0001 같은 제어 문자를 `\x01` 네 글자로 바꿔 크기를 늘린다. `web.render`는 204를 돌려줄 때도 본문을 다 만들고 sha256을 계산한다. 첫 화면(`index.html:25`, 모든 샌드박스)과 샌드박스 화면(`sandbox.html:25`)은 이 조각을 2초마다 다시 받는다.

**근본 원인.** 폴링되는 승인 조각에 카드별·조각 전체의 렌더링 크기 상한이 없다. 대기 승인을 만들 때 쓸 내용의 크기를 확인하지 않는다. 바뀌었는지(204) 판단은 본문을 다 만든 뒤에야 한다.

**지켜야 할 동작.** 2초마다 받는 승인 조각 한 번의 CPU와 응답 크기는 묶여 있어야 한다. 에이전트가 정한 대기 내용 때문에 요청 한 번이 수 초·수십 MiB가 되어서는 안 되며, 사람은 그 요청을 계속 보고 거절할 수 있어야 한다.

**재현 관측.**

- parent-live(실제 dockerd·샌드박스·API): `d{i}/CLAUDE.md`에 1MiB U+0001 내용을 쓰는 `write_file`을 보내 20번 모두 202를 받았다(21번째는 429). 그 뒤 `GET /ui/approvals` 한 번이 **83,920,462바이트, 13.69~13.91초**였고 샌드박스별 조각도 같았다(`agents/parent-live/artifacts/approvals_render_live.out`).
- 3단계 검증자 샌드박스(실제 템플릿·필터): 20 × 1MiB U+0001은 10.846초·80.0MiB, 같은 크기의 일반 ASCII는 0.131초·20.0MiB(`agents/v-approvals-render/artifacts/v_render.out`).
- 5단계 검증자: 앞부분 4KiB만 그리는 수정안을 넣으면 10.127초·83,909,102바이트가 0.040초·352,582바이트로 줄었다(`agents/r-approvals-render/artifacts/fixcheck.out`).

**성립 조건.** 인증 수준, 사용자 상호작용, 데이터 상태, 시스템 설정. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** 폴링 조각에는 내용 앞부분(예: 4KiB)·전체 길이·sha256만 보이고, 폴링하지 않는 별도 페이지(`/ui/approvals/{id}/content`, `_shown`과 같은 처리)에서 전체 내용을 보게 한다. 조각 전체의 렌더링 크기도 묶는다. 대기 승인을 만들기 전에 `max_write_bytes`를 확인한다. 204 판단은 승인 id·상태로 한다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** A prompt-injected sandbox agent holding its own agent token can queue PENDING_APPROVALS_MAX=20 pending write_file approvals per sandbox to instruction-file paths (default rule instruction-file-write-needs-approval). Each pending row stores the agent's full 'content', which is exempt from TOOL_ARG_MAX. _approvals.html renders every pending instruction-file card's content in full through autoescape plus _shown. escape_controls turns each control or format character (Unicode Cc, Cf, Zl or Zp other than newline and tab) into a visible escape, e.g. U+0001 into the 4-character \x01. There is no truncation and no aggregate cap. web.render materialises and SHA-256-hashes the whole body on every request, including ones that end in 204, and index.html and sandbox.html both poll the fragment every 2 s; the index fragment aggregates the pending set of all sandboxes. Parent-live evidence against the real API: 20 write_file calls returned 202 (the 21st 429), and each GET /ui/approvals returned 83,920,462 bytes in about 13.7 s. Independent sandboxed reproduction with the real template and filters: 20 x 1 MiB U+0001 cards took 10.85 s to render and hash and produced an 80.0 MiB body, against 0.13 s / 20.0 MiB for printable ASCII. The human approval view becomes unusable while the attacker's writes are pending, and each poll ties up a control-plane worker for seconds of CPU.

**root_cause** _approvals.html:13 outputs a.args.content in full with no length bound. _shown/escape_controls expands each Cc/Cf/Zl/Zp character (other than newline and tab) into a \xNN (4x), \uNNNN or \UNNNNNNNN escape. Neither the card nor the fragment has a rendered-size cap. web.render (web.py:147-148) always builds and hashes the full body before deciding on a 204. Content size is not checked when the approval is created: ToolCall.args (api.py:55-56) is an unconstrained dict, service.py:359-360 exempts 'content' from TOOL_ARG_MAX, approvals.create stores the full args, and the max_write_bytes=1 MiB check only runs when the approved write executes (sandbox.py:507). A pending card's content is therefore bounded only by the 8 MiB JSON body limit (config.py:65). For U+0001, which strict JSON must carry as the 6-byte \u0001, that is about 1.4M characters per card, so the 1 MiB-per-card figure used in the measurements is a conservative lower bound.

**intended_behavior** The approvals fragment, polled every 2 s from the index and sandbox pages, should cap the CPU and bytes each poll costs, so that pending content chosen by an agent cannot make a poll cost seconds of control-plane CPU or tens of MiB of response, and the human can still review and deny the request.

**trace**

- `agentbox/service.py:359` (entrypoint, AgentBox._call_tool argument-length gate) — The agent's write_file call enters here. The TOOL_ARG_MAX comprehension skips the 'content' key, so content of any size passes. Nothing checks max_write_bytes before the approval is created.
- `agentbox/service.py:433` (propagation, AgentBox._request_approval) — approvals.create stores the full args (including 1 MiB content); up to PENDING_APPROVALS_MAX=20 rows can be pending per sandbox.
- `agentbox/web.py:251` (propagation, approvals_view) — Lists every pending approval; with sandbox_id=None (the index poll) it aggregates all sandboxes into one fragment.
- `agentbox/web.py:148` (propagation, render()) — Builds the entire response body and hashes it on every request, even when it returns 204.
- `agentbox/templates/_approvals.html:13` (sink, pending instruction-file card) — <pre>{{ a.args.content }}</pre> renders the full content through _shown; no truncation or aggregate cap.

**conditions**

- authentication_level: Attacker holds a per-sandbox agent token (the assumed prompt-injected agent).
- user_interaction: A human has an approvals view open; the index and sandbox pages poll /ui/approvals every 2 s automatically.
- data_state: Up to 20 pending instruction-file write approvals per sandbox, each carrying large content made of control or format characters (e.g. U+0001); approvals expire after approval_timeout (default 300 s) and the agent can queue them again.
- system_configuration: Default configuration: default_policy.yaml v4, PENDING_APPROVALS_MAX 20, max_body_bytes 8 MiB.

**execution.attacker_perspective** As the sandbox agent, fill the per-sandbox pending queue with maximum-size instruction-file writes; every human poll of the approvals view then re-renders them.

**execution.instructions**

1. In the sandbox, build a Jinja2 environment for agentbox/templates with autoescape on, finalize=agentbox.web._shown, and filters oneline/short as in web.register.
2. Construct 20 pending-approval dicts with tool='write_file', preview.instruction_file set, and args.content = '\x01' * (1024*1024).
3. Render _approvals.html once and record render time and body size.

**execution.observed_result** Rendering and hashing 20 x 1 MiB U+0001 cards took 10.846 s and produced an 80.0 MiB body; printable ASCII took 0.131 s for 20.0 MiB. The parent-live run against the real API measured 83,920,462 bytes in about 13.7 s per GET /ui/approvals.

**remediation.strategy** In the polled fragment, show only a capped prefix of instruction-file content, with total length, a digest, and a link to a separate non-polled page that shows the full content (escaped like _shown) for the approval under review, so the human can still review all of it before approving. Cap the total rendered bytes per fragment. Reject or bound write_file content at max_write_bytes before creating an approval; on its own this still allows about 4 MiB rendered per card, so the template cap is the main fix. Base the 204 version on approval ids and statuses, not on a hash of the rendered body.

`agentbox/templates/_approvals.html`:

```python
<pre class="instruction-content" style="max-height:480px">{{ a.args.content[:4096] }}{% if a.args.content | length > 4096 %}
…({{ a.args.content | length - 4096 }}자 더)
{% endif %}</pre><a href="/ui/approvals/{{ a.id }}/content" target="_blank">전체 내용 보기</a>
```

`agentbox/web.py`:

```python
# import: from fastapi.responses import PlainTextResponse
    @app.get("/ui/approvals/{aid}/content", include_in_schema=False)
    def approval_content(request: Request, aid: str, p=Depends(browser_human)):
        # 주기적으로 다시 받지 않는 페이지. 지시 파일 쓰기 내용 전체를 _shown과 같은 방식으로 보여 준다
        a = box.approvals.get(aid)
        content = (a or {}).get("args", {}).get("content")
        if not a or a["tool"] != "write_file" or not isinstance(content, str):
            raise HTTPException(404, "승인 요청 없음")
        return PlainTextResponse(escape_controls(content, keep_newlines=True),
                                 headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
```

`agentbox/service.py`:

```python
        # in _call_tool, right after the TOOL_ARG_MAX check and before tool_request is logged
        if tool == "write_file" and len(str(args.get("content", "")).encode("utf-8")) > self.sandboxes.settings.max_write_bytes:
            raise ServiceError(413, f"쓸 내용이 너무 큼 (최대 {self.sandboxes.settings.max_write_bytes} bytes)")
```

</details>

## F2. [낮음] 지시 폴더를 가리키는 링크 자체에 write_file을 하면 승인 없이 지시 폴더 안에 쓴다 (kind()가 끝 조각을 지시 폴더로 보지 않음)

- 지문: `agentbox/instruction_files.py:kind:instruction-dir-as-final-component-unmatched-so-write-into-linked-dir-skips-approval`
- 심각도: 가능성 중간 · 영향 낮음 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/service.py:369`(진입점), `agentbox/service.py:235`(전파), `agentbox/policy.py:226`(전파), `agentbox/instruction_files.py:103`(전파), `agentbox/sandbox.py:511`(도달점)

**설명.** 원본 폴더에 `cfg -> .claude` 같은 링크가 있을 때 에이전트가 `write_file('/workspace/cfg', 내용)`을 부르면, `resolve()`는 `/workspace/.claude`를 돌려준다. 그런데 `kind()`는 지시 폴더 이름(`_DIRS`, `.github/instructions` 등)을 경로의 마지막이 아닌 조각에서만 찾는다(`parts[:-1]`). 그래서 `kind('/workspace/cfg')`와 `kind('/workspace/.claude')`가 모두 None이 되고, 지시 파일 쓰기 규칙이 맞지 않아 `default: allow`로 실행된다. `write_file`의 `mv -f -- tmp cfg`는 디렉터리 링크를 따라가 임시 파일을 `.claude/` 안으로 옮긴다(`.claude/cfg.agentbox-tmp-<hex>`). 도구 결과에는 경로가 `/workspace/cfg`로 남는다. `gh -> .github/instructions`도 같다. `delete_file`은 모든 삭제를 승인으로 보내는 규칙이 있어 해당하지 않는다.

**근본 원인.** `kind()`는 마지막 조각을 지시 폴더로 검사하지 않는다. `scan()`은 `kind(rel + '/_')`로 이를 피하지만 정책과 미리보기는 경로를 그대로 넘긴다. 그래서 실제 대상이 지시 폴더 자체인 쓰기를 지시 파일이 아닌 것으로 판단하는데, `mv -f`는 실행할 때 그 링크를 따라가 폴더 안에 쓴다.

**지켜야 할 동작.** 실제 대상이 지시 폴더이거나 그 안인 에이전트 쓰기는, 한 단계 더 들어간 경로에 쓸 때와 똑같이 사람 승인을 받아야 한다.

**재현 관측.**

- parent-live(실제 API·컨테이너): `write_file /workspace/cfg`가 맞은 규칙 없이 200 executed였고 `/workspace/.claude/cfg.agentbox-tmp-74833b`가 생겼다. 대조로 보낸 `cfg/settings.json`은 202 승인 대기였다(`agents/parent-live/artifacts/recon_leads_live.out`).
- 헌터·3단계 검증자 샌드박스: `decide('write_file', {path: cfg, resolved_path: /workspace/.claude})`는 allow, `.github/instructions`도 allow. 한 단계 더 깊은 경로와 `CLAUDE.md`는 승인. `delete_file`은 모두 승인(`agents/v-if-dirlink/artifacts/repro.out`).
- 들어간 파일 이름이 `cfg.agentbox-tmp-<hex>`로 정해져 있어, 다른 에이전트가 이름으로 자동으로 읽는 파일은 아니다. 그래서 영향은 낮음이다.

**성립 조건.** 데이터 상태, 권한, 사용자 상호작용. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** 정책과 미리보기에서 요청 경로와 `resolved_path` 둘 다 `kind(x) or kind(x.rstrip('/') + '/_')`로 본다(`scan()`과 같은 방식). 이름과 폴더 형태를 함께 보는 함수 하나를 두면 이런 불일치가 다시 생기지 않는다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The instruction-file write-approval gate judges the requested path and the single `realpath -m` resolved path with `instruction_files.kind()`. `kind()` only matches a `_DIRS` / `.github` instruction directory when it appears as a non-final path part (`parts[:-1]`); a path whose final component is itself the instruction directory returns None. A source folder (attacker data) can contain a symlink such as `cfg -> .claude`. A prompt-injected agent calling `write_file('/workspace/cfg', <content>)` has `resolve()` return `/workspace/.claude`; both `kind('/workspace/cfg')` and `kind('/workspace/.claude')` are None, so `Policy.decide` matches no instruction rule and falls through `default: allow`. `_call_tool` then executes `write_file`, whose `mv -f -- /workspace/cfg.agentbox-tmp-<hex> /workspace/cfg` resolves the symlink target directory and deposits the attacker content inside `/workspace/.claude/` (as `cfg.agentbox-tmp-<hex>`) with no human approval card ever shown. `.github/instructions` as a final-component symlink target is the same bypass. delete_file is unaffected because a catch-all `delete-file-needs-approval` rule gates every delete. Independently reproduced in the approved sandbox.

**root_cause** instruction_files.kind() classifies a directory only by inspecting parts[:-1] against _DIRS/_GITHUB_DIRS and never tests the final component as a directory (scan() works around this by probing kind(rel + '/_'), but _resolved/_policy_args/_preview and Policy.decide pass the bare resolved path). A write whose resolved target is exactly an instruction directory is therefore judged as a non-instruction path and allowed, while write_file's `mv -f` follows the directory symlink at execution time and lands inside that instruction directory.

**intended_behavior** An agent-caused write whose final on-disk target is inside (or is) an instruction directory must be routed to human approval, the same as a write that resolves one level deeper into the directory.

**trace**

- `agentbox/service.py:369` (entrypoint, AgentBox._call_tool) — policy.decide(tool, self._policy_args(sid, tool, args)) is the sole write-approval gate; its ALLOW result leads straight to _run_tool.
- `agentbox/service.py:235` (propagation, AgentBox._resolved / _policy_args) — For write_file, resolve(sid, '/workspace/cfg') returns the symlink target '/workspace/.claude', added as resolved_path.
- `agentbox/policy.py:226` (propagation, Policy.decide match.instruction_files) — Hit is computed as kind(args['path']) or kind(args['resolved_path']); both are None for a bare instruction dir, so the instruction-file rule is skipped and evaluation falls through to default: allow.
- `agentbox/instruction_files.py:103` (propagation, instruction_files.kind) — Loop runs over parts[:-1] only, so '.claude'/'.github/instructions' as the final path part is never matched against _DIRS/_GITHUB_DIRS; returns None.
- `agentbox/sandbox.py:511` (sink, SandboxManager.write_file) — c.exec_run(['mv','-f','--', tmp, p]) with p='/workspace/cfg' a symlink to a directory moves the temp file into /workspace/.claude/, an unapproved write inside an instruction directory.

**conditions**

- data_state: The untrusted source folder (attacker data) contains a symlink whose name is an ordinary word and whose target is an instruction directory, e.g. `cfg -> .claude` or `gh -> .github/instructions`, present in /workspace after create_sandbox.
- authorization_role: Lowest-trust agent token (agt_...) for the sandbox; the threat model assumes the agent is prompt-injected.
- user_interaction: No human approval occurs; the bypass removes the approval card that the instruction-file write rule is meant to show.

**execution.attacker_perspective** A prompt-injected sandbox agent that wants to drop content into an instruction directory the recipient's other agents treat as config, without the human seeing an approval card.

**execution.instructions**

1. Build Policy from agentbox/default_policy.yaml and call decide('write_file', {'path':'/workspace/cfg','resolved_path':'/workspace/.claude'}); observe action 'allow' with rule_id None, versus 'require_approval'/'instruction-file-write-needs-approval' when resolved_path is '/workspace/.claude/commands/x' or path is '/workspace/CLAUDE.md'.
2. Confirm instruction_files.kind('/workspace/.claude') and kind('/workspace/.github/instructions') are None while kind('/workspace/.claude/settings.json') is 'Claude Code'.
3. Create a directory .claude, a symlink cfg -> .claude, a file cfg.agentbox-tmp-74833b, and run `mv -f -- cfg.agentbox-tmp-74833b cfg`; observe the file now at .claude/cfg.agentbox-tmp-74833b.
4. Confirm decide('delete_file', {...}) returns require_approval in all cases (catch-all rule).

**execution.observed_result** In the approved sandbox: write cfg (resolved=/workspace/.claude) -> ('allow', None); write gh (resolved=/workspace/.github/instructions) -> ('allow', None); write cmds (resolved=.claude/commands/x) -> require_approval; write CLAUDE.md -> require_approval; delete cfg and delete foo -> require_approval; real `mv -f -- cfg.agentbox-tmp-74833b cfg` produced .claude/cfg.agentbox-tmp-74833b.

**remediation.strategy** Classify a path as an instruction target when its final component is itself an instruction directory. Where the write/delete target is resolved for policy and preview, also test the directory form, mirroring scan()'s `kind(rel + '/_')` probe, for both the requested path and resolved_path.

`agentbox/policy.py`:

```python
                hit = next((x for x in (args.get("path"), args.get("resolved_path"))
                            if isinstance(x, str) and (instruction_files.kind(x) or instruction_files.kind(x.rstrip('/') + "/_"))), None)
```

`agentbox/service.py`:

```python
            real = self._resolved(sid, tool, args)
            def _k(x):
                return x and (IF.kind(x) or IF.kind(x.rstrip('/') + "/_"))
            k = _k(p) or _k(real)
```

</details>

## F3. [낮음] resolve() 실패를 일부러 일으키면 지시 파일 쓰기가 요청 경로로만 판정되어 승인 없이 .claude/settings.json을 덮어쓴다

- 지문: `agentbox/service.py:_resolved:resolve-failure-fails-open-to-requested-path-skips-instruction-file-approval`
- 심각도: 가능성 낮음 · 영향 중간 · 종합 **낮음**. 신뢰도: high
- 경로: `agentbox/service.py:369`(진입점), `agentbox/service.py:246`(전파), `agentbox/service.py:251`(전파), `agentbox/policy.py:225`(전파), `agentbox/sandbox.py:511`(도달점)

**설명.** 단발 F2 수정(a0a186c)은 `cfg -> .claude` 링크를 거친 `cfg/settings.json` 쓰기를 컨테이너 안 `realpath -m`(`SandboxManager.resolve`)으로 푼 `resolved_path`로 잡는다. 그런데 `AgentBox._resolved`는 `resolve()`의 모든 예외를 None으로 바꾸고, `_policy_args`는 그때 `resolved_path`를 빼고 넘긴다. 그러면 정책은 요청 경로 `cfg/settings.json`(`kind()`가 None)만 보고 기본값 allow로 판정한다. 이어서 `write_file`의 `mv -f`가 링크를 따라가 `/workspace/.claude/settings.json`에 쓴다. 에이전트는 승인 없이 도는 허용 목록 exec(`tail -f /dev/null &`를 약 55개)로 컨테이너 pid 상한을 채워 `resolve()`를 실패시키고, 같은 때 보낸 `write_file`이 성공하게 할 수 있다.

**근본 원인.** `_resolved`(`service.py:235-247`)가 링크를 풀지 못한 경우를 '판단할 수 없음'이 아니라 '링크 없음'처럼 다룬다(fail-open). 코드 주석은 풀 수 없는 경로면 쓰기도 실패한다고 가정하는데, 링크 루프에는 맞지만 일부러 일으킨 일시적 실패에는 맞지 않는다.

**지켜야 할 동작.** `write_file`·`delete_file` 대상의 링크를 컨테이너 안에서 풀지 못했으면, 지시 파일 판정은 승인(또는 거부)으로 닫혀야 한다. 요청 경로만으로 판단해서는 안 된다.

**재현 관측.**

- parent-live(실제 dockerd·샌드박스, `AGENTBOX_PIDS=64`, `AGENTBOX_EXEC_TIMEOUT=8`): 백그라운드 `tail` 55개를 띄운 exec(read-only-exec 허용) 중에 보낸 `write_file /workspace/cfg/settings.json` 3번 중 1번이 200 executed(`('allow', None)`)였다. `/workspace/.claude/settings.json` 내용이 `INJECTED n=55 i=0`로 바뀌었고, 나머지 2번은 승인 대기였다. 58개 이상에서는 쓰기도 모두 실패(126)했다(`agents/parent-live/artifacts/resolve_failopen_live.out`).
- 헌터·3단계 검증자 샌드박스: 실제 `_resolved`·`_policy_args`·기본 정책으로 `resolve()`가 성공하면 승인, 예외를 내면 allow(`rule_id` None)였다(`agents/v-resolve-failopen/artifacts/repro.out`).
- pid 상한을 맞춰야 해서 성공 구간이 좁다. 그래서 가능성은 낮음으로 보았다.

**성립 조건.** 인증 수준, 데이터 상태, 타이밍, 사용자 상호작용. 조건별 설명은 아래 원문의 `conditions`에 있다.

**권장 수정 방향.** `_policy_args`가 '풀었음'과 '풀지 못함'을 구별해 `resolve_failed`를 넘기고, `Policy.decide`의 `match.instruction_files`는 `resolve_failed`면 그 규칙(승인)을 적용한다. 에이전트가 직접 넣은 `resolved_path`·`resolve_failed` 키는 서비스가 값을 정하기 전에 지운다. 미리보기도 '실제 대상을 풀지 못함'을 보여 준다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** A prompt-injected agent can write into an instruction directory (for example /workspace/.claude/) without human approval when the source folder contains a planted directory symlink such as cfg -> .claude. The write gate depends on one in-container 'realpath -m' (SandboxManager.resolve) at decide time. AgentBox._resolved catches every exception and returns None, and _policy_args then drops resolved_path. Policy.decide (default_policy.yaml v4 rule instruction-file-write-needs-approval) therefore judges only the requested path 'cfg/settings.json', for which kind() is None, and the decision is default allow. write_file then runs 'mv -f -- tmp /workspace/cfg/settings.json', which follows the cfg -> .claude link, so the content lands in /workspace/.claude/settings.json with no approval. The agent causes resolve() to fail with an allowlisted read-only exec ('tail -f /dev/null &' repeated about 55 times) that uses up the container pid limit, while a concurrent write_file still succeeds. This bypasses the a0a186c fix for the single-pass review's F2.

**root_cause** AgentBox._resolved (service.py:235-247) turns every resolve() exception into None, and _policy_args (service.py:249-251) omits resolved_path when the value is None. A failed link resolution therefore fails open: the instruction-file rule, which needs resolved_path to see through links, is evaluated against the attacker-chosen requested path. The agent can cause resolve() to fail (pid exhaustion through an allowlisted background exec, or the exec timeout). write_file and delete_file act on the requested path and follow the planted link at mv/rm time.

**intended_behavior** When the container-side link resolution for a write_file/delete_file target cannot be completed, the control plane must fail closed for the instruction-file gate (require human approval or deny) rather than judging the requested path alone.

**trace**

- `agentbox/service.py:369` (entrypoint, AgentBox._call_tool) — policy.decide(tool, self._policy_args(sid, tool, args)) decides the write_file without any resolved_path when resolve failed.
- `agentbox/service.py:246` (propagation, AgentBox._resolved) — 'except Exception:' followed by 'return None' at line 247 swallows every resolve() failure (SandboxError, a failed exec_run under pid exhaustion, or a timeout).
- `agentbox/service.py:251` (propagation, AgentBox._policy_args) — Returns args without resolved_path when real is None, so the gate loses its only view through the link.
- `agentbox/policy.py:225` (propagation, Policy.decide match.instruction_files) — hit is the first of args['path']/args['resolved_path'] with a kind; with only the benign path present, hit is None, the rule is skipped, and write_file falls to default allow.
- `agentbox/sandbox.py:511` (sink, SandboxManager.write_file) — mv -f -- tmp p on the requested path follows the cfg->.claude link, writing /workspace/.claude/settings.json with no approval.

**conditions**

- authentication_level: Attacker is a prompt-injected agent holding only its per-sandbox agent token.
- data_state: The source folder (attacker-controlled names and links) contains a directory symlink such as cfg -> .claude, copied into /workspace at creation. Creating a new link needs an approved exec (ln).
- timing_dependency: The agent exhausts the container pid limit with allowlisted background execs so resolve() fails while a write exec still succeeds; parent-live shows the window at about 55 background processes with pids_limit 64.
- user_interaction: Recipient impact needs the human to take more than the top-level outbox files (e.g. copy the workspace) so another coding agent reads the planted .claude/settings.json.

**execution.attacker_perspective** A prompt-injected agent that wants to drop an instruction file into .claude/ without the human approving it.

**execution.instructions**

1. In the approved sandbox, load the real Policy from agentbox/default_policy.yaml and reproduce service._resolved/_policy_args (catch-all -> None, drop resolved_path).
2. Call Policy.decide('write_file', ...) once with a resolve that returns /workspace/.claude/settings.json and once with a resolve that raises.
3. Observe that the raising case yields allow (rule_id None) while the succeeding case yields require_approval.

**execution.observed_result** resolve success -> require_approval; resolve failure -> allow (rule_id None). Parent-live real-docker run wrote /workspace/.claude/settings.json under policy ('allow', None) with no approval.

**remediation.strategy** Fail closed when link resolution for a path tool cannot be completed: _policy_args must distinguish 'resolved' from 'could not resolve', and Policy.decide must require approval (or deny) for a write_file/delete_file whose real target is unknown. Keep the allow path only when resolve() positively returns a non-instruction absolute path. Strip any agent-supplied resolved_path/resolve_failed keys before the service sets them.

`agentbox/service.py`:

```python
def _policy_args(self, sid: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    args = {k: v for k, v in args.items() if k not in ("resolved_path", "resolve_failed")}
    if tool not in ("write_file", "delete_file"):
        return args
    resolve = getattr(self.sandboxes, "resolve", None)
    if resolve is None:
        return args
    try:
        real = resolve(sid, str(args.get("path", "")))
    except Exception:
        return {**args, "resolve_failed": True}   # 실제 대상을 모르면 지시 파일일 수 있다고 본다
    return {**args, "resolved_path": real}
```

`agentbox/policy.py`:

```python
if match.get("instruction_files"):
    if tool not in PATH_TOOLS:
        continue
    if args.get("resolve_failed"):
        return Decision(r["action"], r["id"], r.get("reason"), [str(args.get("path", ""))])
    hit = next((x for x in (args.get("path"), args.get("resolved_path"))
                if isinstance(x, str) and instruction_files.kind(x)), None)
    if hit is None:
        continue
    return Decision(r["action"], r["id"], r.get("reason"), [hit])
```

</details>
