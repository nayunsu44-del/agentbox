"""Korean text for the run-7 Phase 6 reports (written by the parent from findings.json).

The English record in findings.json stays authoritative; gen6.py renders these Korean fields and attaches the
original record text below each entry.
"""

KO = {
    "agentbox/templates/_approvals.html:instruction-content-full-render-unbounded-per-poll": {
        "title": "지시 파일 쓰기 승인 카드가 에이전트가 정한 크기의 내용 전체를 상한 없이 2초마다 다시 그린다",
        "desc": "에이전트는 샌드박스마다 지시 파일 쓰기 승인 대기를 20개(`PENDING_APPROVALS_MAX`)까지 만들 수 있다. 대기 행은 쓸 내용(`content`)을 그대로 담는다. `content`는 16KiB 인자 상한(`TOOL_ARG_MAX`)에서 빠지고, `max_write_bytes`(1MiB)는 승인 뒤 실제로 쓸 때만 확인한다. 그래서 카드 하나의 내용은 JSON 본문 상한 8MiB까지 커질 수 있다. `_approvals.html:13`은 단발 F1 수정에 따라 이 내용을 자르지 않고 `<pre>`에 모두 찍는다. `_shown`(`escape_controls`)은 U+0001 같은 제어 문자를 `\\x01` 네 글자로 바꿔 크기를 늘린다. `web.render`는 204를 돌려줄 때도 본문을 다 만들고 sha256을 계산한다. 첫 화면(`index.html:25`, 모든 샌드박스)과 샌드박스 화면(`sandbox.html:25`)은 이 조각을 2초마다 다시 받는다.",
        "root": "폴링되는 승인 조각에 카드별·조각 전체의 렌더링 크기 상한이 없다. 대기 승인을 만들 때 쓸 내용의 크기를 확인하지 않는다. 바뀌었는지(204) 판단은 본문을 다 만든 뒤에야 한다.",
        "intended": "2초마다 받는 승인 조각 한 번의 CPU와 응답 크기는 묶여 있어야 한다. 에이전트가 정한 대기 내용 때문에 요청 한 번이 수 초·수십 MiB가 되어서는 안 되며, 사람은 그 요청을 계속 보고 거절할 수 있어야 한다.",
        "obs": "- parent-live(실제 dockerd·샌드박스·API): `d{i}/CLAUDE.md`에 1MiB U+0001 내용을 쓰는 `write_file`을 보내 20번 모두 202를 받았다(21번째는 429). 그 뒤 `GET /ui/approvals` 한 번이 **83,920,462바이트, 13.69~13.91초**였고 샌드박스별 조각도 같았다(`agents/parent-live/artifacts/approvals_render_live.out`).\n- 3단계 검증자 샌드박스(실제 템플릿·필터): 20 × 1MiB U+0001은 10.846초·80.0MiB, 같은 크기의 일반 ASCII는 0.131초·20.0MiB(`agents/v-approvals-render/artifacts/v_render.out`).\n- 5단계 검증자: 앞부분 4KiB만 그리는 수정안을 넣으면 10.127초·83,909,102바이트가 0.040초·352,582바이트로 줄었다(`agents/r-approvals-render/artifacts/fixcheck.out`).",
        "fix": "폴링 조각에는 내용 앞부분(예: 4KiB)·전체 길이·sha256만 보이고, 폴링하지 않는 별도 페이지(`/ui/approvals/{id}/content`, `_shown`과 같은 처리)에서 전체 내용을 보게 한다. 조각 전체의 렌더링 크기도 묶는다. 대기 승인을 만들기 전에 `max_write_bytes`를 확인한다. 204 판단은 승인 id·상태로 한다.",
    },
    "agentbox/instruction_files.py:kind:instruction-dir-as-final-component-unmatched-so-write-into-linked-dir-skips-approval": {
        "title": "지시 폴더를 가리키는 링크 자체에 write_file을 하면 승인 없이 지시 폴더 안에 쓴다 (kind()가 끝 조각을 지시 폴더로 보지 않음)",
        "desc": "원본 폴더에 `cfg -> .claude` 같은 링크가 있을 때 에이전트가 `write_file('/workspace/cfg', 내용)`을 부르면, `resolve()`는 `/workspace/.claude`를 돌려준다. 그런데 `kind()`는 지시 폴더 이름(`_DIRS`, `.github/instructions` 등)을 경로의 마지막이 아닌 조각에서만 찾는다(`parts[:-1]`). 그래서 `kind('/workspace/cfg')`와 `kind('/workspace/.claude')`가 모두 None이 되고, 지시 파일 쓰기 규칙이 맞지 않아 `default: allow`로 실행된다. `write_file`의 `mv -f -- tmp cfg`는 디렉터리 링크를 따라가 임시 파일을 `.claude/` 안으로 옮긴다(`.claude/cfg.agentbox-tmp-<hex>`). 도구 결과에는 경로가 `/workspace/cfg`로 남는다. `gh -> .github/instructions`도 같다. `delete_file`은 모든 삭제를 승인으로 보내는 규칙이 있어 해당하지 않는다.",
        "root": "`kind()`는 마지막 조각을 지시 폴더로 검사하지 않는다. `scan()`은 `kind(rel + '/_')`로 이를 피하지만 정책과 미리보기는 경로를 그대로 넘긴다. 그래서 실제 대상이 지시 폴더 자체인 쓰기를 지시 파일이 아닌 것으로 판단하는데, `mv -f`는 실행할 때 그 링크를 따라가 폴더 안에 쓴다.",
        "intended": "실제 대상이 지시 폴더이거나 그 안인 에이전트 쓰기는, 한 단계 더 들어간 경로에 쓸 때와 똑같이 사람 승인을 받아야 한다.",
        "obs": "- parent-live(실제 API·컨테이너): `write_file /workspace/cfg`가 맞은 규칙 없이 200 executed였고 `/workspace/.claude/cfg.agentbox-tmp-74833b`가 생겼다. 대조로 보낸 `cfg/settings.json`은 202 승인 대기였다(`agents/parent-live/artifacts/recon_leads_live.out`).\n- 헌터·3단계 검증자 샌드박스: `decide('write_file', {path: cfg, resolved_path: /workspace/.claude})`는 allow, `.github/instructions`도 allow. 한 단계 더 깊은 경로와 `CLAUDE.md`는 승인. `delete_file`은 모두 승인(`agents/v-if-dirlink/artifacts/repro.out`).\n- 들어간 파일 이름이 `cfg.agentbox-tmp-<hex>`로 정해져 있어, 다른 에이전트가 이름으로 자동으로 읽는 파일은 아니다. 그래서 영향은 낮음이다.",
        "fix": "정책과 미리보기에서 요청 경로와 `resolved_path` 둘 다 `kind(x) or kind(x.rstrip('/') + '/_')`로 본다(`scan()`과 같은 방식). 이름과 폴더 형태를 함께 보는 함수 하나를 두면 이런 불일치가 다시 생기지 않는다.",
    },
    "agentbox/service.py:_resolved:resolve-failure-fails-open-to-requested-path-skips-instruction-file-approval": {
        "title": "resolve() 실패를 일부러 일으키면 지시 파일 쓰기가 요청 경로로만 판정되어 승인 없이 .claude/settings.json을 덮어쓴다",
        "desc": "단발 F2 수정(a0a186c)은 `cfg -> .claude` 링크를 거친 `cfg/settings.json` 쓰기를 컨테이너 안 `realpath -m`(`SandboxManager.resolve`)으로 푼 `resolved_path`로 잡는다. 그런데 `AgentBox._resolved`는 `resolve()`의 모든 예외를 None으로 바꾸고, `_policy_args`는 그때 `resolved_path`를 빼고 넘긴다. 그러면 정책은 요청 경로 `cfg/settings.json`(`kind()`가 None)만 보고 기본값 allow로 판정한다. 이어서 `write_file`의 `mv -f`가 링크를 따라가 `/workspace/.claude/settings.json`에 쓴다. 에이전트는 승인 없이 도는 허용 목록 exec(`tail -f /dev/null &`를 약 55개)로 컨테이너 pid 상한을 채워 `resolve()`를 실패시키고, 같은 때 보낸 `write_file`이 성공하게 할 수 있다.",
        "root": "`_resolved`(`service.py:235-247`)가 링크를 풀지 못한 경우를 '판단할 수 없음'이 아니라 '링크 없음'처럼 다룬다(fail-open). 코드 주석은 풀 수 없는 경로면 쓰기도 실패한다고 가정하는데, 링크 루프에는 맞지만 일부러 일으킨 일시적 실패에는 맞지 않는다.",
        "intended": "`write_file`·`delete_file` 대상의 링크를 컨테이너 안에서 풀지 못했으면, 지시 파일 판정은 승인(또는 거부)으로 닫혀야 한다. 요청 경로만으로 판단해서는 안 된다.",
        "obs": "- parent-live(실제 dockerd·샌드박스, `AGENTBOX_PIDS=64`, `AGENTBOX_EXEC_TIMEOUT=8`): 백그라운드 `tail` 55개를 띄운 exec(read-only-exec 허용) 중에 보낸 `write_file /workspace/cfg/settings.json` 3번 중 1번이 200 executed(`('allow', None)`)였다. `/workspace/.claude/settings.json` 내용이 `INJECTED n=55 i=0`로 바뀌었고, 나머지 2번은 승인 대기였다. 58개 이상에서는 쓰기도 모두 실패(126)했다(`agents/parent-live/artifacts/resolve_failopen_live.out`).\n- 헌터·3단계 검증자 샌드박스: 실제 `_resolved`·`_policy_args`·기본 정책으로 `resolve()`가 성공하면 승인, 예외를 내면 allow(`rule_id` None)였다(`agents/v-resolve-failopen/artifacts/repro.out`).\n- pid 상한을 맞춰야 해서 성공 구간이 좁다. 그래서 가능성은 낮음으로 보았다.",
        "fix": "`_policy_args`가 '풀었음'과 '풀지 못함'을 구별해 `resolve_failed`를 넘기고, `Policy.decide`의 `match.instruction_files`는 `resolve_failed`면 그 규칙(승인)을 적용한다. 에이전트가 직접 넣은 `resolved_path`·`resolve_failed` 키는 서비스가 값을 정하기 전에 지운다. 미리보기도 '실제 대상을 풀지 못함'을 보여 준다.",
    },
    "agentbox/service.py:disk_low-unmonitored-docker-data-root": {
        "title": "Docker 저장소 경로를 컨트롤 플레인이 볼 수 없으면 disk_low()가 오류를 무시하고 DB 디스크만 본다 (run-6 N3 수정이 덜 막음)",
        "desc": "run-6 N3 수정은 `disk_low()`가 DB 디스크와 Docker `DockerRootDir`의 남은 공간 중 작은 쪽을 보게 했다. 그런데 `DockerRootDir`는 데몬 호스트의 경로이고, compose 구성의 컨트롤 플레인 컨테이너는 `docker.sock`과 `AGENTBOX_HOME`만 붙인다. 그래서 `shutil.disk_usage(docker_root)`가 `FileNotFoundError`를 내고, 이 오류를 `except OSError: pass`가 조용히 넘긴다. DB와 Docker 저장소가 다른 파일 시스템에 있으면, 컨테이너 쓰기 층이나 스냅샷이 Docker 저장소를 채워도 507 보호선이 켜지지 않는다.",
        "root": "`disk_low()`(`service.py:474-477`)가 Docker 저장소 경로에 접근하지 못하는 경우를 '제약 없음'으로 처리한다(fail-open). 경고도 남기지 않는다.",
        "blockers": [
            "운영 배포에서 Docker 저장소와 `AGENTBOX_HOME`이 서로 다른 파일 시스템인지는 저장소 밖의 사실이다. 같은 파일 시스템이면 DB 디스크 측정이 Docker 저장소 증가도 반영하므로 노출이 없다.",
            "Docker `data-root`를 `AGENTBOX_HOME` 볼륨 안에 둔 배포에서는 경로가 보여 수정이 동작한다.",
            "실제 호스트 저장소가 찰 때까지 채우는 확인은 운영자 소유의 일회용 다중 볼륨 환경이 필요해 이 감사에서 하지 않았다.",
        ],
        "plan": "운영자 소유의 비운영 compose 배포에서 (1) `docker compose exec agentbox python3 -c 'import shutil,docker; r=docker.from_env().info()[\"DockerRootDir\"]; print(r, shutil.disk_usage(r))'`가 `FileNotFoundError`를 내는지, (2) `AGENTBOX_HOME`과 호스트 Docker 저장소의 `df`가 다른지 확인한다. 다르면 일회용 호스트에서 샌드박스 쓰기 층을 키우며 `disk_low` 기록이 생기지 않는지 본다. 코드 쪽에서는 경로를 볼 수 없을 때 시작 시 경고하거나 Docker API(`df`)로 재는 방식을 검토한다.",
        "live": "- 컨트롤 플레인을 compose처럼 `docker.sock`과 `AGENTBOX_HOME`만 붙인 컨테이너에서 돌렸다. `DockerRootDir`(`/projects/sandbox/.scratch/docker/data`)는 컨테이너 안에 없었고 `disk_usage`는 `FileNotFoundError`를 냈다. 이때 `disk_low()`는 `AGENTBOX_HOME` 디스크만 따라갔다(`agents/parent-live/artifacts/disk_low_compose_live.out`). 데몬 저장소는 다른 장치(`/dev/loop1`)에 있었다.",
    },
    "agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed": {
        "title": "casefold가 U+0130(İ)을 결합 문자로 펼쳐, 대소문자를 가리지 않는 파일 시스템이 같은 파일로 볼 수 있는 이름을 kind()가 놓칠 수 있다",
        "desc": "`_norm`은 `NFKC` 뒤 `casefold()`를 쓴다. 파이썬의 casefold는 U+0130(LATIN CAPITAL LETTER I WITH DOT ABOVE)을 `i` + U+0307(결합 점)로 펼친다. 그래서 `kind('gemİni.md')`는 None이 된다. 이 이름은 `clean_name`을 통과해 결과함에서 내려받을 수 있고, 배지도 승인도 붙지 않는다. 받는 쪽 파일 시스템이나 코딩 에이전트가 U+0130을 그냥 `i`로 접으면 이 파일이 `gemini.md`가 되어, a0a186c가 막은 전각·`ſ` 우회와 같은 경계를 넘는다.",
        "root": "`_norm`(`instruction_files.py:74`)이 결합 문자를 만들어 내는 full casefold에 기대어 분류한다. 결합 문자가 생기지 않는 접기(NFKD 뒤 Mn 제거, 그다음 casefold)를 쓰면 `gemini.md`로 분류된다(검증자 샌드박스에서 확인).",
        "blockers": [
            "macOS APFS·HFS+(대소문자 무시)가 U+0130이 든 이름을 ASCII `i` 이름과 같은 파일로 보는지는 리눅스 오프라인 감사 환경에서 볼 수 없다. 파일 시스템 비교가 흔히 쓰는 simple case folding은 U+0130을 그대로 두므로, 같은 파일이 되지 않을 가능성도 있다.",
            "받는 쪽 코딩 에이전트가 이름을 스스로 접어 맞추는지는 그 에이전트와 OS가 있어야 확인된다.",
            "NTFS `$UpCase`는 U+0130을 `i`와 같게 보지 않는다고 문서화되어 있어 Windows 쪽은 해당하지 않는다.",
        ],
        "plan": "소유자의 macOS에서 대소문자 무시 APFS와 HFS+ 볼륨에 `gemİni.md`(U+0130)를 만들고, `stat gemini.md`가 그 파일을 여는지와 `ls`에 항목이 하나인지 둘인지 본다. 같은 파일이 되면 분류용 접기를 결합 문자를 만들지 않는 방식으로 바꾼다.",
        "live": "",
    },
}
