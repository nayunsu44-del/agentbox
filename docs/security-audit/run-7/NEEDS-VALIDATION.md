# run-7 검증 필요 항목

코드의 동작은 샌드박스와 일회용 Docker 컨테이너에서 확인했으나, 실제 영향이 운영 배포 구성(파일 시스템 분리)이나 감사 환경에 없는 OS(macOS)에 좌우되어 `needs_validation`으로 분류한 항목이다. 항목마다 막힌 지점과 검증 계획을 한국어로 옮겼고, 아래에 영어 레코드 원문(기준)을 접어 두었다.

## N1. casefold가 U+0130(İ)을 결합 문자로 펼쳐, 대소문자를 가리지 않는 파일 시스템이 같은 파일로 볼 수 있는 이름을 kind()가 놓칠 수 있다

- 지문: `agentbox/instruction_files.py:_norm:casefold-expands-dotted-capital-i-so-ci-filesystem-alias-is-missed`
- 경로: `agentbox/policy.py:225`(진입점), `agentbox/instruction_files.py:74`(전파), `agentbox/service.py:674`(전파), `agentbox/api.py:403`(도달점)

**설명.** `_norm`은 `NFKC` 뒤 `casefold()`를 쓴다. 파이썬의 casefold는 U+0130(LATIN CAPITAL LETTER I WITH DOT ABOVE)을 `i` + U+0307(결합 점)로 펼친다. 그래서 `kind('gemİni.md')`는 None이 된다. 이 이름은 `clean_name`을 통과해 결과함에서 내려받을 수 있고, 배지도 승인도 붙지 않는다. 받는 쪽 파일 시스템이나 코딩 에이전트가 U+0130을 그냥 `i`로 접으면 이 파일이 `gemini.md`가 되어, a0a186c가 막은 전각·`ſ` 우회와 같은 경계를 넘는다.

**주장하는 근본 원인.** `_norm`(`instruction_files.py:74`)이 결합 문자를 만들어 내는 full casefold에 기대어 분류한다. 결합 문자가 생기지 않는 접기(NFKD 뒤 Mn 제거, 그다음 casefold)를 쓰면 `gemini.md`로 분류된다(검증자 샌드박스에서 확인).

**막힌 지점.**

- macOS APFS·HFS+(대소문자 무시)가 U+0130이 든 이름을 ASCII `i` 이름과 같은 파일로 보는지는 리눅스 오프라인 감사 환경에서 볼 수 없다. 파일 시스템 비교가 흔히 쓰는 simple case folding은 U+0130을 그대로 두므로, 같은 파일이 되지 않을 가능성도 있다.
- 받는 쪽 코딩 에이전트가 이름을 스스로 접어 맞추는지는 그 에이전트와 OS가 있어야 확인된다.
- NTFS `$UpCase`는 U+0130을 `i`와 같게 보지 않는다고 문서화되어 있어 Windows 쪽은 해당하지 않는다.

**검증 계획.** 소유자의 macOS에서 대소문자 무시 APFS와 HFS+ 볼륨에 `gemİni.md`(U+0130)를 만들고, `stat gemini.md`가 그 파일을 여는지와 `ls`에 항목이 하나인지 둘인지 본다. 같은 파일이 되면 분류용 접기를 결합 문자를 만들지 않는 방식으로 바꾼다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** _norm normalizes a name with unicodedata.normalize('NFKC', name).casefold(). Python's full casefold expands LATIN CAPITAL LETTER I WITH DOT ABOVE (U+0130) to 'i' followed by U+0307 COMBINING DOT ABOVE, so kind('gemİni.md') returns None. clean_name accepts the name on the outbox download path, outbox()/_outbox.html show no instruction-file badge, and the write never hit the instruction-file approval rule. If a recipient on a case-insensitive volume equates 'gemİni.md' to 'gemini.md', the human's other coding agent auto-reads attacker content as an instruction file, the same boundary the a0a186c fullwidth/U+017F fix was meant to close. NTFS $UpCase does not equate U+0130 with ASCII 'i', so Windows recipients are not affected; the open question is macOS and other case-insensitive volumes.

**claimed_root_cause** _norm relies on Python's full casefold, which maps U+0130 to an ASCII letter plus a combining mark, diverging from an OS case-insensitive fold that may map U+0130 to plain 'i'; kind() therefore misclassifies a name a case-insensitive filesystem might resolve to a canonical instruction name. A fold that does not introduce combining marks (NFKD, drop Mn, then casefold, verified locally to yield 'gemini.md') would classify it.

**trace**

- `agentbox/policy.py:225` (entrypoint, Policy.decide, match.instruction_files branch) — A prompt-injected agent calls write_file with path 'outbox/gemİni.md'; kind() of path and resolved_path is None, so the instruction-file-write-needs-approval rule does not fire.
- `agentbox/instruction_files.py:74` (propagation, _norm) — casefold() expands U+0130 to 'i'+U+0307, so _norm('gemİni.md')='gemi̇ni.md' and kind() returns None.
- `agentbox/service.py:674` (propagation, AgentBox.outbox) — outbox() calls IF.kind(f['name']) which returns None, so no instruction_file flag or badge is shown.
- `agentbox/api.py:403` (sink, outbox_file Content-Disposition filename*) — The human downloads the file (clean_name accepts the name); on a volume that folds U+0130 to 'i' the saved name could resolve to 'gemini.md'.

**blockers**

- Whether a real case-insensitive filesystem (APFS or HFS+) equates a filename containing U+0130 with the ASCII-'i' canonical name is not observable on the Linux-only offline host. Full casefold expands U+0130 to 'i'+U+0307, but simple (1:1) case folding, which file-system comparison typically uses, maps U+0130 to itself, so the alias is not established and may well be false.
- Whether a recipient coding agent on such a volume loads the aliased name requires that agent and OS at runtime.
- NTFS $UpCase is documented not to equate U+0130 with ASCII 'i', so the Windows recipient path is excluded.

**validation_plan.local** Already run in the approved sandbox (h2.out). Extend by enumerating every character whose casefold expands to an ASCII letter used in _NAMES/_DIRS plus a combining or invisible code point.

**validation_plan.deployment** On an owner-controlled macOS machine with an APFS case-insensitive volume, create a file literally named 'gemİni.md' and check whether `stat gemini.md` resolves to it and whether `ls` shows one or two files. If it aliases, fold names for classification with a mapping that does not introduce combining marks (for example NFKD, drop Mn, then casefold, or special-case U+0130).


</details>

## N2. Docker 저장소 경로를 컨트롤 플레인이 볼 수 없으면 disk_low()가 오류를 무시하고 DB 디스크만 본다 (run-6 N3 수정이 덜 막음)

- 지문: `agentbox/service.py:disk_low-unmonitored-docker-data-root`
- 경로: `agentbox/sandbox.py:182`(진입점), `agentbox/service.py:475`(전파), `agentbox/service.py:478`(도달점)

**설명.** run-6 N3 수정은 `disk_low()`가 DB 디스크와 Docker `DockerRootDir`의 남은 공간 중 작은 쪽을 보게 했다. 그런데 `DockerRootDir`는 데몬 호스트의 경로이고, compose 구성의 컨트롤 플레인 컨테이너는 `docker.sock`과 `AGENTBOX_HOME`만 붙인다. 그래서 `shutil.disk_usage(docker_root)`가 `FileNotFoundError`를 내고, 이 오류를 `except OSError: pass`가 조용히 넘긴다. DB와 Docker 저장소가 다른 파일 시스템에 있으면, 컨테이너 쓰기 층이나 스냅샷이 Docker 저장소를 채워도 507 보호선이 켜지지 않는다.

**주장하는 근본 원인.** `disk_low()`(`service.py:474-477`)가 Docker 저장소 경로에 접근하지 못하는 경우를 '제약 없음'으로 처리한다(fail-open). 경고도 남기지 않는다.

**막힌 지점.**

- 운영 배포에서 Docker 저장소와 `AGENTBOX_HOME`이 서로 다른 파일 시스템인지는 저장소 밖의 사실이다. 같은 파일 시스템이면 DB 디스크 측정이 Docker 저장소 증가도 반영하므로 노출이 없다.
- Docker `data-root`를 `AGENTBOX_HOME` 볼륨 안에 둔 배포에서는 경로가 보여 수정이 동작한다.
- 실제 호스트 저장소가 찰 때까지 채우는 확인은 운영자 소유의 일회용 다중 볼륨 환경이 필요해 이 감사에서 하지 않았다.

**검증 계획.** 운영자 소유의 비운영 compose 배포에서 (1) `docker compose exec agentbox python3 -c 'import shutil,docker; r=docker.from_env().info()["DockerRootDir"]; print(r, shutil.disk_usage(r))'`가 `FileNotFoundError`를 내는지, (2) `AGENTBOX_HOME`과 호스트 Docker 저장소의 `df`가 다른지 확인한다. 다르면 일회용 호스트에서 샌드박스 쓰기 층을 키우며 `disk_low` 기록이 생기지 않는지 본다. 코드 쪽에서는 경로를 볼 수 없을 때 시작 시 경고하거나 Docker API(`df`)로 재는 방식을 검토한다.

**부모 실측 (일회용 컨테이너, 에이전트 예산 밖).**

- 컨트롤 플레인을 compose처럼 `docker.sock`과 `AGENTBOX_HOME`만 붙인 컨테이너에서 돌렸다. `DockerRootDir`(`/projects/sandbox/.scratch/docker/data`)는 컨테이너 안에 없었고 `disk_usage`는 `FileNotFoundError`를 냈다. 이때 `disk_low()`는 `AGENTBOX_HOME` 디스크만 따라갔다(`agents/parent-live/artifacts/disk_low_compose_live.out`). 데몬 저장소는 다른 장치(`/dev/loop1`)에 있었다.

<details><summary>레코드 원문 (영어, 기준)</summary>

**description** The run-6 N3 fix added Docker-data-root monitoring to AgentBox.disk_low by taking min(free(db_path.parent), free(docker_root)), where docker_root is the host daemon's DockerRootDir. In the documented compose deployment the control-plane container does not mount the daemon's data root, so shutil.disk_usage(docker_root) raises OSError, which is silently ignored. disk_low then measures only the SQLite db partition. If that partition differs from the host filesystem holding container writable layers and snapshot images, a prompt-injected agent can grow Docker storage without disk_low ever returning True, so the 507 back-pressure never engages. The fix is therefore ineffective in exactly the separate-filesystem topology it was intended to cover.

**claimed_root_cause** disk_low (service.py:461-485) treats an unreachable docker_root as no additional constraint (except OSError: pass) instead of failing closed or warning, and docker_root is taken from the daemon's DockerRootDir (sandbox.py:179-183), a path the compose control-plane container does not mount.

**trace**

- `agentbox/sandbox.py:182` (entrypoint, SandboxManager._detect_runtime) — self.docker_root is set to Path(info['DockerRootDir']), the host daemon's data-root path, not necessarily present inside the control-plane container.
- `agentbox/service.py:475` (propagation, AgentBox.disk_low) — free = min(free, shutil.disk_usage(docker_root).free) is wrapped in try/except OSError: pass (service.py:474-477), so an unreachable docker_root silently drops the Docker-storage term.
- `agentbox/service.py:478` (sink, AgentBox.disk_low) — low = free < s.min_free_bytes is computed from the db partition alone when the docker term was dropped; call_tool's 507 guard never trips on Docker-storage exhaustion.

**blockers**

- Whether, in the compose deployment, the host daemon's DockerRootDir is unreachable inside the control-plane container (compose shows it is not mounted, but a custom data_root on the AGENTBOX_HOME volume would be reachable).
- Whether the host's Docker data-root filesystem is distinct from the AGENTBOX_HOME filesystem; if they are the same, the db measurement still reflects Docker storage.
- Whether a sandbox can grow the Docker data root (writable layers plus up to snapshot_quota=50 commit images, AGENTBOX_DISK empty by default) enough to exhaust host storage before other limits intervene; confirming this needs destructive saturation on an operator-owned multi-volume deployment, which the audit must not run.

**validation_plan.local** In the approved sandbox, construct an object exposing docker_root=Path('/nonexistent/docker/root') and a db path on scratch, set min_free_bytes so disk_low is True only when the docker term counts, and confirm the except-OSError branch returns False.

**validation_plan.deployment** On a real compose deployment: run `docker compose exec agentbox python3 -c 'import shutil,docker; r=docker.from_env().info()["DockerRootDir"]; print(r); print(shutil.disk_usage(r))'` and observe FileNotFoundError; compare df of AGENTBOX_HOME and the host data root; grow a sandbox writable layer and confirm no disk_low event.


</details>
