"""exec 허용 목록 차등 퍼저: 정책의 판정과 실제 bash의 동작을 견준다.

정책(`agentbox/policy.py`)은 명령 문자열을 직접 읽어 '읽기 전용 프로그램만 쓰는 단순 명령'인지 판정한다.
bash와 해석이 한 군데라도 갈리면 허용 목록 밖의 프로그램이 승인 없이 돈다. 그래서 명령을 무작위로 만들고,
정책이 `read-only-exec`로 허용한 것만 실제 bash로 돌려서 다음 둘을 확인한다.

- 프로그램: bash가 실행하려 한 이름(xtrace)이 모두 정책이 댄 프로그램 목록 안에 있는가.
- 쓰기: 작업 폴더의 기존 파일이 바뀌거나 내용 있는 새 파일이 생기지 않았는가 (리다이렉션을 놓친 경우).

허용 목록의 프로그램은 이름만 찍는 가짜로 바꿔 두므로 실행해도 아무 일도 하지 않는다. `touch`·`mkdir`만
작업 폴더 안에서 진짜로 돈다 (`mkdir 2~` 뒤 `>&2~/../x` 같은 연쇄를 잡으려고).
허용 목록 밖의 이름은 PATH에 없어 '명령 없음'으로 끝나지만 xtrace에는 남는다.

pytest는 `tests/test_policy_fuzz.py`가 정해진 씨앗으로 짧게 돌린다. 오래 돌리려면:

    python -m tests.policy_fuzz --executed 200000 --seed 7
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from agentbox import policy as current_policy

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "agentbox" / "default_policy.yaml"
_SYSTEM_BIN = {"/bin", "/usr/bin", "/sbin", "/usr/sbin"}
_MARK = "\x1f"                      # xtrace 줄 표시. 만드는 명령에는 이 글자가 없다
_PRELUDE = f"PS4=$'+{_MARK}'\nset -x\numask 002\n"   # 샌드박스도 'umask 002\n' 뒤에 명령을 붙여 bash -c로 돌린다
_SEED_FILES = {"a": "seed-a\n", "a.txt": "seed-a.txt\n", "f": "seed-f\n", "CLAUDE.md": "seed-claude\n"}
_SEED_DIRS = ["d", "1", "2", "2~", "x~"]

# ---- 명령 만들기 ----

_GOOD = ["ls", "cat", "wc", "echo", "pwd", "true", "touch", "mkdir", "test", "head", "cd", "printf",
         "/bin/ls", "/usr/bin/wc"]
_BAD = ["sh", "chmod", "cp", "tee", "python3", "find", "env", "eval", "exec", "command", "./ls",
        "/workspace/ls", "/bin/../bin/sh", "/bin/sh", "X=1"]
_ARGS = ["a", "f", "x", "d", "-l", "-c", "id", "777", "a.txt", "CLAUDE.md", "d/n", "2~", "*", "/dev/null",
         "../CLAUDE.md", "~", "0", "1", "2", "EOF"]
_SEPS = [";", "&&", "||", "|", "&", "\n", "(", ")", "|&", ";;", "{", "}", "!"]
_REDIRS = ["<", ">", ">>", "<>", ">&", "<&", "2>&1", ">&2", "1>&2", "<<", "<<<", "2>", "&>", ">|", "<(", ">(",
           ">/dev/null", "2>/dev/null", ">&-", "<&-"]
_GLUE = ["~", "}", "{", "\\;", "\\", "\r", "\t", "#", "=", "*", "?", "/", "..", "'", '"', "$", "`", ",", "\x0b"]
_JOIN = [" ", " ", " ", "", "", "\t", "\n", "  "]


def _wrap(rng: random.Random, s: str) -> str:
    r = rng.random()
    if r < 0.80:
        return s
    if r < 0.87:
        return "'" + s + "'"
    if r < 0.94:
        return '"' + s + '"'
    return "\\" + s


def generate(rng: random.Random) -> str:
    """명령 하나. 허용되는 뼈대(읽기 전용 명령 몇 개)에 구분자·리다이렉션·붙임 글자·목록 밖 명령을 섞는다."""
    parts: list[str] = []
    for i in range(rng.randint(1, 4)):
        if i:
            parts.append(rng.choice(_SEPS))
        for _ in range(rng.randint(0, 2)):                       # 명령 앞의 리다이렉션·잡음
            if rng.random() < 0.15:
                parts.append(_wrap(rng, rng.choice(_REDIRS)))
                if rng.random() < 0.7:
                    parts.append(rng.choice(_ARGS))
        parts.append(_wrap(rng, rng.choice(_GOOD if rng.random() < 0.6 else _BAD)))
        for _ in range(rng.randint(0, 3)):
            r = rng.random()
            if r < 0.50:
                parts.append(_wrap(rng, rng.choice(_ARGS)))
            elif r < 0.80:
                parts.append(_wrap(rng, rng.choice(_REDIRS)))
            elif r < 0.92:
                parts.append(rng.choice(_GLUE))
            else:
                parts.append(rng.choice(_SEPS))
    out = parts[0]
    for p in parts[1:]:
        out += rng.choice(_JOIN) + p
    # 글자 단위 변형: 지우기, 붙임 글자 끼우기, 조각 바꾸기
    for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
        if not out:
            break
        i = rng.randrange(len(out) + 1)
        r = rng.random()
        if r < 0.35:
            out = out[:i] + out[i + 1:]
        elif r < 0.75:
            out = out[:i] + rng.choice(_GLUE + _SEPS + _REDIRS) + out[i:]
        else:
            out = out[:i] + rng.choice(_REDIRS) + rng.choice(["", " ", "\t"]) + rng.choice(_ARGS + _BAD) + out[i:]
    return out


# ---- 실제 bash로 돌리기 ----

@dataclass
class Result:
    command: str
    claimed: set[str]
    executed: list[str] = field(default_factory=list)
    unclaimed: list[str] = field(default_factory=list)     # 정책이 대지 않았는데 bash가 실행하려 한 이름
    writes: list[str] = field(default_factory=list)        # 바뀐 파일, 내용 있는 새 파일
    timed_out: bool = False

    @property
    def violation(self) -> bool:
        return bool(self.unclaimed or self.writes)

    def describe(self) -> str:
        return (f"명령 {self.command!r}\n  정책이 댄 프로그램 {sorted(self.claimed)}\n"
                f"  bash가 실행하려 한 것 {self.executed}\n  목록 밖 {self.unclaimed}\n  쓰기 {self.writes}")


class Harness:
    """가짜 프로그램 폴더와 작업 폴더를 만들고 명령을 bash로 돌린다."""

    def __init__(self, allowlist: list[str], base: Path | None = None):
        self.bash = shutil.which("bash")
        if not self.bash:
            raise RuntimeError("bash가 없음")
        self._own = base is None
        self.base = Path(tempfile.mkdtemp(prefix="agentbox-fuzz-")) if base is None else Path(base)
        self.base = self.base.resolve()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        real = {n: shutil.which(n) for n in ("touch", "mkdir")}
        for name in allowlist:
            if "/" in name or name in (".", ".."):
                continue
            if real.get(name):
                # 작업 폴더 안의 상대 경로일 때만 진짜로 만든다 (root로 돌려도 밖에 흔적을 남기지 않게)
                body = ('#!/bin/sh\ncase "$(pwd -P)/" in "$FUZZ_ROOT"/*) ;; *) exit 0 ;; esac\n'
                        'for a in "$@"; do case "$a" in /*|*..*|~*) exit 0 ;; esac; done\n'
                        f'exec {shlex.quote(real[name])} "$@" 2>/dev/null\n')
            else:
                body = f"#!/bin/sh\necho stub:{shlex.quote(name)}\n"
            p = self.bin / name
            p.write_text(body)
            p.chmod(0o755)
        self._n = 0

    def close(self) -> None:
        if self._own:
            shutil.rmtree(self.base, ignore_errors=True)

    def __enter__(self) -> "Harness":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @staticmethod
    def _digest(root: Path) -> dict[str, str]:
        out: dict[str, str] = {}
        for p in sorted(root.rglob("*")):
            rel = str(p.relative_to(root))
            if p.is_symlink():
                out[rel] = "link:" + os.readlink(p)
            elif p.is_dir():
                out[rel] = "dir"
            elif p.is_file():
                data = p.read_bytes()
                out[rel] = "empty" if not data else "file:" + hashlib.sha256(data).hexdigest()
            else:
                out[rel] = "other"
        return out

    @staticmethod
    def _name(word: str) -> str:
        """정책과 같은 방식으로 이름을 줄인다: 시스템 폴더 바로 아래면 이름만, 아니면 그대로."""
        if "/" in word:
            folder, name = word.rsplit("/", 1)
            if folder in _SYSTEM_BIN:
                return name
        return word

    def run(self, command: str, claimed: set[str], slot: int | None = None) -> Result:
        if slot is None:
            self._n += 1
            slot = self._n
        root = self.base / f"run-{slot}"
        shutil.rmtree(root, ignore_errors=True)
        work = root / "p" / "q" / "r" / "ws"       # '..'가 몇 번 붙어도 root 안에 머물게 깊이 둔다
        work.mkdir(parents=True)
        for name, text in _SEED_FILES.items():
            (work / name).write_text(text)
        for name in _SEED_DIRS:
            (work / name).mkdir()
        before = self._digest(root)
        res = Result(command, set(claimed))
        env = {"PATH": str(self.bin), "HOME": str(work), "FUZZ_ROOT": str(root), "LC_ALL": "C"}
        try:
            proc = subprocess.run([self.bash, "-c", _PRELUDE + command], cwd=work, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
            trace = proc.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as e:
            res.timed_out = True
            trace = (e.stderr or b"").decode("utf-8", "replace")
        for line in trace.split("\n"):
            body = line.lstrip("+")
            if body == line or not body.startswith(_MARK):
                continue
            text = body[len(_MARK):]
            if text.startswith("umask 002"):
                continue
            try:
                first = shlex.split(text)[0]
            except (ValueError, IndexError):
                first = (text.split() or [""])[0]
            res.executed.append(first)
            if not first or first[0] in ";&|()<>":
                # 따옴표·역슬래시로 글자가 된 구분자로 시작하는 이름("<", \\;, \\;1)이나 빈 이름(''). 정책 렉서는
                # 따옴표를 벗겨 구분자로 읽고 bash는 그 이름의 프로그램을 찾는다. 해석은 갈리지만 시스템 폴더에 그런
                # 이름의 프로그램은 없고, 정책이 더 많이 끊어 읽는 방향이라 뒤의 단어는 프로그램으로 검사된다.
                # 위반으로 세지 않는다.
                continue
            if self._name(first) not in claimed:
                res.unclaimed.append(first)
        after = self._digest(root)
        for rel, kind in after.items():
            old = before.get(rel)
            if old is None and kind not in ("dir", "empty"):
                res.writes.append(f"새 파일 {rel} ({kind[:4]})")       # 빈 파일·폴더는 touch·mkdir로도 생긴다
            elif old is not None and old != kind:
                res.writes.append(f"바뀜 {rel}")
        res.writes.extend(f"없어짐 {rel}" for rel in before if rel not in after)
        shutil.rmtree(root, ignore_errors=True)
        return res


# ---- 정책과 견주기 ----

def load_policy_module(path: str | None):
    """다른 판의 policy.py를 불러온다 (옛 판이 퍼저에 걸리는지 볼 때). None이면 지금 것."""
    if path is None:
        return current_policy
    spec = importlib.util.spec_from_file_location("agentbox._fuzzed_policy", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def allowlist_of(pol: Any) -> list[str]:
    for r in pol.rules:
        only = (r.get("match") or {}).get("only_commands")
        if only and r.get("action") == "allow":
            return [str(c) for c in only]
    raise ValueError("정책에 only_commands 허용 규칙이 없음")


def allowed(pol: Any, command: str) -> set[str] | None:
    """정책이 승인 없이 허용하면 정책이 댄 프로그램 목록, 아니면 None."""
    d = pol.decide("exec", {"command": command})
    return set(d.matched) if d.action == "allow" else None


@dataclass
class Summary:
    generated: int = 0
    executed: int = 0
    timed_out: int = 0
    violations: list[Result] = field(default_factory=list)


def fuzz(pol: Any, *, seed: int, executed: int, max_generated: int | None = None, workers: int | None = None,
         stop_after: int | None = None, on_violation: Callable[[Result], None] | None = None) -> Summary:
    """정책이 허용한 명령을 executed개 돌릴 때까지(또는 max_generated개 만들 때까지) 퍼징한다."""
    rng = random.Random(seed)
    cap = max_generated if max_generated is not None else executed * 400
    summary = Summary()
    seen: set[str] = set()

    def candidates() -> Iterator[tuple[str, set[str]]]:
        while summary.generated < cap:
            cmd = generate(rng)
            summary.generated += 1
            if cmd in seen:
                continue
            seen.add(cmd)
            progs = allowed(pol, cmd)
            if progs is not None:
                yield cmd, progs

    workers = workers or min(8, os.cpu_count() or 2)
    with Harness(allowlist_of(pol)) as h, ThreadPoolExecutor(workers) as pool:
        source = candidates()
        while summary.executed < executed:
            batch = [c for _, c in zip(range(min(workers * 8, executed - summary.executed)), source)]
            if not batch:
                break
            for res in pool.map(lambda ic: h.run(ic[1][0], ic[1][1], slot=ic[0]), enumerate(batch)):
                summary.executed += 1
                summary.timed_out += res.timed_out
                if res.violation:
                    summary.violations.append(res)
                    if on_violation:
                        on_violation(res)
            if stop_after and len(summary.violations) >= stop_after:
                break
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="exec 허용 목록 차등 퍼저 (정책 대 bash)")
    ap.add_argument("--executed", type=int, default=20000, help="정책이 허용해 실제로 돌릴 명령 수")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--stop-after", type=int, default=20, help="위반이 이만큼 모이면 멈춤 (0 = 끝까지)")
    ap.add_argument("--policy", default=str(DEFAULT_POLICY), help="정책 YAML")
    ap.add_argument("--policy-module", default=None, help="다른 판의 policy.py 경로 (옛 판 확인용)")
    a = ap.parse_args(argv)
    mod = load_policy_module(a.policy_module)
    pol = mod.Policy.load(a.policy)
    s = fuzz(pol, seed=a.seed, executed=a.executed, workers=a.workers, stop_after=a.stop_after or None,
             on_violation=lambda r: print(r.describe(), flush=True))
    print(f"만든 명령 {s.generated}개, 정책이 허용해 bash로 돌린 명령 {s.executed}개, "
          f"시간 초과 {s.timed_out}개, 위반 {len(s.violations)}건")
    return 1 if s.violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
