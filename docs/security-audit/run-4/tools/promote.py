#!/usr/bin/python3 -I
"""Trusted parent-side promotion of agent scratch files to retained artifacts.

usage: promote.py <agent-id> <rel> [<rel> ...]

Implements the security-audit skill's "Artifact promotion procedure" (11 steps):
  * every path component is walked with no-follow, directory-relative operations;
  * the leaf is opened no-follow + nonblocking and must be a regular file with link count 1;
  * per-file (256 KiB) and cumulative (1 MiB per agent) byte limits are enforced twice
    (fstat before reading, and again while reading);
  * the source is fstat'ed again after the copy and rejected if identity/type/nlink/size changed;
  * destination directories are created exclusively (or reopened no-follow and verified);
  * the destination leaf is created exclusively, no-follow, and verified regular with link count 1.
A file that fails any check is discarded and reported; nothing is ever copied by glob or recursively.
Exit code is 0 only if every requested file was promoted.
"""
import os
import stat
import sys

RUN = "/home/user/agentbox/docs/security-audit/run-4"
PER_FILE = 256 * 1024
PER_AGENT = 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def parts_of(rel):
    if not rel or "\x00" in rel or rel.startswith("/"):
        raise ValueError("absolute or empty path")
    parts = rel.split("/")
    for p in parts:
        if p in ("", ".", ".."):
            raise ValueError("empty, '.' or '..' component")
    return parts


def open_root(path):
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{path} is not a real directory")
    return os.open(path, DIR_FLAGS)


def walk_src(root_fd, dirs):
    cur = os.dup(root_fd)
    try:
        for d in dirs:
            nxt = os.open(d, DIR_FLAGS, dir_fd=cur)
            os.close(cur)
            cur = nxt
        return cur
    except BaseException:
        os.close(cur)
        raise


def walk_dst(root_fd, dirs):
    cur = os.dup(root_fd)
    try:
        for d in dirs:
            try:
                os.mkdir(d, 0o755, dir_fd=cur)  # exclusive create
            except FileExistsError:
                pass
            nxt = os.open(d, DIR_FLAGS, dir_fd=cur)  # reopen no-follow, must be a directory
            if not stat.S_ISDIR(os.fstat(nxt).st_mode):
                os.close(nxt)
                raise ValueError("destination component is not a directory")
            os.close(cur)
            cur = nxt
        return cur
    except BaseException:
        os.close(cur)
        raise


def promote_one(scratch_fd, art_fd, rel, used):
    parts = parts_of(rel)
    src_dir = walk_src(scratch_fd, parts[:-1])
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=src_dir)
    finally:
        os.close(src_dir)
    try:
        st1 = os.fstat(fd)
        if not stat.S_ISREG(st1.st_mode):
            raise ValueError("not a regular file")
        if st1.st_nlink != 1:
            raise ValueError(f"link count {st1.st_nlink} != 1")
        if st1.st_size > PER_FILE:
            raise ValueError(f"size {st1.st_size} exceeds per-file limit {PER_FILE}")
        if used + st1.st_size > PER_AGENT:
            raise ValueError("cumulative per-agent limit exceeded")
        chunks, got = [], 0
        while got < st1.st_size:
            b = os.read(fd, min(65536, st1.st_size - got))
            if not b:
                break
            got += len(b)
            if got > PER_FILE:
                raise ValueError("file grew past the per-file limit while reading")
            chunks.append(b)
        st2 = os.fstat(fd)
        same = (st1.st_dev, st1.st_ino, stat.S_IFMT(st1.st_mode), st1.st_nlink, st1.st_size) == (
            st2.st_dev, st2.st_ino, stat.S_IFMT(st2.st_mode), st2.st_nlink, st2.st_size)
        if got != st1.st_size or not same:
            raise ValueError("source changed while copying")
        data = b"".join(chunks)
    finally:
        os.close(fd)
    dst_dir = walk_dst(art_fd, parts[:-1])
    try:
        out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dst_dir)
    finally:
        os.close(dst_dir)
    try:
        ost = os.fstat(out)
        if not stat.S_ISREG(ost.st_mode) or ost.st_nlink != 1:
            raise ValueError("destination is not a fresh regular file")
        view = memoryview(data)
        while view:
            n = os.write(out, view)
            view = view[n:]
    finally:
        os.close(out)
    return len(data)


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    agent = sys.argv[1]
    import re
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", agent):
        print("bad agent id", file=sys.stderr)
        return 2
    base = f"{RUN}/agents/{agent}"
    os.makedirs(f"{base}/artifacts", exist_ok=True)
    scratch_fd = open_root(f"{base}/scratch")
    art_fd = open_root(f"{base}/artifacts")
    used = 0
    failed = 0
    for rel in sys.argv[2:]:
        try:
            n = promote_one(scratch_fd, art_fd, rel, used)
            used += n
            print(f"PROMOTED agents/{agent}/artifacts/{rel} ({n} bytes)")
        except (OSError, ValueError) as e:
            failed += 1
            print(f"DISCARDED {rel}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
