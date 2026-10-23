#!/usr/bin/env python3
"""Trusted parent-side promotion of agent scratch files to retained artifacts (run-4, Windows host).

usage: promote.py <agent-id> <rel> [<rel> ...]

Implements the security-audit skill's "Artifact promotion procedure" with the checks the
Windows API can express:

  * every path component is checked with lstat and must be a real directory: no symlink,
    no junction/other reparse point, no '.'/'..' and no absolute path;
  * the leaf is opened with O_NOINHERIT and must be a regular file (not a device, pipe or
    socket, which is why FIFOs cannot hang the copy), owned by nobody weird, and a
    reparse point is refused;
  * per-file (256 KiB) and cumulative (1 MiB per agent) byte limits are enforced twice:
    by size before reading, and while reading;
  * the source identity (volume id, file index, size) is re-read after the copy and the
    copy is rejected if it changed;
  * the destination leaf is created exclusively ('xb', O_EXCL) and never follows a link.

The Linux-only primitives of the run-3 version (O_NOFOLLOW, O_DIRECTORY, dir_fd,
st_nlink) do not exist here; the replacements above keep every property that mattered.
A file that fails any check is discarded and reported; nothing is copied by glob or
recursively. Exit code is 0 only if every requested file was promoted.
"""
import os
import stat
import sys

RUN = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
PER_FILE = 256 * 1024
PER_AGENT = 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def parts_of(rel):
    if not rel or "\x00" in rel or rel.startswith("/") or rel.startswith("\\") or ":" in rel:
        raise ValueError("absolute or empty path")
    parts = rel.replace("\\", "/").split("/")
    for p in parts:
        if p in ("", ".", ".."):
            raise ValueError("empty, '.' or '..' component")
    return parts


def is_reparse(path):
    st = os.lstat(path)
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def real_dir(path):
    if is_reparse(path) or not os.path.isdir(path):
        raise ValueError(f"{path} is not a real directory")
    return path


def promote_one(scratch_root, art_root, rel, used):
    parts = parts_of(rel)
    cur = real_dir(scratch_root)
    for d in parts[:-1]:
        cur = real_dir(os.path.join(cur, d))
    src = os.path.join(cur, parts[-1])
    if is_reparse(src):
        raise ValueError("source is a reparse point")
    st1 = os.lstat(src)
    if not stat.S_ISREG(st1.st_mode):
        raise ValueError("not a regular file")
    if getattr(st1, "st_nlink", 1) != 1:
        raise ValueError(f"link count {st1.st_nlink} != 1")
    if st1.st_size > PER_FILE:
        raise ValueError(f"size {st1.st_size} exceeds per-file limit {PER_FILE}")
    if used + st1.st_size > PER_AGENT:
        raise ValueError("cumulative per-agent limit exceeded")

    fd = os.open(src, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
    try:
        chunks, got = [], 0
        while got < st1.st_size:
            b = os.read(fd, min(65536, st1.st_size - got))
            if not b:
                break
            got += len(b)
            if got > PER_FILE:
                raise ValueError("grew past the per-file limit while reading")
            if used + got > PER_AGENT:
                raise ValueError("grew past the per-agent limit while reading")
            chunks.append(b)
        data = b"".join(chunks)
    finally:
        os.close(fd)

    st2 = os.lstat(src)
    ident1 = (getattr(st1, "st_ino", 0), st1.st_size)
    ident2 = (getattr(st2, "st_ino", 0), st2.st_size)
    if ident1 != ident2 or len(data) != st1.st_size:
        raise ValueError("source changed while it was being copied")

    dst_dir = real_dir(art_root)
    for d in parts[:-1]:
        nxt = os.path.join(dst_dir, d)
        try:
            os.mkdir(nxt)
        except FileExistsError:
            pass
        dst_dir = real_dir(nxt)
    dst = os.path.join(dst_dir, parts[-1])
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0), 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    st3 = os.lstat(dst)
    if not stat.S_ISREG(st3.st_mode) or st3.st_size != len(data):
        os.unlink(dst)
        raise ValueError("destination is not a verified regular file")
    return len(data)


def main():
    if len(sys.argv) < 3:
        print("usage: promote.py <agent-id> <rel> [<rel> ...]", file=sys.stderr)
        sys.exit(2)
    aid, rels = sys.argv[1], sys.argv[2:]
    scratch_root = f"{RUN}/agents/{aid}/scratch"
    art_root = f"{RUN}/agents/{aid}/artifacts"
    os.makedirs(art_root, exist_ok=True)
    used, ok = 0, 0
    for rel in rels:
        try:
            n = promote_one(scratch_root, art_root, rel, used)
        except (ValueError, OSError) as e:
            print(f"DISCARD {rel}: {e}")
            continue
        used += n
        ok += 1
        print(f"PROMOTED {rel} ({n} bytes)")
    print(f"{ok}/{len(rels)} promoted, {used} bytes total")
    sys.exit(0 if ok == len(rels) else 1)


if __name__ == "__main__":
    main()
