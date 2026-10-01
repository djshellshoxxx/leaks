# SPDX-License-Identifier: AGPL-3.0-or-later
#
# safe-read.py - race-free, size-capped copy of one config-check input (AUD-RM2-DEP-24).
#
# Usage (called by config-check.sh only, as `python3 -I -S -B safe-read.py ...`):
#   safe-read.py ABS-PATH OUT MAX-BYTES OWNERS DENY-MODE
#     ABS-PATH   absolute path of the input (no '.'/'..' components)
#     OUT        output file (created 0600, never through a symlink; truncated)
#     MAX-BYTES  size cap; a larger file is refused
#     OWNERS     comma list of uids that may own the input
#     DENY-MODE  octal permission bits the input must not have (e.g. 022)
#
# Every path component is opened relative to its parent with openat semantics and
# O_NOFOLLOW (directories with O_PATH|O_DIRECTORY), starting at "/": a component swapped for a
# symlink after any earlier check fails with ELOOP/ENOTDIR instead of being followed. The input
# is checked with fstatat(AT_SYMLINK_NOFOLLOW) before the open (a FIFO or device node is never
# opened), opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY (a FIFO swapped in at the last moment
# cannot block), and the open descriptor is fstat-checked: regular file, the same inode as
# checked, one link, owner in OWNERS, none of DENY-MODE, size <= MAX-BYTES. Content is never
# printed: the only output is an exit status.
#
# Exit status: 0 copied; 10 symlinked/unsafe path component; 11 missing; 12 not a regular file
# (FIFO, device, directory, ...); 13 owner, mode or link count not allowed; 14 too large;
# 15 read/write error; 2 usage.

import errno
import os
import stat
import sys

EX_OK, EX_LINK, EX_MISSING, EX_TYPE, EX_POLICY, EX_SIZE, EX_IO, EX_USAGE = 0, 10, 11, 12, 13, 14, 15, 2


def main(argv):
    if len(argv) != 6:
        return EX_USAGE
    path, out, max_s, owners_s, deny_s = argv[1:]
    try:
        max_bytes = int(max_s, 10)
        owners = {int(u, 10) for u in owners_s.split(",") if u != ""}
        deny = int(deny_s, 8)
    except ValueError:
        return EX_USAGE
    if not path.startswith("/") or max_bytes < 0 or not owners or not out.startswith("/"):
        return EX_USAGE
    comps = [c for c in path.split("/") if c != ""]
    if not comps or any(c in (".", "..") for c in comps):
        return EX_LINK

    dflags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        dfd = os.open("/", dflags)
    except OSError:
        return EX_IO
    try:
        for c in comps[:-1]:
            try:
                nfd = os.open(c, dflags, dir_fd=dfd)
            except FileNotFoundError:
                return EX_MISSING
            except OSError:
                # ELOOP (symlink), ENOTDIR (symlink or file), EACCES, ...
                return EX_LINK
            os.close(dfd)
            dfd = nfd
        name = comps[-1]
        try:
            pre = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return EX_MISSING
        except OSError:
            return EX_IO
        if stat.S_ISLNK(pre.st_mode):
            return EX_LINK
        if not stat.S_ISREG(pre.st_mode):
            return EX_TYPE
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            return EX_MISSING
        except OSError as e:
            return EX_LINK if e.errno in (errno.ELOOP, errno.ENOTDIR) else EX_IO
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return EX_TYPE
        if (st.st_dev, st.st_ino) != (pre.st_dev, pre.st_ino):
            return EX_LINK
        if st.st_nlink != 1 or st.st_uid not in owners or (st.st_mode & deny) != 0:
            return EX_POLICY
        if st.st_size > max_bytes:
            return EX_SIZE
        chunks = []
        total = 0
        while True:
            try:
                b = os.read(fd, min(65536, max_bytes + 1 - total))
            except BlockingIOError:
                return EX_TYPE
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                return EX_SIZE
            chunks.append(b)
    except OSError:
        return EX_IO
    finally:
        os.close(fd)
    try:
        ofd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        return EX_IO
    try:
        for b in chunks:
            view = memoryview(b)
            while view:
                n = os.write(ofd, view)
                view = view[n:]
    except OSError:
        return EX_IO
    finally:
        os.close(ofd)
    return EX_OK


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception:  # never a traceback (it could quote a path or value)
        sys.exit(EX_IO)
