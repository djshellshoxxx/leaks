# SPDX-License-Identifier: AGPL-3.0-or-later
#
# safe-read.py - race-free, size-capped reader for config-check inputs (AUD-RM2-DEP-24).
#
# Usage (called by config-check.sh only, as `python3 -I -S -B safe-read.py ...`):
#   safe-read.py ABS-PATH OUT MAX-BYTES OWNERS DENY-MODE
#       copy one input to OUT (created 0600, never through a symlink, truncated)
#   safe-read.py --md5 MAX-BYTES OWNERS DENY-MODE ABS-PATH...
#       print one line per path, in order: "OK <md5 hex>" or "ERR <status>" (paths and
#       content are never printed; dpkg records conffile digests as MD5)
#   MAX-BYTES  size cap; a larger file is refused
#   OWNERS     comma list of uids that may own the input
#   DENY-MODE  octal permission bits the input must not have (e.g. 022)
#
# Every path component is opened relative to its parent with openat semantics and
# O_NOFOLLOW (directories with O_PATH|O_DIRECTORY), starting at "/": a component swapped for a
# symlink after any earlier check fails with ELOOP/ENOTDIR instead of being followed. The input
# is checked with fstatat(AT_SYMLINK_NOFOLLOW) before the open (a FIFO or device node is never
# opened on purpose), opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY (a FIFO swapped in at the
# last moment cannot block), and the open descriptor is fstat-checked: regular file, the same
# inode as checked, one link, owner in OWNERS, none of DENY-MODE, size <= MAX-BYTES. Reads are
# capped at MAX-BYTES + 1. Content is never printed.
#
# Exit status (copy mode; also the <status> of --md5): 0 ok; 10 symlinked/swapped path
# component; 11 missing; 12 not a regular file (FIFO, device, directory, ...); 13 owner, mode
# or link count not allowed; 14 too large; 15 read/write error; 2 usage.

import errno
import hashlib
import os
import stat
import sys

EX_OK, EX_LINK, EX_MISSING, EX_TYPE, EX_POLICY, EX_SIZE, EX_IO, EX_USAGE = 0, 10, 11, 12, 13, 14, 15, 2


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def read_checked(path, max_bytes, owners, deny):
    """Return the bytes of `path` or raise Refused(status)."""
    if not path.startswith("/"):
        raise Refused(EX_USAGE)
    comps = [c for c in path.split("/") if c != ""]
    if not comps or any(c in (".", "..") for c in comps):
        raise Refused(EX_LINK)
    dflags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        dfd = os.open("/", dflags)
    except OSError:
        raise Refused(EX_IO) from None
    try:
        for c in comps[:-1]:
            try:
                nfd = os.open(c, dflags, dir_fd=dfd)
            except FileNotFoundError:
                raise Refused(EX_MISSING) from None
            except OSError:
                # ELOOP (symlink), ENOTDIR (symlink or file), EACCES, ...
                raise Refused(EX_LINK) from None
            os.close(dfd)
            dfd = nfd
        name = comps[-1]
        try:
            pre = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            raise Refused(EX_MISSING) from None
        except OSError:
            raise Refused(EX_IO) from None
        if stat.S_ISLNK(pre.st_mode):
            raise Refused(EX_LINK)
        if not stat.S_ISREG(pre.st_mode):
            raise Refused(EX_TYPE)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            raise Refused(EX_MISSING) from None
        except OSError as e:
            raise Refused(EX_LINK if e.errno in (errno.ELOOP, errno.ENOTDIR) else EX_IO) from None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(EX_TYPE)
        if (st.st_dev, st.st_ino) != (pre.st_dev, pre.st_ino):
            raise Refused(EX_LINK)
        if st.st_nlink != 1 or st.st_uid not in owners or (st.st_mode & deny) != 0:
            raise Refused(EX_POLICY)
        if st.st_size > max_bytes:
            raise Refused(EX_SIZE)
        chunks = []
        total = 0
        while True:
            try:
                b = os.read(fd, min(65536, max_bytes + 1 - total))
            except BlockingIOError:
                raise Refused(EX_TYPE) from None
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                raise Refused(EX_SIZE)
            chunks.append(b)
        return b"".join(chunks)
    except OSError:
        raise Refused(EX_IO) from None
    finally:
        os.close(fd)


def parse_policy(max_s, owners_s, deny_s):
    max_bytes = int(max_s, 10)
    owners = {int(u, 10) for u in owners_s.split(",") if u != ""}
    deny = int(deny_s, 8)
    if max_bytes < 0 or not owners:
        raise ValueError
    return max_bytes, owners, deny


def copy_mode(argv):
    if len(argv) != 6:
        return EX_USAGE
    path, out = argv[1], argv[2]
    try:
        max_bytes, owners, deny = parse_policy(argv[3], argv[4], argv[5])
    except ValueError:
        return EX_USAGE
    if not out.startswith("/"):
        return EX_USAGE
    try:
        data = read_checked(path, max_bytes, owners, deny)
    except Refused as r:
        return r.code
    try:
        ofd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        return EX_IO
    try:
        view = memoryview(data)
        while view:
            n = os.write(ofd, view)
            view = view[n:]
    except OSError:
        return EX_IO
    finally:
        os.close(ofd)
    return EX_OK


def md5_mode(argv):
    if len(argv) < 5:
        return EX_USAGE
    try:
        max_bytes, owners, deny = parse_policy(argv[2], argv[3], argv[4])
    except ValueError:
        return EX_USAGE
    lines = []
    for path in argv[5:]:
        try:
            data = read_checked(path, max_bytes, owners, deny)
            lines.append("OK " + hashlib.md5(data, usedforsecurity=False).hexdigest())
        except Refused as r:
            lines.append("ERR %d" % r.code)
    sys.stdout.write("".join(line + "\n" for line in lines))
    sys.stdout.flush()
    return EX_OK


def main(argv):
    if len(argv) >= 2 and argv[1] == "--md5":
        return md5_mode(argv)
    return copy_mode(argv)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception:  # never a traceback (it could quote a path or value)
        sys.exit(EX_IO)
