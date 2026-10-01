"""Windows-only file checks for the two places that read security-sensitive files (Stage 14).

On Linux and macOS, private keys and model artefacts are read with POSIX guarantees:
``O_NOFOLLOW`` file descriptors, permission bits, and (for artefacts) every file opened
relative to one directory handle. Windows Python has none of these: ``os.open`` cannot open
a directory, ``dir_fd`` is unsupported, ``O_NOFOLLOW`` does not exist, and the permission
bits it reports do not describe NTFS access control.

:func:`open_checked` is the Windows replacement, used **only** when :data:`IS_WINDOWS` is
true (it is never reached on POSIX). It keeps every check that has a Windows meaning:

* the path must not be a symlink, junction or other reparse point (``lstat``);
* it must be a regular file with a single link (hard links refused);
* the file opened must be the file that was checked (same volume, file index and size),
  which narrows, but does not close, the window between the check and the open.

What it cannot give is the POSIX guarantee that every file in an artefact directory is
opened relative to one directory handle. On Windows a writer to the model directory could
in principle swap a file between the check and the open; the digest and signature checks
on the bytes actually read still catch any change to content. NTFS permissions on the
directory (normally the user profile) are the filesystem control. See TRUST_CHAIN.md (Windows).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO

IS_WINDOWS = os.name == "nt"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class UnsafeFileError(OSError):
    """The path is not a plain, singly linked regular file (or directory)."""


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def check_directory(path: Path) -> None:
    """Refuse a directory that is a symlink, a junction or not a directory at all."""
    info = os.lstat(path)
    if _is_link(info):
        raise UnsafeFileError(f"{path} is a symlink or junction")
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeFileError(f"{path} is not a directory")


def open_checked(path: Path) -> tuple[BinaryIO, os.stat_result]:
    """Open ``path`` for reading after refusing links; return the handle and its ``fstat``."""
    before = os.lstat(path)
    if _is_link(before):
        raise UnsafeFileError(f"{path} is a symlink or junction")
    if not stat.S_ISREG(before.st_mode):
        raise UnsafeFileError(f"{path} is not a regular file")
    if before.st_nlink > 1:
        raise UnsafeFileError(f"{path} has {before.st_nlink} hard links")
    handle = open(path, "rb")  # noqa: SIM115 - returned to the caller, who closes it
    after = os.fstat(handle.fileno())
    if (after.st_dev, after.st_ino, after.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ) or not stat.S_ISREG(after.st_mode):
        handle.close()
        raise UnsafeFileError(f"{path} changed between the check and the open")
    return handle, after


def unchanged_since(path: Path, info: os.stat_result) -> bool:
    """True when ``path`` still has the size and modification time read into ``info``."""
    now = os.lstat(path)
    return (now.st_size, now.st_mtime_ns, now.st_ino) == (
        info.st_size,
        info.st_mtime_ns,
        info.st_ino,
    )
