"""Filesystem and parsing helpers shared by the baseline and audit engines."""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import stat
from typing import Any, Dict, Iterable, List, Optional, Tuple

_CHUNK = 1024 * 1024
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
_MAX_SAMPLE_ERRORS = 50

# sudoers treats "#include", "#includedir" and "#<uid>" as live syntax even
# though they start with a hash character.
_SUDOERS_LIVE_HASH = re.compile(r"^#(include|includedir)\b|^#\d+\s", re.IGNORECASE)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 digest of *path*, reading it in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_bytes(data: bytes) -> str:
    """Decode bytes losslessly enough for line-oriented comparison."""
    return data.decode("utf-8", errors="surrogateescape")


def mode_string(mode: int) -> str:
    """Format permission bits (including setuid/setgid/sticky) as 4 octal digits."""
    return "%04o" % stat.S_IMODE(mode)


def mode_int(record: Optional[Dict[str, Any]]) -> Optional[int]:
    """Parse the ``mode`` field of a record, or return ``None`` if unavailable."""
    if not record:
        return None
    try:
        return int(record["mode"], 8)
    except (KeyError, TypeError, ValueError):
        return None


def _type_name(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def inspect_path(
    path: str, hash_content: bool = True, capture: bool = False
) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Collect metadata (and optionally a SHA-256) for *path*.

    Returns ``(record, data)``. ``record["exists"]`` is ``True``, ``False`` or
    ``None`` (``None`` means the state could not be determined, e.g. EACCES).
    ``data`` holds the file bytes only when *capture* is set, the file is a
    regular file below ``MAX_CAPTURE_BYTES`` and it could be read; the hash is
    then computed from those same bytes so hash and content never disagree.
    """
    try:
        lst = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return {"exists": False}, None
    except OSError as exc:
        return {"exists": None, "error": exc.strerror or str(exc)}, None

    is_link = stat.S_ISLNK(lst.st_mode)
    try:
        st = os.stat(path) if is_link else lst
    except FileNotFoundError:
        return (
            {
                "exists": True,
                "type": "broken-symlink",
                "symlink": True,
                "link_target": os.readlink(path),
                "mode": mode_string(lst.st_mode),
                "uid": lst.st_uid,
                "gid": lst.st_gid,
            },
            None,
        )
    except OSError as exc:
        return {"exists": None, "error": exc.strerror or str(exc)}, None

    record: Dict[str, Any] = {
        "exists": True,
        "type": _type_name(st.st_mode),
        "mode": mode_string(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }
    if is_link:
        record["symlink"] = True
        record["link_target"] = os.readlink(path)

    data: Optional[bytes] = None
    if hash_content and record["type"] == "file":
        try:
            if capture and st.st_size <= MAX_CAPTURE_BYTES:
                with open(path, "rb") as handle:
                    data = handle.read()
                record["sha256"] = hashlib.sha256(data).hexdigest()
            else:
                record["sha256"] = sha256_file(path)
        except OSError as exc:
            data = None
            record["hash_error"] = exc.strerror or str(exc)
    return record, data


def list_directory_files(directory: str) -> Tuple[List[str], Optional[str]]:
    """List non-directory entries of *directory* (sorted, non-recursive).

    Returns ``(paths, error)``. A missing directory is not an error (empty
    list, ``None``); an unreadable one yields an error message so callers can
    avoid reporting its contents as "removed".
    """
    try:
        names = sorted(os.listdir(directory))
    except (FileNotFoundError, NotADirectoryError):
        return [], None
    except OSError as exc:
        return [], "%s: %s" % (directory, exc.strerror or exc)
    paths: List[str] = []
    for name in names:
        full = os.path.join(directory, name)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode):
            continue
        paths.append(full)
    return paths, None


def parse_active_lines(text: str, sudoers: bool = False) -> List[str]:
    """Return non-empty, non-comment lines (whitespace-stripped)."""
    lines: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") and not (sudoers and _SUDOERS_LIVE_HASH.match(line)):
            continue
        lines.append(line)
    return lines


def parse_passwd(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse /etc/passwd content into ``{name: {uid, gid, home, shell}}``."""
    accounts: Dict[str, Dict[str, Any]] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        name = parts[0]
        try:
            uid = int(parts[2])
            gid = int(parts[3])
        except ValueError:
            continue
        key = name
        dup = 1
        while key in accounts:  # duplicate usernames are themselves suspicious
            dup += 1
            key = "%s#dup%d" % (name, dup)
        accounts[key] = {"uid": uid, "gid": gid, "home": parts[5], "shell": parts[6]}
    return accounts


def _is_excluded(path: str, excludes: Iterable[str]) -> bool:
    for ex in excludes:
        if path == ex or path.startswith(ex.rstrip(os.sep) + os.sep):
            return True
    return False


def scan_suid_sgid(
    roots: Iterable[str], excludes: Iterable[str]
) -> Tuple[Dict[str, Dict[str, Any]], int, List[str]]:
    """Find regular files with the setuid or setgid bit under *roots*.

    Symlinks are never followed. Returns ``(entries, error_count, samples)``
    where *samples* holds the first few access errors encountered.
    """
    norm_excludes = [os.path.normpath(e) for e in excludes]
    found: Dict[str, Dict[str, Any]] = {}
    error_count = 0
    samples: List[str] = []

    def on_error(exc: OSError) -> None:
        nonlocal error_count
        error_count += 1
        if len(samples) < _MAX_SAMPLE_ERRORS:
            samples.append("%s: %s" % (exc.filename, exc.strerror or exc))

    for root in roots:
        root = os.path.normpath(root)
        for dirpath, dirnames, filenames in os.walk(
            root, topdown=True, onerror=on_error, followlinks=False
        ):
            if _is_excluded(dirpath, norm_excludes):
                dirnames[:] = []
                continue
            dirnames[:] = [
                d for d in dirnames if not _is_excluded(os.path.join(dirpath, d), norm_excludes)
            ]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if full in found:
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if not st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    continue
                entry: Dict[str, Any] = {
                    "mode": mode_string(st.st_mode),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "size": st.st_size,
                    "suid": bool(st.st_mode & stat.S_ISUID),
                    "sgid": bool(st.st_mode & stat.S_ISGID),
                }
                try:
                    entry["sha256"] = sha256_file(full)
                except OSError as exc:
                    entry["hash_error"] = exc.strerror or str(exc)
                found[full] = entry
    return found, error_count, samples
