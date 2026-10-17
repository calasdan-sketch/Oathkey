"""Secret storage: .env handling with locked-down permissions.

Rules:
- The key value is NEVER printed, logged, or returned to callers.
- The file is private from its first byte: the content is written to a
  randomly named temp file created with O_CREAT|O_EXCL and mode 0o600 in
  the same directory, fsync'd, then atomically renamed over the target.
  There is no moment at which a partial or world-readable .env exists,
  and a pre-planted file (or link) at a guessable name is never written
  through.
- Existing keys are updated in place; nothing else in the file moves.
- On Windows, mode bits are meaningless; the file's ACL is reduced to
  the current user instead (best effort, via icacls).
"""

from __future__ import annotations

import getpass
import os
import re
import subprocess
import tempfile

from .recipes import ENV_VAR_RE

OWNER_ONLY = 0o600


def _windows_owner_only(path: str) -> bool:
    """Replace the file's ACL with 'current user: full control' only.
    Returns True on success; never raises (Windows ACLs are best effort)."""
    try:
        user = os.environ.get("USERNAME") or getpass.getuser()
    except Exception:  # pragma: no cover - getuser can fail in odd sessions
        return False
    try:
        proc = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:(F)"],
            capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _lock_down(path: str) -> None:
    """Owner-only permissions: chmod 0600 everywhere (on Windows that
    only clears the read-only bit, so the ACL is restricted too)."""
    os.chmod(path, OWNER_ONLY)
    if os.name == "nt":
        _windows_owner_only(path)


def read_env(path: str) -> tuple[list[str], dict[str, int]]:
    """Return (lines, {VAR: line_index}). Missing file -> ([], {})."""
    if not os.path.isfile(path):
        return [], {}
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    index: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) not in index:
            index[m.group(1)] = i
    return lines, index


def write_private(path: str, text: str) -> None:
    """Atomically replace `path` with `text`, private from the start.

    mkstemp() picks an unguessable name in the target directory and
    creates it with O_CREAT|O_EXCL and mode 0o600, so nobody can pre-create
    the file we write through and no reader ever sees a half-written or
    world-readable key. On any failure the temp file is removed and the
    old `path` is left exactly as it was.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    base = os.path.basename(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{base}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, OWNER_ONLY)  # mkstemp already did; belt and braces
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _lock_down(path)


def store_key(env_var: str, key: str, env_file: str = ".env") -> tuple[str, bool]:
    """Write key to env_file as ENV_VAR=<key> with owner-only permissions.

    Returns (path, updated_existing). The key value never leaves this
    function except into the file.

    Refuses a malformed env_var (anything but a shell identifier):
    writing it verbatim would let a hostile recipe inject extra lines
    into the user's .env. Recipe validation normally catches this at
    load time; this is the last line of defense.
    """
    if not isinstance(env_var, str) or not ENV_VAR_RE.match(env_var):
        raise ValueError(
            f"refusing to write invalid env var name to {env_file}: "
            f"{env_var!r}")
    existed = os.path.isfile(env_file)
    lines, index = read_env(env_file)
    entry = f"{env_var}={key}"
    if env_var in index:
        lines[index[env_var]] = entry
        updated = True
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(entry)
        updated = False
    write_private(env_file, "\n".join(lines) + "\n")
    # Scrub our own reference.
    del entry
    return env_file, (updated and existed)


def file_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777


def describe_protection() -> str:
    """Human wording for the success line, honest per platform."""
    if os.name == "nt":
        return "owner-only ACL"
    return "mode 0600"

