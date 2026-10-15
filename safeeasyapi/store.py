"""Secret storage: .env handling with locked-down permissions.

Rules:
- The key value is NEVER printed, logged, or returned to callers.
- Files are created with mode 0o600 (owner read/write only).
- Existing keys are updated in place; nothing else in the file moves.
"""

from __future__ import annotations

import os
import re

from .recipes import ENV_VAR_RE


def _lock_down(path: str) -> None:
    os.chmod(path, 0o600)


def read_env(path: str) -> tuple[list[str], dict[str, int]]:
    """Return (lines, {VAR: line_index}). Missing file -> ([], {})."""
    if not os.path.isfile(path):
        return [], {}
    with open(path) as f:
        lines = f.read().splitlines()
    index: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m and m.group(1) not in index:
            index[m.group(1)] = i
    return lines, index


def store_key(env_var: str, key: str, env_file: str = ".env") -> tuple[str, bool]:
    """Write key to env_file as ENV_VAR=<key> with 0o600 perms.

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
    # Write via a temp file + rename so a crash never leaves a half key.
    tmp = env_file + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    _lock_down(tmp)
    os.replace(tmp, env_file)
    _lock_down(env_file)
    # Scrub our own reference.
    del entry
    return env_file, (updated and existed)


def file_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777
