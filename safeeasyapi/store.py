"""Secret storage: .env handling with locked-down permissions.

Rules:
- The key value is NEVER printed, logged, or returned to callers.
- The file is private from its first byte: the content is written to a
  randomly named temp file created with O_CREAT|O_EXCL and mode 0o600 in
  the same directory, fsync'd, then atomically renamed over the target.
  There is no moment at which a partial or world-readable .env exists,
  and a pre-planted file (or link) at a guessable name is never written
  through.
- Existing keys are updated in place (``export KEY=`` lines included);
  nothing else in the file moves.
- Values are written so that every dotenv reader (python-dotenv, Node
  dotenv, docker compose, a shell `source`) gets the whole key back: a
  value that is not plain ``[A-Za-z0-9_.+/=:-]`` is double-quoted with
  ``"`` and ``\\`` escaped, because an unquoted ``#`` or space would
  otherwise truncate it silently.
- On Windows, mode bits are meaningless; the file's ACL is reduced to
  the current user instead (best effort, via icacls) — and the success
  line says so honestly when that did not work.
"""

from __future__ import annotations

import dataclasses
import getpass
import os
import re
import subprocess
import tempfile

from .recipes import ENV_VAR_RE

OWNER_ONLY = 0o600

# Characters that are safe unquoted in every dotenv dialect we know of.
_PLAIN_VALUE_RE = re.compile(r"^[A-Za-z0-9_.+/=:-]+$")

# `KEY=` or `export KEY=`; group 1 is the optional export prefix.
_ASSIGN_RE = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=")

PROTECTION_POSIX = "mode 0600"
PROTECTION_WINDOWS = "owner-only ACL"
PROTECTION_WINDOWS_FAILED = ("could not restrict ACL - icacls failed; the file "
                             "has the folder's default permissions")


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


def _lock_down(path: str) -> bool:
    """Owner-only permissions: chmod 0600 everywhere (on Windows that
    only clears the read-only bit, so the ACL is restricted too).
    Returns True when the protection this platform promises is in place."""
    os.chmod(path, OWNER_ONLY)
    if os.name == "nt":
        return _windows_owner_only(path)
    return True


def describe_protection(protected: bool = True) -> str:
    """Human wording for the success line, honest per platform AND per
    outcome: on Windows a failed `icacls` must not be reported as an
    owner-only ACL."""
    if os.name == "nt":
        return PROTECTION_WINDOWS if protected else PROTECTION_WINDOWS_FAILED
    return PROTECTION_POSIX


def quote_value(value: str) -> str:
    """The on-disk form of a value: bare when it is plain, otherwise
    double-quoted with `"` and `\\` escaped (the common dotenv rule)."""
    if value and _PLAIN_VALUE_RE.match(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_value(raw: str) -> str:
    """Read a value back the way dotenv readers do: a double-quoted value
    is unescaped; a single-quoted one is literal; a bare value ends at the
    first ` #` comment and is stripped."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"':
        end = _closing_quote(s)
        body = s[1:end]
        return re.sub(r'\\(["\\])', r"\1", body)
    if len(s) >= 2 and s[0] == "'" and s.endswith("'"):
        return s[1:-1]
    return re.split(r"\s+#", s, maxsplit=1)[0].strip()


def _closing_quote(s: str) -> int:
    """Index of the closing unescaped `"` in s (which starts with `"`),
    or len(s) when it is missing."""
    i = 1
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == '"':
            return i
        i += 1
    return len(s)


def read_env(path: str) -> tuple[list[str], dict[str, int]]:
    """Return (lines, {VAR: line_index}). Missing file -> ([], {}).
    `export VAR=...` lines count as definitions of VAR."""
    if not os.path.isfile(path):
        return [], {}
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    index: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = _ASSIGN_RE.match(line)
        if m and m.group(2) not in index:
            index[m.group(2)] = i
    return lines, index


def load_env(path: str) -> dict[str, str]:
    """Parse a .env file into {VAR: value} (quoted values decoded). For
    tests and tooling — the CLI itself never reads keys back into memory
    except to hand them to a child process."""
    lines, index = read_env(path)
    values: dict[str, str] = {}
    for var, i in index.items():
        m = _ASSIGN_RE.match(lines[i])
        values[var] = parse_value(lines[i][m.end():])
    return values


def write_private(path: str, text: str) -> bool:
    """Atomically replace `path` with `text`, private from the start.

    mkstemp() picks an unguessable name in the target directory and
    creates it with O_CREAT|O_EXCL and mode 0o600, so nobody can pre-create
    the file we write through and no reader ever sees a half-written or
    world-readable key. On any failure the temp file is removed and the
    old `path` is left exactly as it was. The parent directory is created
    when missing. Returns whether the platform's protection (mode 0600 /
    owner-only ACL) is fully in place.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
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
    return _lock_down(path)


@dataclasses.dataclass
class Stored:
    path: str
    updated: bool          # an existing entry was replaced
    protected: bool        # mode 0600 / owner-only ACL fully applied

    @property
    def protection(self) -> str:
        return describe_protection(self.protected)


def store_key_result(env_var: str, key: str, env_file: str = ".env") -> Stored:
    """Write key to env_file as ENV_VAR=<key> (quoted when needed) with
    owner-only permissions; returns what happened. The key value never
    leaves this function except into the file.

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
    value = quote_value(key)
    if env_var in index:
        prefix = _ASSIGN_RE.match(lines[index[env_var]]).group(1)
        lines[index[env_var]] = f"{prefix}{env_var}={value}"  # keeps `export`
        updated = True
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"{env_var}={value}")
        updated = False
    protected = write_private(env_file, "\n".join(lines) + "\n")
    # Scrub our own reference.
    del value
    return Stored(env_file, updated and existed, protected)


def store_key(env_var: str, key: str, env_file: str = ".env") -> tuple[str, bool]:
    """Compatibility form of store_key_result(): (path, updated_existing)."""
    r = store_key_result(env_var, key, env_file)
    return r.path, r.updated


def remove_key(env_var: str, env_file: str = ".env") -> bool:
    """Delete ENV_VAR's line from env_file (for `safeeasyapi forget`).
    Returns True when a line was removed. The rest of the file is kept
    byte-for-byte; the file stays private."""
    lines, index = read_env(env_file)
    if env_var not in index:
        return False
    del lines[index[env_var]]
    write_private(env_file, ("\n".join(lines) + "\n") if lines else "")
    return True


def file_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777
