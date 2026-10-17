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
  nothing else in the file moves - not even a byte of it. A variable set
  more than once is updated on its LAST line - the one python-dotenv,
  docker compose and a shell ``source`` end up using - and the earlier
  lines are left alone; ``forget`` removes every one of them. Every
  other line comes back out exactly as it went in: a Windows cp1252 file
  with an accented comment stays cp1252 (bytes that are not UTF-8
  survive through ``surrogateescape``), and every line keeps its own
  line ending - a CRLF file stays CRLF, an LF file stays LF. The line we
  add or change takes the file's own style, and a missing last newline
  is added in that style.
- A ``.env`` that is a symbolic link is refused (``refuse_link``): never
  written through, never silently replaced. So is a file that is not plain
  text (UTF-16 from PowerShell's ``>``), because appending UTF-8 to it
  would wreck it. Both refusals change nothing and say why.
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

import collections
import dataclasses
import errno
import getpass
import os
import re
import stat
import subprocess
import tempfile

from .recipes import ENV_VAR_RE

OWNER_ONLY = 0o600

# The file is UTF-8 (python-dotenv, Node dotenv and docker compose all read
# it that way), but one saved by Notepad on a Windows code page is not. Its
# other bytes must come back out untouched, so decoding maps every byte that
# is not UTF-8 to a lone surrogate and encoding maps it straight back: the
# round trip is exact for any input.
_ENCODING = "utf-8"
_UNDECODABLE = "surrogateescape"

# Characters that are safe unquoted in every dotenv dialect we know of.
_PLAIN_VALUE_RE = re.compile(r"^[A-Za-z0-9_.+/=:-]+$")

# `KEY=` or `export KEY=`; group 1 is everything before the name: an optional
# byte-order mark (Windows editors and PowerShell's `Out-File -Encoding utf8`
# put one at the very start of a UTF-8 file, and without this the first line
# is never recognised - a second ACME_API_KEY= line gets added instead of the
# first one being updated), indentation and the optional `export`. Because
# the whole prefix is written back unchanged, the mark stays where it was.
_ASSIGN_RE = re.compile(
    r"^(\ufeff?\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=")

# A line ending is CRLF, LF or a lone CR (what python-dotenv and Node dotenv
# both accept) and nothing else: str.splitlines() would also cut at \x0c,
# \x1c-\x1e, \x85 and U+2028/9 and then rewrite those lines with "\n".
_EOL_RE = re.compile(r"\r\n|\n|\r")

PROTECTION_POSIX = "mode 0600"
PROTECTION_WINDOWS = "owner-only ACL"
PROTECTION_WINDOWS_FAILED = ("could not restrict ACL - icacls failed; the file "
                             "has the folder's default permissions")

LINK_REASON = ("it is a link to another file, so safeeasyapi will not edit it "
               "- delete the link, or point --env-file at the real file")
NOT_TEXT_REASON = ("it is not a plain UTF-8 text file (Windows PowerShell's > "
                   "saves UTF-16), so safeeasyapi will not edit it - save it "
                   "as UTF-8 first")


class EnvFileRefused(OSError):
    """The .env file is one safeeasyapi will not edit: a link, or not plain
    text. Nothing was changed. ``strerror`` is a single plain-language
    sentence with the reason and the way out; ``filename`` is the path.
    An OSError so every existing "could not save" handler already copes."""

    def __init__(self, path: str, reason: str):
        super().__init__(errno.EINVAL, reason, path)


def refuse_link(path: str) -> None:
    """Raise EnvFileRefused when `path` is a symbolic link (a dangling one
    too). Called before anything is read or written.

    Why refuse - rather than write through the link, or replace it:
    - A link can point anywhere: another project's .env, ~/.ssh/config, a
      system file. A cloned repository can ship a `.env` link as a trap.
      Writing "through" it would put the key somewhere the person never
      looked at, and reading through it would copy the target's contents
      into this folder.
    - Replacing it (all that os.replace() can do to a link) silently breaks
      whatever the link was for - a shared secrets file, a dotfile manager -
      and leaves the other files that rely on it without the new key.
    - Allowing "links that stay inside the same folder" was rejected: it needs
      realpath() comparisons that differ per platform (case folding, 8.3
      names, junctions, bind mounts) to protect a case, a link to a sibling
      file, that is no easier to explain than naming that file in
      --env-file. A person who really wants a linked file edited can do
      exactly that, and it is their own explicit choice.
    So the rule is one line for every write: a link is stopped, with a
    message that says what to do instead."""
    if os.path.islink(path):
        raise EnvFileRefused(path, LINK_REASON)


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
    """Owner-only permissions on `path`, the regular file we just wrote:
    chmod 0600 (on Windows that only clears the read-only bit, so the ACL is
    restricted too). Returns True when the protection this platform
    promises is in place.

    chmod and icacls both FOLLOW a link, so a path that is not a regular
    file by now - something swapped a link in after our rename - is left
    alone (False): a permission change must never land on whatever a link
    points at. On POSIX the mode is set through a descriptor opened with
    O_NOFOLLOW, which closes the gap between the check and the change;
    Windows has no such handle for icacls, so the check is all it gets."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
    except OSError:
        return False
    if os.name == "nt":
        os.chmod(path, OWNER_ONLY)
        return _windows_owner_only(path)
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        os.fchmod(fd, OWNER_ONLY)
    finally:
        os.close(fd)
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


def _read_bytes(path: str) -> bytes:
    """The file's raw bytes; a missing file is empty."""
    if not os.path.isfile(path):
        return b""
    with open(path, "rb") as f:
        return f.read()


def _split_lines(text: str) -> list[list[str]]:
    """[[content, ending], ...] - the text cut at CRLF / LF / CR only, each
    line paired with its own ending ("" for a last line without one)."""
    entries: list[list[str]] = []
    pos = 0
    for m in _EOL_RE.finditer(text):
        entries.append([text[pos:m.start()], m.group()])
        pos = m.end()
    if pos < len(text):
        entries.append([text[pos:], ""])
    return entries


def _occurrences(entries: list[list[str]]) -> dict[str, list[int]]:
    """{VAR: [index of every line that assigns it, in file order]}."""
    found: dict[str, list[int]] = {}
    for i, (content, _ending) in enumerate(entries):
        m = _ASSIGN_RE.match(content)
        if m:
            found.setdefault(m.group(2), []).append(i)
    return found


def _index(entries: list[list[str]]) -> dict[str, int]:
    """{VAR: index of the line that takes effect}: the LAST one. python-dotenv,
    Node dotenv, docker compose and a shell `source` all let a later
    assignment of a variable override an earlier one, so that is the line
    that has to hold the key."""
    return {var: lines[-1] for var, lines in _occurrences(entries).items()}


def times(count: int) -> str:
    """How often, for the notes about a variable set more than once."""
    return "twice" if count == 2 else f"{count} times"


def _newline_style(entries: list[list[str]]) -> str:
    """The line ending this file uses: its most common one (the first seen
    wins a tie). A file with no line ending at all - new, empty, or a single
    unterminated line - gets LF, which every dotenv reader, docker compose
    and a shell `source` all take (a shell would keep a CR as part of the
    value)."""
    seen = [ending for _content, ending in entries if ending]
    if not seen:
        return "\n"
    return collections.Counter(seen).most_common(1)[0][0]


def _render(entries: list[list[str]], newline: str) -> str:
    """The text to write: every line exactly as it was, the last one ended
    in the file's own style."""
    if entries and not entries[-1][1]:
        entries[-1][1] = newline
    return "".join(content + ending for content, ending in entries)


def _load_for_edit(path: str) -> list[list[str]]:
    """The file's lines, ready to be edited - or EnvFileRefused when editing
    it would be unsafe. A missing file is no lines."""
    refuse_link(path)
    data = _read_bytes(path)
    if b"\x00" in data:
        # UTF-16/32 (or binary). Without this, decoding "works" and a UTF-8
        # line appended to a UTF-16 file silently wrecks it.
        raise EnvFileRefused(path, NOT_TEXT_REASON)
    return _split_lines(data.decode(_ENCODING, _UNDECODABLE))


def check_env_file(path: str) -> None:
    """Raise OSError (EnvFileRefused for a link or a non-text file) unless
    `path` can be edited. connect() runs this BEFORE the browser opens and
    a key is pasted, so a refusal costs the person nothing."""
    _load_for_edit(path)


def read_env(path: str) -> tuple[list[str], dict[str, int]]:
    """Return (lines, {VAR: line_index}). Missing file -> ([], {}).
    `export VAR=...` lines count as definitions of VAR; when a variable is
    set more than once the index is the last line, the one that takes
    effect. Lines come without their line endings; bytes that are not UTF-8
    show up as lone surrogates (they are only ever written back, never
    displayed)."""
    entries = _split_lines(_read_bytes(path).decode(_ENCODING, _UNDECODABLE))
    return [content for content, _ending in entries], _index(entries)


def load_env(path: str) -> dict[str, str]:
    """Parse a .env file into {VAR: value} (quoted values decoded; a variable
    set twice has the value of its last line, as in every dotenv reader).
    For tests and tooling — the CLI itself never reads keys back into memory
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

    A `path` that is a link is refused (EnvFileRefused): the callers check
    first, this is the last line of defence for any other caller. `text`
    goes out byte-exact: line endings are not translated, and bytes that
    came in as lone surrogates go back out as the bytes they were.
    """
    refuse_link(path)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    base = os.path.basename(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{base}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode(_ENCODING, _UNDECODABLE))
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
    duplicates: int = 0    # EARLIER lines that set the same variable (left as they were)

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
    entries = _load_for_edit(env_file)      # refuses a link / a non-text file
    newline = _newline_style(entries)
    lines = _occurrences(entries).get(env_var, [])
    value = quote_value(key)
    if lines:
        # The LAST assignment is the one every reader ends up using, so it
        # is the one that gets the key; earlier ones are not touched.
        i = lines[-1]
        prefix = _ASSIGN_RE.match(entries[i][0]).group(1)
        # keeps `export` and the line's own ending
        entries[i][0] = f"{prefix}{env_var}={value}"
        updated = True
    else:
        if entries and not entries[-1][1]:
            entries[-1][1] = newline        # end the last line before ours
        if entries and entries[-1][0].strip():
            entries.append(["", newline])
        entries.append([f"{env_var}={value}", ""])
        updated = False
    protected = write_private(env_file, _render(entries, newline))
    # Scrub our own reference.
    del value
    return Stored(env_file, updated and existed, protected,
                  max(len(lines) - 1, 0))


def store_key(env_var: str, key: str, env_file: str = ".env") -> tuple[str, bool]:
    """Compatibility form of store_key_result(): (path, updated_existing)."""
    r = store_key_result(env_var, key, env_file)
    return r.path, r.updated


def remove_key(env_var: str, env_file: str = ".env") -> int:
    """Delete every ENV_VAR= line from env_file (for `safeeasyapi forget`)
    and return how many there were: 0 (false) when the variable is not
    there. All of them, not just the one that takes effect - otherwise an
    older line would spring back and the "forgotten" key would still be
    live. The rest of the file is kept byte-for-byte (line endings
    included); the file stays private. A link or a non-text file is
    refused, as when saving (EnvFileRefused)."""
    entries = _load_for_edit(env_file)
    lines = _occurrences(entries).get(env_var)
    if not lines:
        return 0
    newline = _newline_style(entries)
    bom = lines[0] == 0 and entries[0][0].startswith("\ufeff")
    for i in reversed(lines):
        del entries[i]
    if bom and entries:
        # The byte-order mark belongs to the file, not to the line we took
        # out: the next line becomes the first and keeps it.
        entries[0][0] = "\ufeff" + entries[0][0]
    write_private(env_file, _render(entries, newline))
    return len(lines)


def file_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777
