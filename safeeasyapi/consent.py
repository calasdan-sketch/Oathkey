"""The terminal route's permission for agent-driven key capture, signed so that a file edit cannot forge it.

IMPORTANT - what this is and is not. The permission a person gives in the
confirmation WINDOW (dialog.py) is kept only in the memory of the running MCP
server, for that session, and is never written here. This file holds only the
permission given with the terminal command `safeeasyapi allow-agent`, which
survives restarts. It is ADVISORY: a program running as the same user can read
the secret that signs it (DPAPI and the keychain protect against other users
and other machines, not against another process of yours) and a terminal can
be faked by a pseudo-terminal. The window is a real gate only against an agent
that cannot run code as the same user; nothing here stops one that can.

Where: ~/.safeeasyapi/agent-consent.json, in the home folder from the system's
user database (not $HOME, which a launcher can change). What: the list of
(project, service) grants, a counter and an HMAC-SHA256 over both. The key is
a random per-user secret kept in the best place the system offers: a
DPAPI-protected blob, the macOS keychain, the Linux Secret Service
(secret-tool), else a 0600 file marked ADVISORY. The counter is kept next to
the key and goes up on every grant and revoke, so an OLD copy of the file (an
undone grant put back) does not verify. A file that does not verify counts as
NO grants (fail closed).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

from . import safeexec

VERSION = 3
DIR_NAME = ".safeeasyapi"
FILE_NAME = "agent-consent.json"
SECRET_FILE = "consent.key"
LABEL = "safeeasyapi-consent"


def home_dir() -> str:
    """The user's home folder from the system's user database, not from
    environment variables an agent's launcher may have changed."""
    if os.name == "posix":
        try:
            import pwd
            return pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError, OSError):
            pass
    return os.path.expanduser("~")


def consent_dir() -> str:
    return os.path.join(home_dir(), DIR_NAME)


def consent_path() -> str:
    return os.path.join(consent_dir(), FILE_NAME)


# ------------------------------------------------------------- the secret

class FileSecret:
    kind = "file"
    advisory = True

    def __init__(self, path: str | None = None):
        self.path = path

    def _p(self) -> str:
        return self.path or os.path.join(consent_dir(), SECRET_FILE)

    def load(self) -> bytes | None:
        try:
            with open(self._p(), "rb") as f:
                data = f.read(256)
        except OSError:
            return None
        return data if len(data) >= 16 else None

    def save(self, secret: bytes) -> None:
        path = self._p()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _write_private(path, secret)


def _write_private(path: str, data: bytes) -> None:
    """Create `path` private (0600) without a window in which another process
    could have made it first: O_EXCL when it is new, else a private temporary
    file moved over it."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            _replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class DpapiSecret(FileSecret):
    """The secret in a file, encrypted for this Windows user (DPAPI)."""
    kind = "dpapi"
    advisory = False

    def _p(self) -> str:
        return self.path or os.path.join(consent_dir(), SECRET_FILE + ".dpapi")

    @staticmethod
    def _crypt(data: bytes, protect: bool) -> bytes:
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        entropy_bytes = b"safeeasyapi-consent"
        buf = ctypes.create_string_buffer(data, len(data))
        ent = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes))
        blob_in = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_ent = Blob(len(entropy_bytes), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
        blob_out = Blob()
        fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
        if not fn(ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None, 0,
                  ctypes.byref(blob_out)):
            raise OSError("DPAPI refused")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    def load(self) -> bytes | None:
        try:
            with open(self._p(), "rb") as f:
                blob = f.read(4096)
            return self._crypt(blob, False)
        except (OSError, ValueError):
            return None

    def save(self, secret: bytes) -> None:
        path = self._p()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _write_private(path, self._crypt(secret, True))


class CommandSecret:
    """The secret in the OS keychain (macOS `security`) or the Secret Service
    (`secret-tool`), reached through its command line tool, found only in
    system folders and run with a fixed environment (safeexec.py)."""
    advisory = False

    def __init__(self, kind: str, run=safeexec.run, find=safeexec.find):
        self.kind = kind
        self.run = run
        self.find = find

    def _tool(self) -> str:
        path = self.find("security" if self.kind == "keychain" else "secret-tool")
        if not path:
            raise OSError("the keychain tool is not available in a trusted place")
        return path

    def load(self) -> bytes | None:
        try:
            tool = self._tool()
            argv = ([tool, "find-generic-password", "-a", LABEL, "-s", LABEL, "-w"]
                    if self.kind == "keychain" else
                    [tool, "lookup", "service", LABEL, "kind", "consent"])
            done = self.run(argv, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode != 0:
            return None
        try:
            return bytes.fromhex(done.stdout.decode("ascii", "replace").strip())
        except ValueError:
            return None

    def save(self, secret: bytes) -> None:
        text = secret.hex()
        tool = self._tool()
        if self.kind == "keychain":
            argv, data = [tool, "add-generic-password", "-U", "-a", LABEL, "-s", LABEL,
                          "-w", text], None
        else:
            argv, data = [tool, "store", "--label=" + LABEL, "service", LABEL,
                          "kind", "consent"], text.encode("ascii")
        done = self.run(argv, input=data, capture_output=True, timeout=30)
        if done.returncode != 0:
            raise OSError("the keychain refused the consent secret")


class ChainSecret:
    """A keychain first; when it cannot save (locked, no session bus, refused)
    the 0600 file is used instead, so a grant never fails for want of a
    keyring. Of the two readings the NEWER (higher counter) wins."""

    def __init__(self, primary, fallback):
        self.primary, self.fallback, self.used = primary, fallback, primary

    @property
    def kind(self) -> str:
        return self.used.kind

    @property
    def advisory(self) -> bool:
        return self.used.advisory

    def load(self) -> bytes | None:
        best, store = None, self.primary
        for candidate in (self.primary, self.fallback):
            try:
                blob = candidate.load()
            except Exception:
                blob = None
            if blob and (best is None or split(blob)[1] > split(best)[1]):
                best, store = blob, candidate
        self.used = store
        return best

    def save(self, secret: bytes) -> None:
        try:
            self.primary.save(secret)
            self.used = self.primary
        except Exception:
            self.fallback.save(secret)
            self.used = self.fallback


def pick_secret_store(platform: str | None = None, which=safeexec.find):
    platform = platform or sys.platform
    if platform == "win32":
        return DpapiSecret()
    if platform == "darwin" and which("security"):
        return ChainSecret(CommandSecret("keychain", find=which), FileSecret())
    if which("secret-tool"):
        return ChainSecret(CommandSecret("secret-tool", find=which), FileSecret())
    return FileSecret()


_STORE = None


def secret_store():
    global _STORE
    if _STORE is None:
        _STORE = pick_secret_store()
    return _STORE


def set_secret_store(store) -> None:
    """For tests (and callers that know better)."""
    global _STORE
    _STORE = store


def integrity() -> str:
    """How well the consent file is protected here, in a few words."""
    store = secret_store()
    return store.kind + (" (advisory: a plain file)" if store.advisory else "")


# ---------------------------------------------------------------- the file

def split(blob: bytes) -> tuple[bytes, int]:
    """(HMAC key, counter) from what the secret store holds: 32 key bytes then
    an 8-byte counter. A shorter blob has counter 0."""
    if len(blob) >= 40:
        return blob[:32], int.from_bytes(blob[32:40], "big")
    return blob, 0


def pack(key: bytes, counter: int) -> bytes:
    return key[:32].ljust(32, b"\0") + counter.to_bytes(8, "big")


def _canonical(grants: list, counter: int) -> bytes:
    return json.dumps({"version": VERSION, "counter": counter, "grants": grants},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mac(grants: list, counter: int, key: bytes) -> str:
    return hmac.new(key, _canonical(grants, counter), hashlib.sha256).hexdigest()


def read_grants(path: str | None = None, store=None) -> tuple[list[dict], str]:
    """(grants, problem). `problem` is "" when the file is fine, "missing" when
    there is none, else "corrupt" / "forged" / "stale" / "no secret". Anything
    wrong gives NO grants: a file that does not verify is not consent."""
    store = store or secret_store()
    try:
        with open(path or consent_path(), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [], "missing"
    except (OSError, ValueError, RecursionError):
        return [], "corrupt"
    if not isinstance(data, dict) or data.get("version") != VERSION \
            or not isinstance(data.get("grants"), list) or not isinstance(data.get("mac"), str) \
            or not isinstance(data.get("counter"), int) or isinstance(data.get("counter"), bool):
        return [], "corrupt"
    blob = store.load()
    if not blob:
        return [], "no secret"
    key, counter = split(blob)
    if not hmac.compare_digest(_mac(data["grants"], data["counter"], key), data["mac"]):
        return [], "forged"
    if data["counter"] != counter:
        return [], "stale"                      # an older (or newer) copy of the file
    return [g for g in data["grants"] if isinstance(g, dict)
            and isinstance(g.get("project"), str) and isinstance(g.get("service"), str)], ""


def _replace(src: str, dst: str) -> None:
    for attempt in range(8):                    # Windows: a scanner may hold the file a moment
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == 7:
                raise
            time.sleep(0.05 * (attempt + 1))


def _write(grants: list, path: str, key: bytes, counter: int) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".consent-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "counter": counter, "grants": grants,
                       "mac": _mac(grants, counter, key)}, f, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        _replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def project_key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def consent_for(project: str, service: str, path: str | None = None, store=None) -> dict | None:
    grants, _ = read_grants(path, store)
    for g in grants:
        if g["service"] == service and _same(g["project"], project):
            return g
    return None


def grants_for(project: str, path: str | None = None, store=None) -> list[dict]:
    return [g for g in read_grants(path, store)[0] if _same(g["project"], project)]


_LOCK = threading.RLock()


class _FolderLock:
    """One writer at a time, across threads and processes: an O_EXCL lock
    file next to the consent file (stale after 30 seconds)."""

    def __init__(self, folder: str):
        self.path = os.path.join(folder, ".lock")

    def __enter__(self):
        _LOCK.acquire()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        end = time.monotonic() + 10
        while True:
            try:
                os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
                return self
            except FileExistsError:
                try:
                    if time.time() - os.stat(self.path).st_mtime > 30:
                        os.unlink(self.path)
                        continue
                except OSError:
                    pass
                if time.monotonic() > end:
                    _LOCK.release()
                    raise OSError("the consent file is locked by another process")
                time.sleep(0.02)
            except BaseException:
                _LOCK.release()
                raise

    def __exit__(self, *exc):
        try:
            os.unlink(self.path)
        except OSError:
            pass
        _LOCK.release()


def _commit(grants: list, path: str, store) -> None:
    """Save the new counter with the key FIRST, then the file: a crash in
    between leaves a file that does not verify (no consent), never a stale
    one that does."""
    blob = store.load()
    key = split(blob)[0] if blob else os.urandom(32)
    counter = (split(blob)[1] if blob else 0) + 1
    store.save(pack(key, counter))
    _write(grants, path, key, counter)
    try:
        os.unlink(path + ".bak")                # no old copies lying around
    except OSError:
        pass


def grant(project: str, service: str, history_ok: bool = False, path: str | None = None,
          env_file: str | None = None, store=None,
          now: datetime.datetime | None = None) -> None:
    path = path or consent_path()
    store = store or secret_store()
    with _FolderLock(os.path.dirname(path)):
        grants, _problem = read_grants(path, store)     # a file that does not verify starts clean
        grants = [g for g in grants if not (g["service"] == service and _same(g["project"], project))]
        stamp = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
        entry = {"project": os.path.realpath(project), "service": service,
                 "clipboard_history_ok": bool(history_ok), "granted": stamp.isoformat()}
        if env_file:
            entry["env_file"] = env_file
        grants.append(entry)
        _commit(grants, path, store)


def revoke(project: str, service: str | None = None, path: str | None = None, store=None) -> int:
    path = path or consent_path()
    store = store or secret_store()
    with _FolderLock(os.path.dirname(path)):
        grants, _ = read_grants(path, store)
        keep = [g for g in grants if not (_same(g["project"], project)
                                          and (service is None or g["service"] == service))]
        if len(keep) != len(grants):
            _commit(keep, path, store)
        return len(grants) - len(keep)
