"""The person's permission for agent-driven key capture, kept so that a file edit cannot forge it.

Where: ~/.safeeasyapi/agent-consent.json, in the home folder from the system's
user database (not $HOME, which a launcher can change). What: the list of
(project, service) grants the person made, with an HMAC-SHA256 over the list.
The key for the HMAC is a random per-user secret kept in the best place the
system offers: Windows DPAPI-protected blob, the macOS keychain, the Linux
Secret Service (secret-tool), else a 0600 file marked ADVISORY.

What this stops: an agent that can write files or run shell commands editing
the consent file to give itself permission - without the secret the MAC does
not match, and a file that does not verify counts as NO grants (fail closed).
What it does not stop: a program running as the same user that reads the secret
too (DPAPI and the keychain protect against other users and other machines,
not against another process of yours). The real gate is that the grant is made
in a window of the operating system (dialog.py) or by a person at a terminal.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

VERSION = 2
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
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)


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
        blob = self._crypt(secret, True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.replace(tmp, path)


class CommandSecret:
    """The secret in the OS keychain (macOS `security`) or the Secret Service
    (`secret-tool`), reached through its command line tool."""
    advisory = False

    def __init__(self, kind: str, run=subprocess.run):
        self.kind = kind
        self.run = run

    def load(self) -> bytes | None:
        argv = (["security", "find-generic-password", "-a", LABEL, "-s", LABEL, "-w"]
                if self.kind == "keychain" else
                ["secret-tool", "lookup", "service", LABEL, "kind", "consent"])
        try:
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
        if self.kind == "keychain":
            argv, data = ["security", "add-generic-password", "-U", "-a", LABEL, "-s", LABEL,
                          "-w", text], None
        else:
            argv, data = ["secret-tool", "store", "--label=" + LABEL, "service", LABEL,
                          "kind", "consent"], text.encode("ascii")
        done = self.run(argv, input=data, capture_output=True, timeout=30)
        if done.returncode != 0:
            raise OSError("the keychain refused the consent secret")


def pick_secret_store(platform: str | None = None, which=shutil.which):
    platform = platform or sys.platform
    if platform == "win32":
        return DpapiSecret()
    if platform == "darwin" and which("security"):
        return CommandSecret("keychain")
    if which("secret-tool"):
        return CommandSecret("secret-tool")
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

def _canonical(grants: list) -> bytes:
    return json.dumps({"version": VERSION, "grants": grants}, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _mac(grants: list, secret: bytes) -> str:
    return hmac.new(secret, _canonical(grants), hashlib.sha256).hexdigest()


def read_grants(path: str | None = None, store=None) -> tuple[list[dict], str]:
    """(grants, problem). `problem` is "" when the file is fine, "missing" when
    there is none, else "corrupt" / "forged" / "no secret". Anything wrong
    gives NO grants: a file that does not verify is not consent."""
    store = store or secret_store()
    try:
        with open(path or consent_path(), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [], "missing"
    except (OSError, ValueError, RecursionError):
        return [], "corrupt"
    if not isinstance(data, dict) or data.get("version") != VERSION \
            or not isinstance(data.get("grants"), list) or not isinstance(data.get("mac"), str):
        return [], "corrupt"
    secret = store.load()
    if not secret:
        return [], "no secret"
    if not hmac.compare_digest(_mac(data["grants"], secret), data["mac"]):
        return [], "forged"
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


def _write(grants: list, path: str, secret: bytes) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".consent-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "grants": grants, "mac": _mac(grants, secret)}, f, indent=2)
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


def grant(project: str, service: str, history_ok: bool = False, path: str | None = None,
          env_file: str | None = None, store=None,
          now: datetime.datetime | None = None) -> None:
    path = path or consent_path()
    store = store or secret_store()
    grants, problem = read_grants(path, store)
    if problem in ("corrupt", "forged", "no secret") and os.path.exists(path):
        # never write over a file we could not read: keep it, start clean
        try:
            shutil.copy2(path, path + ".bak")
        except OSError:
            pass
        grants = []
    secret = store.load()
    if not secret:
        secret = os.urandom(32)
        store.save(secret)
    grants = [g for g in grants if not (g["service"] == service and _same(g["project"], project))]
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
    entry = {"project": os.path.realpath(project), "service": service,
             "clipboard_history_ok": bool(history_ok), "granted": stamp.isoformat()}
    if env_file:
        entry["env_file"] = env_file
    grants.append(entry)
    _write(grants, path, secret)


def revoke(project: str, service: str | None = None, path: str | None = None, store=None) -> int:
    path = path or consent_path()
    store = store or secret_store()
    grants, _ = read_grants(path, store)
    keep = [g for g in grants if not (_same(g["project"], project)
                                      and (service is None or g["service"] == service))]
    if len(keep) != len(grants):
        secret = store.load()
        if secret:
            _write(keep, path, secret)
    return len(grants) - len(keep)
