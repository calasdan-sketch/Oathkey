"""Opt-in OS keychain storage (`safeeasyapi connect --store keychain`).

No third-party `keyring` package - each platform uses what it ships with:

- macOS:   the `security` command (login Keychain, generic password).
           Commands are fed over stdin (`security -i`), so the key never
           appears in the process list or shell history.
- Windows: the Credential Manager (Windows Vault) through ctypes ->
           advapi32 CredWriteW / CredReadW / CredDeleteW, as a generic
           credential persisted for the local machine (same store as
           `cmdkey`). The blob is UTF-16-LE like cmdkey/.NET write it.
- Linux:   `secret-tool` (libsecret / GNOME Keyring / KWallet via the
           Secret Service API) when it is installed; the key goes in on
           stdin.
- Anything else, or a missing tool: no backend. The caller falls back to
  the owner-only `.env` file and says so.

The entry is keyed by service slug + env var, so one keychain can hold
several services. Keys are read back only by `safeeasyapi run`, which
injects them into a child process's environment - never printed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from .recipes import printable

TARGET_PREFIX = "safeeasyapi"
# How long an OS tool (security, secret-tool) may take to answer. A keyring
# that is waiting for a dialog nobody sees would otherwise hold us forever.
TOOL_TIMEOUT = 30
MACOS, WINDOWS, LINUX = "macos-keychain", "windows-credential-manager", "secret-service"
LABELS = {MACOS: "macOS Keychain", WINDOWS: "Windows Credential Manager",
          LINUX: "Secret Service keyring (secret-tool)"}


class KeychainError(Exception):
    pass


class KeychainUnavailable(KeychainError):
    """The OS tool could not be run, or did not answer in time. Unlike a
    plain refusal this says nothing about whether the entry exists, so a
    caller must not read it as "not stored"."""


def target_name(service: str) -> str:
    return f"{TARGET_PREFIX}:{service}"


def detect_backend(platform: str | None = None, which=shutil.which,
                   ctypes_mod=None) -> str | None:
    """Pick the backend for `platform` (default: this machine), or None
    when the OS offers nothing we can drive without extra packages."""
    plat = platform if platform is not None else sys.platform
    if plat == "darwin":
        return MACOS if which("security") else None
    if plat.startswith("win"):
        mod = ctypes_mod
        if mod is None:
            try:
                import ctypes as mod  # type: ignore[no-redef]
            except ImportError:  # pragma: no cover
                return None
        return WINDOWS if hasattr(mod, "windll") else None
    if which("secret-tool"):
        return LINUX
    return None


def label(backend: str | None) -> str:
    return LABELS.get(backend or "", "no OS keychain")


# ----------------------------------------------------------------- macOS

def _security_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _macos(op: str, service: str, account: str, key: str | None, run) -> str | None:
    target = target_name(service)
    if op == "store":
        # interactive mode reads commands from stdin: the key is never an
        # argv entry (visible in `ps`) - `-U` updates an existing item
        cmd = (f"add-generic-password -U -a {_security_quote(account)} "
               f"-s {_security_quote(target)} -w {_security_quote(key or '')}\n")
        proc = run(["security", "-i"], input=cmd.encode("utf-8"),
                   capture_output=True, timeout=TOOL_TIMEOUT)
        if proc.returncode != 0:
            raise KeychainError("security add-generic-password failed "
                                f"(exit {proc.returncode})")
        return None
    if op == "read":
        proc = run(["security", "find-generic-password", "-a", account,
                    "-s", target, "-w"], capture_output=True,
                   timeout=TOOL_TIMEOUT)
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").rstrip("\r\n")
    proc = run(["security", "delete-generic-password", "-a", account,
                "-s", target], capture_output=True, timeout=TOOL_TIMEOUT)
    return None if proc.returncode == 0 else ""


# ----------------------------------------------------------------- Linux

def _secret_tool(op: str, service: str, account: str, key: str | None, run) -> str | None:
    attrs = ["service", TARGET_PREFIX, "account", account, "slug", service]
    if op == "store":
        proc = run(["secret-tool", "store", "--label",
                    f"{TARGET_PREFIX} {service} ({account})"] + attrs,
                   input=(key or "").encode("utf-8"), capture_output=True,
                   timeout=TOOL_TIMEOUT)
        if proc.returncode != 0:
            raise KeychainError(f"secret-tool store failed (exit {proc.returncode})")
        return None
    if op == "read":
        proc = run(["secret-tool", "lookup"] + attrs, capture_output=True,
                   timeout=TOOL_TIMEOUT)
        if proc.returncode != 0 or not proc.stdout:
            return None
        return proc.stdout.decode("utf-8", "replace").rstrip("\r\n")
    proc = run(["secret-tool", "clear"] + attrs, capture_output=True,
               timeout=TOOL_TIMEOUT)
    return None if proc.returncode == 0 else ""


# --------------------------------------------------------------- Windows

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2


def _win_structs(ctypes_mod):
    ct = ctypes_mod
    wt = ct.wintypes

    class FILETIME(ct.Structure):
        _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]

    class CREDENTIAL(ct.Structure):
        _fields_ = [
            ("Flags", wt.DWORD),
            ("Type", wt.DWORD),
            ("TargetName", wt.LPWSTR),
            ("Comment", wt.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", wt.DWORD),
            ("CredentialBlob", ct.POINTER(ct.c_ubyte)),
            ("Persist", wt.DWORD),
            ("AttributeCount", wt.DWORD),
            ("Attributes", ct.c_void_p),
            ("TargetAlias", wt.LPWSTR),
            ("UserName", wt.LPWSTR),
        ]

    return CREDENTIAL


def _windows(op: str, service: str, account: str, key: str | None,
             ctypes_mod=None) -> str | None:
    ct = ctypes_mod
    if ct is None:
        import ctypes
        import ctypes.wintypes  # noqa: F401  (attaches ctypes.wintypes)
        ct = ctypes
    advapi32 = ct.windll.advapi32
    CREDENTIAL = _win_structs(ct)
    target = target_name(service)
    if op == "store":
        blob = (key or "").encode("utf-16-le")
        buf = ct.create_string_buffer(blob, len(blob))
        cred = CREDENTIAL()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.Comment = "stored by safeeasyapi"
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ct.cast(buf, ct.POINTER(ct.c_ubyte))
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.TargetAlias = None
        cred.UserName = account
        if not advapi32.CredWriteW(ct.byref(cred), 0):
            raise KeychainError("CredWriteW failed "
                                f"(error {ct.GetLastError()})")
        return None
    if op == "read":
        pcred = ct.POINTER(CREDENTIAL)()
        if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ct.byref(pcred)):
            return None
        try:
            c = pcred.contents
            blob = ct.string_at(c.CredentialBlob, c.CredentialBlobSize)
        finally:
            advapi32.CredFree(pcred)
        return blob.decode("utf-16-le")
    ok = advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0)
    return None if ok else ""


# ------------------------------------------------------------- dispatch

_TOOL_NAMES = {MACOS: "the `security` command", LINUX: "`secret-tool`",
               WINDOWS: "the Windows Credential Manager"}


def _dispatch(op: str, backend: str, service: str, account: str,
              key: str | None, run, ctypes_mod) -> str | None:
    tool = _TOOL_NAMES.get(backend, "the keychain")
    try:
        if backend == MACOS:
            return _macos(op, service, account, key, run)
        if backend == LINUX:
            return _secret_tool(op, service, account, key, run)
        if backend == WINDOWS:
            return _windows(op, service, account, key, ctypes_mod)
    except subprocess.TimeoutExpired as e:
        # Never let this out as a traceback: for `connect` it would arrive
        # after the key was validated and lose it, for `forget` it would
        # stop before the .env file was touched. Nothing here names the key
        # (it travels on stdin, not in argv).
        raise KeychainUnavailable(
            f"{tool} did not answer within {e.timeout:g} seconds") from None
    except (subprocess.SubprocessError, OSError) as e:
        raise KeychainUnavailable(
            f"{tool} could not be run ({type(e).__name__})") from None
    raise KeychainError(f"no keychain backend: {backend!r}")


def store(service: str, env_var: str, key: str, backend: str | None = None,
          run=subprocess.run, ctypes_mod=None) -> str:
    """Store the key. Returns the backend used. Raises KeychainError when
    there is no backend or the OS tool refused."""
    backend = backend or detect_backend()
    if backend is None:
        raise KeychainError("no OS keychain available on this system")
    _dispatch("store", backend, service, env_var, key, run, ctypes_mod)
    return backend


def read(service: str, env_var: str, backend: str | None = None,
         run=subprocess.run, ctypes_mod=None) -> str | None:
    """The stored key, or None when absent. For `safeeasyapi run` only -
    callers must never print it."""
    backend = backend or detect_backend()
    if backend is None:
        return None
    return _dispatch("read", backend, service, env_var, None, run, ctypes_mod)


def delete(service: str, env_var: str, backend: str | None = None,
           run=subprocess.run, ctypes_mod=None) -> bool:
    backend = backend or detect_backend()
    if backend is None:
        return False
    return _dispatch("delete", backend, service, env_var, None, run,
                     ctypes_mod) is None


class CannotRun(Exception):
    """The command cannot be started. `code` is the shell's: 127 when it is
    not there, 126 when it is there but cannot be run. The text names the
    command, made printable, and nothing else."""

    def __init__(self, code: int, text: str):
        super().__init__(text)
        self.code = code


BATCH_SUFFIXES = (".cmd", ".bat")


def _search_path(env: dict | None, on_windows: bool) -> str:
    env = os.environ if env is None else env
    if on_windows:
        # Windows spells it PATH, Path or path
        return next((v for k, v in env.items() if k.upper() == "PATH"), "")
    return env.get("PATH", os.defpath)


def _why_not(name: str, search: str) -> CannotRun:
    """`name` is not a program we can start: not there at all (127), or
    there but not something that can be run (126) - a shell tells them apart
    the same way."""
    shown = printable(name)
    explicit = bool(os.path.dirname(name))
    for candidate in ([name] if explicit else
                      [os.path.join(d, name) for d in search.split(os.pathsep) if d]):
        if explicit and os.path.isdir(candidate):
            return CannotRun(126, f"cannot run {shown}: it is a directory")
        if os.path.isfile(candidate):
            return CannotRun(126, f"cannot run {shown}: it is there but not "
                                  f"an executable file")
    return CannotRun(127, f"command not found: {shown}")


def locate_program(name: str, env: dict | None = None, which=shutil.which,
                   on_windows: bool | None = None) -> str:
    """Check that `name` can be started, and say what to hand to subprocess.

    Raises CannotRun - before the keychain has been asked for anything, so a
    typo costs no unlock prompt. On POSIX the name is returned as typed:
    subprocess searches the child's PATH itself, and argv[0] stays what the
    person wrote. On Windows CreateProcess looks for `name.exe` only, so a
    command that is really a batch file (`npm` is `npm.cmd`) would be "not
    found"; the name is looked up the way the shell does it (PATHEXT) and
    the full path of a .cmd or .bat file is returned."""
    if on_windows is None:
        on_windows = os.name == "nt"
    search = _search_path(env, on_windows)
    found = which(name, path=search)
    if found is None:
        raise _why_not(name, search)
    if on_windows and os.path.splitext(found)[1].lower() in BATCH_SUFFIXES:
        return found
    return name


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def run_with_key(recipe: dict, cmd: list[str], backend: str | None = None,
                 env: dict | None = None, read_fn=None, call=None,
                 scrub: bool | None = None) -> int:
    """Run `cmd` with the recipe's env var injected from the keychain.
    The key goes straight into the child's environment, never to a
    terminal. Returns the child's exit code - 128 plus the signal number for
    a child a signal stopped, as a shell reports it; raises KeychainError
    when no key is stored for the service, and CannotRun (126) when the
    system will not start the command."""
    from .recipes import env_vars
    child_env = dict(os.environ if env is None else env)
    secrets: list[str] = []
    for var in env_vars(recipe):
        key = (read_fn or read)(recipe["service"], var, backend)
        if key is None:
            raise KeychainError(f"no key stored for '{recipe['service']}'"
                                + ("" if var == recipe["env_var"] else f" ({var})"))
        child_env[var] = key
        secrets.append(key)
        del key
    # When nobody is watching a terminal (an AI agent reads the output), the
    # child must not be able to print the key back: `run x -- env` would.
    if scrub is None:
        scrub = False   # the command line decides (cli._cmd_run)
    try:
        if scrub and call is None:
            from .scrub import run_scrubbed
            status = run_scrubbed(cmd, child_env, secrets)
        else:
            status = (call or subprocess.call)(cmd, env=child_env)
    except OSError as e:
        # The caller found the program (locate_program) but the system would
        # not start it: a script whose interpreter is missing, a file that
        # is no program, a command line that is too long.
        raise CannotRun(126, f"cannot run {printable(cmd[0])}: "
                             f"{printable(e.strerror or type(e).__name__)}"
                        ) from None
    return 128 - status if status < 0 else status
