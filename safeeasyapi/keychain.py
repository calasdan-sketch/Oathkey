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

TARGET_PREFIX = "safeeasyapi"
MACOS, WINDOWS, LINUX = "macos-keychain", "windows-credential-manager", "secret-service"
LABELS = {MACOS: "macOS Keychain", WINDOWS: "Windows Credential Manager",
          LINUX: "Secret Service keyring (secret-tool)"}


class KeychainError(Exception):
    pass


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
                   capture_output=True, timeout=30)
        if proc.returncode != 0:
            raise KeychainError("security add-generic-password failed "
                                f"(exit {proc.returncode})")
        return None
    if op == "read":
        proc = run(["security", "find-generic-password", "-a", account,
                    "-s", target, "-w"], capture_output=True, timeout=30)
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").rstrip("\r\n")
    proc = run(["security", "delete-generic-password", "-a", account,
                "-s", target], capture_output=True, timeout=30)
    return None if proc.returncode == 0 else ""


# ----------------------------------------------------------------- Linux

def _secret_tool(op: str, service: str, account: str, key: str | None, run) -> str | None:
    attrs = ["service", TARGET_PREFIX, "account", account, "slug", service]
    if op == "store":
        proc = run(["secret-tool", "store", "--label",
                    f"{TARGET_PREFIX} {service} ({account})"] + attrs,
                   input=(key or "").encode("utf-8"), capture_output=True,
                   timeout=30)
        if proc.returncode != 0:
            raise KeychainError(f"secret-tool store failed (exit {proc.returncode})")
        return None
    if op == "read":
        proc = run(["secret-tool", "lookup"] + attrs, capture_output=True,
                   timeout=30)
        if proc.returncode != 0 or not proc.stdout:
            return None
        return proc.stdout.decode("utf-8", "replace").rstrip("\r\n")
    proc = run(["secret-tool", "clear"] + attrs, capture_output=True, timeout=30)
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

def _dispatch(op: str, backend: str, service: str, account: str,
              key: str | None, run, ctypes_mod) -> str | None:
    if backend == MACOS:
        return _macos(op, service, account, key, run)
    if backend == LINUX:
        return _secret_tool(op, service, account, key, run)
    if backend == WINDOWS:
        return _windows(op, service, account, key, ctypes_mod)
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


def run_with_key(recipe: dict, cmd: list[str], backend: str | None = None,
                 env: dict | None = None, read_fn=None, call=None) -> int:
    """Run `cmd` with the recipe's env var injected from the keychain.
    The key goes straight into the child's environment, never to a
    terminal. Returns the child's exit code; raises KeychainError when no
    key is stored for the service."""
    key = (read_fn or read)(recipe["service"], recipe["env_var"], backend)
    if key is None:
        raise KeychainError(f"no key stored for '{recipe['service']}'")
    child_env = dict(os.environ if env is None else env)
    child_env[recipe["env_var"]] = key
    del key
    return (call or subprocess.call)(cmd, env=child_env)
