"""Copy-and-go: take a key from the clipboard the moment it is copied.

The person clicks the vendor's own "Copy" button; this notices a new,
key-shaped value on the clipboard, takes it and EMPTIES the clipboard, so
the key is not left there for the next paste or another program. Nothing
is typed or pasted, and the value is never shown.

It only looks while `oathkey connect --clipboard` is waiting for a key,
and only takes a value that:
  - matches the field's pattern, when the recipe gives one; otherwise
  - looks like a key: one line, no spaces, 8 to 4096 visible characters,
    and different from what was on the clipboard when it started waiting
    and from the values already taken for this connect.

Backends: Windows (user32, no extra tools), macOS (pbpaste / pbcopy),
Linux (wl-paste / wl-copy, xclip or xsel). With none available, connect
falls back to the hidden paste prompt. Windows clipboard history (Win+V)
and clipboard managers can keep their own copy; this cannot clear those.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time

POLL_SECONDS = 0.3
WAIT_SECONDS = 180
MAX_LEN = 4096
KEY_SHAPE = re.compile(r"^[!-~]{8,4096}\Z")   # printable ASCII, no spaces


class Unavailable(Exception):
    """No way to read the clipboard on this system."""


# ---- backends ----------------------------------------------------------------

def _windows():
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    cf_unicode = 13

    def opened(fn):
        for _ in range(10):                     # another program may hold it a moment
            if user32.OpenClipboard(None):
                try:
                    return fn()
                finally:
                    user32.CloseClipboard()
            time.sleep(0.05)
        return None

    def get() -> str:
        def read():
            handle = user32.GetClipboardData(cf_unicode)
            if not handle:
                return ""
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return ""
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(handle)
        return opened(read) or ""

    def clear() -> None:
        opened(user32.EmptyClipboard)

    return get, clear


def _command(read: list[str], clear: list[str]):
    def get() -> str:
        try:
            done = subprocess.run(read, capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else ""

    def wipe() -> None:
        try:
            subprocess.run(clear, input=b"", capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return get, wipe


def backend():
    """(get, clear) functions for this system, or raise Unavailable."""
    if sys.platform == "win32":
        try:
            return _windows()
        except (OSError, AttributeError) as e:
            raise Unavailable(f"Windows clipboard not reachable ({e})") from None
    if sys.platform == "darwin" and shutil.which("pbpaste"):
        return _command(["pbpaste"], ["pbcopy"])
    if shutil.which("wl-paste") and shutil.which("wl-copy"):
        return _command(["wl-paste", "--no-newline"], ["wl-copy", "--clear"])
    if shutil.which("xclip"):
        return _command(["xclip", "-selection", "clipboard", "-o"], ["xclip", "-selection", "clipboard", "-i"])
    if shutil.which("xsel"):
        return _command(["xsel", "--clipboard", "--output"], ["xsel", "--clipboard", "--clear"])
    raise Unavailable("no clipboard tool found (install wl-clipboard, xclip or xsel)")


# ---- waiting for a key ---------------------------------------------------------

def looks_like(value: str, pattern: str | None) -> bool:
    value = value.strip()
    if not value or len(value) > MAX_LEN:
        return False
    if "://" in value or value.lower().startswith(("www.", "mailto:")):
        return False                     # a web address is never a key
    if pattern:
        return re.fullmatch(pattern, value) is not None
    return KEY_SHAPE.match(value) is not None


def is_empty(get) -> bool:
    """True when the clipboard really is empty now (some systems refuse to
    clear it, and clipboard-history tools may keep their own copy)."""
    try:
        return not (get() or "").strip()
    except Exception:                                    # noqa: BLE001
        return False


def wait_for_key(pattern: str | None, taken: set[str], get, clear,
                 wait: float = WAIT_SECONDS, poll: float = POLL_SECONDS,
                 now=time.monotonic, sleep=time.sleep) -> str | None:
    """The next key-shaped value copied, or None after `wait` seconds.

    What is on the clipboard when waiting starts is taken only when the
    recipe's pattern recognises it (the person copied the key a moment
    early); a generic-looking value from before is ignored as stale. The
    clipboard is emptied as soon as a value is taken."""
    start = (get() or "").strip()
    if pattern and start not in taken and looks_like(start, pattern):
        clear()
        return start
    seen = start
    deadline = now() + wait
    while now() < deadline:
        sleep(poll)
        current = (get() or "").strip()
        if current == seen:
            continue
        seen = current
        if current not in taken and looks_like(current, pattern):
            clear()
            return current
    return None
