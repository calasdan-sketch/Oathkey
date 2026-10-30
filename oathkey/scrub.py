"""Hide secrets in anything an AI is about to read.

A key can come back in a program's output or an API response in more than
one shape: as it is, URL-encoded, base64 (at any of three alignments),
hex, JSON-escaped, or backwards. `Scrubber` removes all of them, also when a
key is split across two chunks of a stream. Best effort, and said so: it
cannot catch a secret an API transforms in some way we did not think of.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
from urllib.parse import quote, quote_plus

REDACTED = b"[REDACTED]"
MIN_LEN = 6          # shorter "secrets" would mangle ordinary text


def forms(secret: str) -> list[bytes]:
    """Every byte-string we will remove for this secret, longest first."""
    raw = secret.encode("utf-8")
    if len(raw) < MIN_LEN:
        return []
    out: set[bytes] = {raw, raw[::-1]}
    for text in (quote(secret, safe=""), quote_plus(secret),
                 json.dumps(secret)[1:-1]):
        out.add(text.encode("utf-8"))
    out.add(raw.hex().encode())
    out.add(raw.hex().upper().encode())
    for k in (0, 1, 2):
        lead = (0, 2, 3)[k]
        total = k + len(raw)
        full = total // 3
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            piece = enc(b"x" * k + raw)[lead:full * 4]
            if len(piece) >= 8:
                out.add(piece)
                out.add(piece.rstrip(b"="))
    return sorted((f for f in out if len(f) >= MIN_LEN),
                  key=len, reverse=True)


class Scrubber:
    """Streaming remover. feed() returns bytes that are safe to show; the
    last few bytes are held back until the next feed(), because a secret
    may straddle two chunks. Call flush() at the end."""

    def __init__(self, secrets):
        seen: set[bytes] = set()
        self._forms: list[bytes] = []
        for s in secrets:
            for f in forms(s):
                if f not in seen:
                    seen.add(f)
                    self._forms.append(f)
        self._forms.sort(key=len, reverse=True)
        self._hold = max((len(f) for f in self._forms), default=1) - 1
        self._buf = b""

    def _clean(self, data: bytes) -> bytes:
        for f in self._forms:
            if f in data:
                data = data.replace(f, REDACTED)
        return data

    def feed(self, chunk: bytes) -> bytes:
        if not self._forms:
            return chunk
        data = self._clean(self._buf + chunk)
        if self._hold and len(data) > self._hold:
            self._buf = data[-self._hold:]
            return data[:-self._hold]
        self._buf, out = (data, b"") if self._hold else (b"", data)
        return out

    def flush(self) -> bytes:
        data, self._buf = self._clean(self._buf), b""
        return data


def scrub_text(text: str, secrets) -> str:
    s = Scrubber(secrets)
    return (s.feed(text.encode("utf-8")) + s.flush()).decode("utf-8", "replace")


def _pump(src, dst, scrubber: Scrubber) -> None:
    try:
        while True:
            chunk = src.read1(8192) if hasattr(src, "read1") else src.read(8192)
            if not chunk:
                break
            dst.write(scrubber.feed(chunk))
            dst.flush()
        dst.write(scrubber.flush())
        dst.flush()
    except (OSError, ValueError):
        pass


def run_scrubbed(cmd, env, secrets, out=None, err=None) -> int:
    """Like subprocess.call, but the child's stdout and stderr go through
    a Scrubber before anyone (an AI) can read them."""
    out = out or sys.stdout.buffer
    err = err or sys.stderr.buffer
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    threads = [threading.Thread(target=_pump, args=(proc.stdout, out,
                                                    Scrubber(secrets))),
               threading.Thread(target=_pump, args=(proc.stderr, err,
                                                    Scrubber(secrets)))]
    for t in threads:
        t.start()
    try:
        status = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        status = proc.wait()
    for t in threads:
        t.join()
    return status


# ---- fail-closed second check ---------------------------------------------------------

def _normalize(text: str) -> str:
    """Undo the common disguises: whitespace splits, escaped slashes,
    unicode escapes, percent-encoding (any case, repeated), HTML entities."""
    import html
    import re
    from urllib.parse import unquote
    t = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    t = t.replace("\\/", "/")
    for _ in range(3):
        nxt = html.unescape(unquote(t))
        if nxt == t:
            break
        t = nxt
    return re.sub(r"\s+", "", t)


def _squash(text: str) -> str:
    """Only letters and digits, lower case. Defeats dashes, dots, zero-width
    characters, NUL bytes (UTF-16 text), accents and upper/lower-case games."""
    import re
    import unicodedata
    t = unicodedata.normalize("NFKD", text.replace("\x00", ""))
    return re.sub(r"[^0-9a-z]", "", t.lower())


def _extra_forms(secret: str) -> list[str]:
    import base64
    import codecs
    raw = secret.encode("utf-8")
    out = [codecs.encode(secret, "rot13")]
    out.append(base64.b32encode(raw).decode().rstrip("="))
    out.append(base64.b32hexencode(raw).decode().rstrip("="))
    out.append(base64.b85encode(raw).decode())
    out.append(base64.a85encode(raw).decode())
    return out


def loosely_contains(text: str, secrets) -> bool:
    """True if, after undoing common disguises, any secret (in a plain,
    base64 or hex form) is still in the text. The caller then withholds the
    whole text instead of trying to patch it."""
    text = text.replace("\x00", "")
    norm = _normalize(text)
    squashed = _squash(norm)
    for s in secrets:
        if len(s) < MIN_LEN:
            continue
        for f in forms(s):
            try:
                needle = _normalize(f.decode("utf-8"))
            except UnicodeDecodeError:
                continue
            if len(needle) >= MIN_LEN and needle in norm:
                return True
            sq = _squash(needle)
            if len(sq) >= 14 and sq in squashed:
                return True
        for extra in _extra_forms(s):
            sq = _squash(extra)
            if len(sq) >= 14 and sq in squashed:
                return True
    return False
