"""Scrub exact key values (and common re-writings of them) out of output.

`safeeasyapi run` hands a key to a program through its environment. A
program that prints its own environment, or an error that quotes a request
header, would put the key on your screen - and in an AI agent's chat if it
is watching. With redaction ON (the default) the program's output goes
through this filter first.

What it catches: the exact value; its base64 forms (standard and URL-safe,
padded or not, at any of the three alignments it can take inside a longer
base64 string); hex (lower and upper case); percent-encoding; JSON string
escaping; its upper-case and lower-case forms; and the value with its characters
reversed is NOT caught.

What it CANNOT catch (honest limits):
  - a value the program changes: hashed, encrypted, truncated, split over
    several lines or reversed, or only part of it printed;
  - a value shorter than MIN_LENGTH (too many false hits);
  - anything the program writes to a file or sends over the network instead
    of printing it;
  - output a program only produces on a real terminal: with redaction on,
    the program's output is a pipe, not a terminal, so some programs drop
    colours or stop asking questions. Use --no-redact for those.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse

MIN_LENGTH = 6
MARK = b"[REDACTED]"
CHUNK = 4096


def variants(value: str) -> set[bytes]:
    """Every byte string worth hiding for `value`."""
    if len(value) < MIN_LENGTH:
        return set()
    raw = value.encode("utf-8", "surrogateescape")
    out = {raw}
    # upper / lower case re-writings (a program that shouts or lower-cases)
    for alt in (value.lower(), value.upper()):
        if alt != value:
            out.add(alt.encode("utf-8", "surrogateescape"))
    out.add(value.encode("utf-16-le", "surrogatepass")) if value.isascii() else None
    out.add(binascii.hexlify(raw))
    out.add(binascii.hexlify(raw).upper())
    out.add(urllib.parse.quote(value, safe="").encode())
    out.add(urllib.parse.quote_plus(value).encode())
    out.add(json.dumps(value)[1:-1].encode())
    out.add(json.dumps(value, ensure_ascii=False)[1:-1].encode("utf-8", "surrogateescape"))
    # base64 of the value as it can sit inside a longer base64 string: the
    # encoding of (prefix + value) depends on len(prefix) % 3
    for pad in (0, 1, 2):
        enc = base64.b64encode(b"\x00" * pad + raw).decode()
        lead = len(base64.b64encode(b"\x00" * pad).decode().rstrip("="))
        body = enc[lead:] if pad else enc
        # drop trailing characters that depend on what follows the value
        stable = body.rstrip("=")
        trim = {0: 0, 1: 1, 2: 2}[(len(raw) + pad) % 3] if (len(raw) + pad) % 3 else 0
        core = stable[:len(stable) - trim] if trim else stable
        core = core[:max(len(core), 0)]
        if len(core) >= MIN_LENGTH:
            for form in (core, core.replace("+", "-").replace("/", "_")):
                out.add(form.encode())
        if pad == 0:
            for form in (enc, enc.rstrip("="),
                         enc.replace("+", "-").replace("/", "_"),
                         enc.replace("+", "-").replace("/", "_").rstrip("=")):
                out.add(form.encode())
    return {v for v in out if len(v) >= MIN_LENGTH}


class Redactor:
    """Streaming filter: feed() raw bytes, get safe bytes back; flush() at
    the end. A value split across two chunks is still caught, because the
    last (longest-variant - 1) bytes are held back until more arrives."""

    def __init__(self, values):
        found: set[bytes] = set()
        for v in values:
            found |= variants(v)
        # longest first, so a long form is not half-replaced by a short one
        self._needles = sorted(found, key=len, reverse=True)
        self._hold = max((len(n) for n in self._needles), default=1) - 1
        # only text that could be the START of a value is held back, so
        # ordinary output (a line ending in a newline) is never delayed
        self._prefixes = {n[:k] for n in self._needles for k in range(1, len(n))}
        self._tail = b""
        self.hits = 0

    def _scrub(self, data: bytes) -> bytes:
        for needle in self._needles:
            if needle in data:
                self.hits += data.count(needle)
                data = data.replace(needle, MARK)
        return data

    def feed(self, chunk: bytes) -> bytes:
        if not self._needles:
            return chunk
        data = self._scrub(self._tail + chunk)
        keep = 0
        for k in range(min(self._hold, len(data)), 0, -1):
            if data[-k:] in self._prefixes:
                keep = k
                break
        self._tail = data[len(data) - keep:] if keep else b""
        return data[:len(data) - keep]

    def flush(self) -> bytes:
        data, self._tail = self._scrub(self._tail), b""
        return data

    def text(self, s: str) -> str:
        """One-shot scrub of a string (messages, logs)."""
        r = Redactor.__new__(Redactor)
        r._needles, r._hold, r._tail, r.hits = self._needles, self._hold, b"", 0
        r._prefixes = self._prefixes
        return r._scrub(s.encode("utf-8", "surrogateescape")).decode("utf-8", "replace")
