"""Start a program with keys in its environment, optionally scrubbing its output.

The keys go into the CHILD's environment only: not onto its command line,
not into this process's own environment, not into any file. With redaction
on, the child's standard output and error come back through redact.Redactor
so a program that prints a key does not put it on your screen.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

from . import redact as redact_mod
from . import store as store_mod


def env_file_value(path: str, var: str) -> str | None:
    """The value of `var` in a .env file, or None. A link, a missing file or a
    file that is not plain text gives None. For `run` only: never printed."""
    try:
        store_mod.refuse_link(path)
        if not os.path.isfile(path):
            return None
        value = store_mod.load_env(path).get(var)
    except (OSError, ValueError):
        return None
    return value if value else None


def _pump(src, dst, redactor: redact_mod.Redactor) -> None:
    try:
        while True:
            chunk = src.read1(redact_mod.CHUNK) if hasattr(src, "read1") else src.read(redact_mod.CHUNK)
            if not chunk:
                break
            out = redactor.feed(chunk)
            if out:
                dst.write(out)
                dst.flush()
        tail = redactor.flush()
        if tail:
            dst.write(tail)
            dst.flush()
    except (OSError, ValueError):
        pass        # our reader went away (closed pipe): keep draining quietly
    finally:
        try:
            src.close()
        except OSError:
            pass


def _binary(stream):
    return getattr(stream, "buffer", stream)


def run_redacted(cmd: list[str], child_env: dict, secrets, popen=subprocess.Popen,
                 stdout=None, stderr=None) -> int:
    """Run `cmd`; its output is scrubbed of every value in `secrets`.
    Returns the child's status (128 + n for a signal). Standard input is the
    child's own (inherited), so it can still ask you things."""
    out = _binary(stdout if stdout is not None else sys.stdout)
    err = _binary(stderr if stderr is not None else sys.stderr)
    proc = popen(cmd, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threads = []
    for src, dst in ((proc.stdout, out), (proc.stderr, err)):
        t = threading.Thread(target=_pump, args=(src, dst, redact_mod.Redactor(secrets)),
                             daemon=True)
        t.start()
        threads.append(t)
    try:
        status = proc.wait()
    except KeyboardInterrupt:
        # Ctrl-C reached the child too; give it a moment to finish, then say so
        try:
            status = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = proc.wait()
        raise
    finally:
        for t in threads:
            t.join(timeout=5)
    return 128 - status if status < 0 else status
