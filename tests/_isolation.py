"""Test-environment isolation shared by every test module.

Importing this module points HOME / USERPROFILE / APPDATA / LOCALAPPDATA /
XDG_* at a throwaway directory for the whole test process, so no test can
read or write the real user's ~/.safeeasyapi (user recipes, directory
cache) or their real .env. The directory is removed at exit with a
cleanup that tolerates read-only files (Windows).
"""

import atexit
import os
import shutil
import stat
import sys
import tempfile

ENV_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
            "XDG_CONFIG_HOME", "XDG_DATA_HOME")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rmtree(path: str) -> None:
    """shutil.rmtree that copes with read-only files."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerror(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerror)


def mktemp() -> str:
    """Short-pathed temp dir, removed at exit."""
    d = tempfile.mkdtemp(prefix="se")
    _TEMP_DIRS.append(d)
    return d


def _cleanup() -> None:
    for d in _TEMP_DIRS + [FAKE_HOME]:
        try:
            rmtree(d)
        except OSError:
            pass


_TEMP_DIRS: list = []
FAKE_HOME = os.environ.get("SAFEEASYAPI_TEST_HOME") or tempfile.mkdtemp(prefix="seh")
for _var in ENV_VARS:
    os.environ[_var] = FAKE_HOME
os.environ["SAFEEASYAPI_TEST_HOME"] = FAKE_HOME  # subprocesses share it
atexit.register(_cleanup)
