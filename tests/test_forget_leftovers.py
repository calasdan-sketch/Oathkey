"""forget must not say the key is gone while a copy of it is still on disk.

Panel finding (SEA-7): `forget` removed the line from .env and reported
success while

- a temp file left by a write that was killed (SIGKILL, power cut) still held
  the whole file, key included - `forget` even said "nothing stored" when the
  killed write was the one that was going to store it; and
- a hard link to the file (a `.env.bak` made with `ln`) kept the old
  contents, because rewriting a file by rename never touches its other names.

Now `forget` removes the first kind (they are safeeasyapi's own) and names the
second kind without deleting it (it is not safeeasyapi's), exiting 1 because
the key is not gone.
"""

import functools
import io
import os
import random
import subprocess
import sys
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from safeeasyapi import cli as cli_mod
from safeeasyapi import keychain as keychain_mod
from safeeasyapi import store as store_mod

KEY = "sk-forget-me-7731"
NO_KEYCHAIN = types.SimpleNamespace(detect_backend=lambda: None,
                                    label=keychain_mod.label,
                                    delete=lambda *a: False)
RECIPE = {"service": "acme", "display": "Acme", "env_var": "ACME_API_KEY",
          "key_url": "https://acme.test/keys", "steps": ["x"],
          "validate": {"method": "GET", "url": "https://acme.test/me",
                       "auth": {"type": "bearer"}, "expect": [200]}}


def new_folder():
    return _isolation.mktemp()


def write(path, text):
    with open(path, "wb") as f:
        f.write(text.encode("utf-8"))
    os.chmod(path, 0o600)


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8")


def temp_name(base=".env"):
    """The name write_private() gives its temp file: .<name>.<8 of a-z0-9_>.tmp"""
    letters = "abcdefghijklmnopqrstuvwxyz0123456789_"
    return f".{base}." + "".join(random.choice(letters) for _ in range(8)) + ".tmp"


def forget(env, **kw):
    out = io.StringIO()
    code = cli_mod._cmd_forget(RECIPE, env, out=out, keychain=NO_KEYCHAIN, **kw)
    return code, out.getvalue()


KILLED_WRITER = """
import os, signal, sys
sys.path.insert(0, sys.argv[1])
from safeeasyapi import store
os.replace = lambda *a, **k: os.kill(os.getpid(), signal.SIGKILL)
store.store_key_result("ACME_API_KEY", sys.argv[3], sys.argv[2])
"""


class TestAKilledWriteLeavesACopy(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "needs SIGKILL")
    def test_forget_removes_the_copy_a_really_killed_write_left(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, "OTHER=1\n")
        child_env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        proc = subprocess.run(
            [sys.executable, "-c", KILLED_WRITER, _isolation.REPO, env, KEY],
            env=child_env, capture_output=True, timeout=120)
        self.assertEqual(proc.returncode, -9, proc.stderr)
        leftovers = [n for n in os.listdir(folder) if n != ".env"]
        self.assertEqual(len(leftovers), 1, leftovers)         # the setup is real
        self.assertIn(KEY, read(os.path.join(folder, leftovers[0])))

        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(os.listdir(folder)), [".env"])
        self.assertEqual(read(env), "OTHER=1\n")
        self.assertIn(leftovers[0], text)
        self.assertIn("interrupted write", text)
        self.assertNotIn("nothing stored", text)
        self.assertNotIn(KEY, text)

    def test_the_line_in_env_and_the_leftover_both_go(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"OTHER=1\nACME_API_KEY={KEY}\n")
        orphan = os.path.join(folder, temp_name())
        write(orphan, f"OTHER=1\nACME_API_KEY={KEY}\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertFalse(os.path.exists(orphan))
        self.assertEqual(read(env), "OTHER=1\n")
        self.assertIn("removed ACME_API_KEY from", text)
        self.assertIn(os.path.basename(orphan), text)
        self.assertNotIn(KEY, text)

    def test_every_leftover_that_holds_the_key_goes(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, "OTHER=1\n")
        orphans = [os.path.join(folder, temp_name()) for _ in range(3)]
        for orphan in orphans:
            write(orphan, f"export ACME_API_KEY='{KEY}'\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertEqual([o for o in orphans if os.path.exists(o)], [])

    def test_forget_with_an_env_file_in_another_folder_or_name(self):
        folder = new_folder()
        env = os.path.join(folder, "prod.env")
        write(env, "OTHER=1\n")
        mine = os.path.join(folder, temp_name("prod.env"))
        write(mine, f"ACME_API_KEY={KEY}\n")
        not_mine = os.path.join(folder, temp_name(".env"))     # another file's
        write(not_mine, f"ACME_API_KEY={KEY}\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertFalse(os.path.exists(mine))
        self.assertTrue(os.path.exists(not_mine))

    def test_a_leftover_alone_is_not_nothing_stored(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")                      # no .env at all
        orphan = os.path.join(folder, temp_name())
        write(orphan, f"ACME_API_KEY={KEY}\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertFalse(os.path.exists(orphan))
        self.assertNotIn("nothing stored", text)
        self.assertIn("forgot acme", text)
        self.assertFalse(os.path.exists(env))                   # and no .env made


class TestOnlyOurOwnLeftoversAreTouched(unittest.TestCase):
    def test_other_files_are_left_alone_even_if_they_hold_the_key(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"ACME_API_KEY={KEY}\n")
        keep = {}
        keep[".env.bak"] = f"ACME_API_KEY={KEY}\n"             # a backup
        keep[".env.tmp"] = f"ACME_API_KEY={KEY}\n"             # the OLD guessable name
        keep["..env.short.tmp"] = f"ACME_API_KEY={KEY}\n"
        keep["..env.ABCD1234.tmp"] = f"ACME_API_KEY={KEY}\n"   # mkstemp never makes capitals
        keep["..env.abcd1234.tmp.bak"] = f"ACME_API_KEY={KEY}\n"
        keep["...env.abcd1234.tmp"] = f"ACME_API_KEY={KEY}\n"
        keep[temp_name(".env.local")] = f"ACME_API_KEY={KEY}\n"
        keep[temp_name()] = "OTHER=1\n"                         # ours, but not this key
        keep[temp_name().replace(".tmp", ".txt")] = f"ACME_API_KEY={KEY}\n"
        for name, text in keep.items():
            write(os.path.join(folder, name), text)
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(os.listdir(folder)), sorted(list(keep) + [".env"]))
        for name, content in keep.items():
            self.assertEqual(read(os.path.join(folder, name)), content, name)

    def test_a_directory_or_a_link_with_that_name_is_not_followed(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"ACME_API_KEY={KEY}\n")
        as_dir = os.path.join(folder, temp_name())
        os.mkdir(as_dir)
        write(os.path.join(as_dir, "inside"), f"ACME_API_KEY={KEY}\n")
        target = os.path.join(new_folder(), "elsewhere")
        write(target, f"ACME_API_KEY={KEY}\n")
        as_link = os.path.join(folder, temp_name())
        try:
            os.symlink(target, as_link)
        except (OSError, NotImplementedError):
            as_link = None
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertTrue(os.path.isdir(as_dir))
        self.assertEqual(read(os.path.join(as_dir, "inside")), f"ACME_API_KEY={KEY}\n")
        self.assertEqual(read(target), f"ACME_API_KEY={KEY}\n")
        if as_link:
            self.assertTrue(os.path.islink(as_link))

    def test_nothing_anywhere_still_says_nothing_stored(self):
        env = os.path.join(new_folder(), ".env")
        code, text = forget(env)
        self.assertEqual(code, 0)
        self.assertIn("nothing stored", text)


class TestALeftoverThatCannotBeRemoved(unittest.TestCase):
    def test_it_is_named_and_forget_exits_1(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"OTHER=1\nACME_API_KEY={KEY}\n")
        orphan = os.path.join(folder, temp_name())
        write(orphan, f"ACME_API_KEY={KEY}\n")

        def refuse(path):
            raise PermissionError(13, "Permission denied", path)

        real = store_mod.remove_leftovers
        with mock.patch.object(store_mod, "remove_leftovers",
                               functools.partial(real, unlink=refuse)):
            code, text = forget(env)
        self.assertEqual(code, 1, text)
        self.assertTrue(os.path.exists(orphan))
        self.assertIn(os.path.basename(orphan), text)
        self.assertIn("Permission denied", text)
        self.assertIn("still", text)
        self.assertIn("removed ACME_API_KEY from", text)        # the line did go
        self.assertNotIn(KEY, text)


def hard_link(src, dst):
    try:
        os.link(src, dst)
    except (OSError, NotImplementedError, AttributeError):
        raise unittest.SkipTest("this file system has no hard links")


class TestAHardLinkKeepsTheOldFile(unittest.TestCase):
    def test_forget_names_the_other_name_and_exits_1(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        bak = os.path.join(folder, ".env.bak")
        write(env, f"OTHER=1\nACME_API_KEY={KEY}\n")
        hard_link(env, bak)
        code, text = forget(env)
        self.assertEqual(code, 1, text)
        self.assertEqual(read(env), "OTHER=1\n")                 # the line did go
        self.assertEqual(read(bak), f"OTHER=1\nACME_API_KEY={KEY}\n")   # not ours
        self.assertIn(".env.bak", text)
        self.assertIn("hard link", text)
        self.assertIn("still", text)
        self.assertIn("removed ACME_API_KEY from", text)
        self.assertNotIn(KEY, text)

    def test_a_name_in_another_folder_is_counted(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"ACME_API_KEY={KEY}\n")
        hard_link(env, os.path.join(new_folder(), "backup"))
        code, text = forget(env)
        self.assertEqual(code, 1, text)
        self.assertIn("another folder", text)
        self.assertIn("hard link", text)

    def test_names_that_try_to_drive_the_terminal_are_shown_as_escapes(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"ACME_API_KEY={KEY}\n")
        hard_link(env, os.path.join(folder, "bak" + chr(27) + "[2J"))
        code, text = forget(env)
        self.assertEqual(code, 1, text)
        self.assertNotIn(chr(27), text)
        self.assertIn("bak\\x1b[2J", text)

    def test_one_name_only_means_no_note(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, f"ACME_API_KEY={KEY}\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertNotIn("hard link", text)

    def test_a_link_to_a_file_with_no_key_in_it_is_not_news(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        write(env, "OTHER=1\n")
        hard_link(env, os.path.join(folder, ".env.bak"))
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertIn("nothing stored", text)
        self.assertNotIn("hard link", text)

    def test_other_links_reports_what_it_can_see(self):
        folder = new_folder()
        env = os.path.join(folder, ".env")
        self.assertIsNone(store_mod.other_links(env))            # no file
        write(env, "A=1\n")
        self.assertIsNone(store_mod.other_links(env))            # one name
        hard_link(env, os.path.join(folder, "two"))
        hard_link(env, os.path.join(new_folder(), "three"))
        links = store_mod.other_links(env)
        self.assertEqual(links.names, ["two"])
        self.assertEqual(links.elsewhere, 1)

    def test_a_symbolic_link_is_not_looked_through(self):
        folder = new_folder()
        target = os.path.join(folder, "real")
        write(target, "A=1\n")
        hard_link(target, os.path.join(folder, "real2"))
        link = os.path.join(folder, ".env")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("no symbolic links here")
        self.assertIsNone(store_mod.other_links(link))


class TestReadmeSaysWhatForgetCanAndCannotDo(unittest.TestCase):
    def test_the_forget_paragraph(self):
        with open(os.path.join(_isolation.REPO, "README.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("interrupted write", "hard link", "cannot know about"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
