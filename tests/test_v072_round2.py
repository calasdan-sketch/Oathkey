"""0.7.2: the second review's findings. Fake clipboard, vendor, window, helper
programs and secret store; key-like values are built from pieces; waits are
conditions with deadlines."""

import ctypes
import io
import json
import os
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
import test_v070_capture as base
from safeeasyapi import agent as agent_mod
from safeeasyapi import agentsetup
from safeeasyapi import allowcmd
from safeeasyapi import capture as capture_mod
from safeeasyapi import cli as cli_mod
from safeeasyapi import clipboard as clip_mod
from safeeasyapi import consent as consent_mod
from safeeasyapi import dialog as dialog_mod
from safeeasyapi import hook as hook_mod
from safeeasyapi import mcp as mcp_mod
from safeeasyapi import safeexec
from safeeasyapi import skillcmd
from safeeasyapi import validate as validate_mod

GH_KEY, OTHER, CATALOG = base.GH_KEY, base.OTHER, base.CATALOG
until, wait_for = base.until, base.wait_for


def st(uid=0, mode=0o100755):
    return types.SimpleNamespace(st_uid=uid, st_mode=mode)


# ------------------------------------------------------------------ F1

@unittest.skipIf(os.name == "nt", "POSIX ownership rules")
class TestTrustedHelpers(unittest.TestCase):
    def fake(self, table):
        def statfn(path):
            if path not in table:
                raise FileNotFoundError(path)
            return table[path]
        return statfn

    def test_a_root_owned_helper_in_a_system_folder_is_found_by_absolute_path(self):
        table = {"/usr/bin/zenity": st(), "/usr/bin": st(0, 0o040755)}
        self.assertEqual(safeexec.find("zenity", statfn=self.fake(table)), "/usr/bin/zenity")

    def test_a_helper_owned_by_the_user_is_refused(self):
        table = {"/usr/bin/zenity": st(1000), "/usr/bin": st(0, 0o040755)}
        self.assertIsNone(safeexec.find("zenity", statfn=self.fake(table)))

    def test_a_helper_others_can_write_is_refused(self):
        for mode in (0o100775, 0o100757):
            table = {"/usr/bin/zenity": st(0, mode), "/usr/bin": st(0, 0o040755)}
            self.assertIsNone(safeexec.find("zenity", statfn=self.fake(table)), oct(mode))

    def test_a_folder_the_user_can_write_is_refused(self):
        table = {"/usr/local/bin/xclip": st(), "/usr/local/bin": st(1000, 0o040755)}
        self.assertIsNone(safeexec.find("xclip", statfn=self.fake(table)))
        table = {"/usr/local/bin/xclip": st(), "/usr/local/bin": st(0, 0o040777)}
        self.assertIsNone(safeexec.find("xclip", statfn=self.fake(table)))

    def test_only_the_fixed_folders_are_looked_in_never_path(self):
        seen = []

        def statfn(path):
            seen.append(path)
            raise FileNotFoundError(path)
        with mock.patch.dict(os.environ, {"PATH": "/tmp/evil:" + os.environ.get("PATH", "")}):
            self.assertIsNone(safeexec.find("zenity", statfn=statfn))
        self.assertEqual(sorted({os.path.dirname(p) for p in seen}),
                         sorted(safeexec.SYSTEM_DIRS))

    def test_names_that_are_paths_are_refused(self):
        for bad in ("../zenity", "/tmp/zenity", ".zenity", "", "a\\b"):
            self.assertIsNone(safeexec.find(bad, statfn=self.fake({})), bad)

    def test_the_environment_is_minimal_and_the_path_fixed(self):
        env = safeexec.env({"PATH": "/tmp/evil", "LD_PRELOAD": "/tmp/x.so", "PYTHONPATH": "/x",
                            "DISPLAY": ":0", "HOME": "/home/u", "SECRET": "s"})
        self.assertEqual(env["PATH"], safeexec.FIXED_PATH)
        self.assertEqual(env["DISPLAY"], ":0")
        for gone in ("LD_PRELOAD", "PYTHONPATH", "SECRET"):
            self.assertNotIn(gone, env)

    def test_run_needs_an_absolute_program_and_passes_the_fixed_env(self):
        with self.assertRaises(OSError):
            safeexec.run(["zenity"])
        with mock.patch.object(safeexec.subprocess, "run") as run:
            safeexec.run(["/usr/bin/zenity", "--x"], timeout=1)
        self.assertEqual(run.call_args.kwargs["env"]["PATH"], safeexec.FIXED_PATH)

    def test_the_clipboard_backend_uses_the_trusted_paths(self):
        calls = []

        def find(name):
            return "/usr/bin/" + name if name in ("xclip",) else None

        def run(argv, **kw):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0, stdout=b"text")
        with mock.patch.object(sys, "platform", "linux"):
            get, clear = clip_mod.backend(find=find)
        self.assertEqual(clip_mod._command(["/usr/bin/xclip", "-o"], ["/usr/bin/xclip", "-i"], run)[0](), "text")
        self.assertTrue(get)
        with mock.patch.object(sys, "platform", "linux"):
            with self.assertRaises(clip_mod.Unavailable):
                clip_mod.backend(find=lambda n: None)


class TestDialogBranches(unittest.TestCase):
    ENV = {"DISPLAY": ":0"}

    def which(self, *have):
        return lambda name: "/usr/bin/" + name if name in have else None

    def runner(self, returncode=0, stdout=b"", boom=None):
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            if boom:
                raise boom
            return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"")
        run.calls = calls
        return run

    def test_osascript_allow_deny_and_gave_up(self):
        w = self.which("osascript")
        for out, rc, want in ((b"button returned:Allow", 0, True), (b"button returned:Deny", 0, False),
                              (b"button returned:Allow, gave up:true", 0, None), (b"", 1, False)):
            run = self.runner(rc, out)
            self.assertIs(dialog_mod.confirm("t", "m", "darwin", {}, w, run), want, out)
            self.assertEqual(run.calls[0][0][0], "/usr/bin/osascript")
        self.assertEqual(run.calls[0][0][1], "-e")

    def test_zenity_is_sent_no_markup_and_a_timeout_is_not_a_no(self):
        w = self.which("zenity")
        run = self.runner(0)
        self.assertTrue(dialog_mod.confirm("t", "m <b>x</b>", "linux", self.ENV, w, run))
        argv = run.calls[0][0]
        self.assertEqual(argv[0], "/usr/bin/zenity")
        self.assertIn("--no-markup", argv)
        self.assertIn("--default-cancel", argv)
        self.assertFalse(dialog_mod.confirm("t", "m", "linux", self.ENV, w, self.runner(1)))
        self.assertIsNone(dialog_mod.confirm("t", "m", "linux", self.ENV, w, self.runner(5)))

    def test_kdialog_and_its_timeout(self):
        w = self.which("kdialog")
        run = self.runner(0)
        self.assertTrue(dialog_mod.confirm("t", "m", "linux", self.ENV, w, run))
        self.assertEqual(run.calls[0][0][0], "/usr/bin/kdialog")
        self.assertFalse(dialog_mod.confirm("t", "m", "linux", self.ENV, w, self.runner(1)))
        slow = self.runner(boom=subprocess.TimeoutExpired("kdialog", 1))
        self.assertIsNone(dialog_mod.confirm("t", "m", "linux", self.ENV, w, slow))

    def test_a_crash_is_a_no_never_a_yes(self):
        w = self.which("zenity")
        self.assertIs(dialog_mod.confirm("t", "m", "linux", self.ENV, w,
                                         self.runner(boom=OSError("x"))), False)

    def test_no_window_means_none(self):
        self.assertIsNone(dialog_mod.confirm("t", "m", "linux", {}, self.which("zenity"), self.runner()))
        self.assertIsNone(dialog_mod.confirm("t", "m", "linux", {"DISPLAY": ":0", "SSH_CONNECTION": "x"},
                                             self.which("zenity"), self.runner()))
        self.assertIsNone(dialog_mod.confirm("t", "m", "linux", self.ENV, self.which(), self.runner()))
        self.assertIsNone(dialog_mod.confirm("t", "m", "darwin", {}, self.which(), self.runner()))

    def test_windows_goes_to_the_message_box(self):
        self.assertTrue(dialog_mod.confirm("t", "m", "win32", {}, message_box=lambda t, m: True))
        self.assertFalse(dialog_mod.confirm("t", "m", "win32", {}, message_box=lambda t, m: False))
        self.assertIsNone(dialog_mod.confirm("t", "m", "win32", {}, message_box=lambda t, m: None))

    def test_look_alike_letters_and_long_paths_cannot_mislead(self):
        self.assertEqual(dialog_mod.plain("pr\u043ej\u0435ct"), "pr?j?ct")
        self.assertEqual(dialog_mod.plain("a\x07b\x1b[0m"), "a?b?[0m")
        long = "/home/u/" + "d/" * 200 + "project"
        short = dialog_mod.short_path(long)
        self.assertLessEqual(len(short), dialog_mod.MAX_PATH)
        self.assertTrue(short.startswith("...") and short.endswith("project"))
        run = self.runner(0)
        dialog_mod.confirm("t", "p\u0430th", "linux", self.ENV, self.which("zenity"), run)
        self.assertNotIn("\u0430", " ".join(run.calls[0][0]))


class TestWindowsMessageBox(unittest.TestCase):
    def patched(self, user32):
        return mock.patch.object(ctypes, "windll", types.SimpleNamespace(user32=user32), create=True)

    def test_the_timeout_form_answers_yes_no_and_timed_out(self):
        for code, want in ((6, True), (7, False), (32000, None)):
            seen = {}

            def fn(hwnd, text, caption, flags, lang, ms, code=code):
                seen["ms"] = ms
                return code
            with self.patched(types.SimpleNamespace(MessageBoxTimeoutW=fn)):
                self.assertIs(dialog_mod._message_box("t", "m", seconds=5), want, code)
            self.assertEqual(seen["ms"], 5000)

    def test_without_it_a_watchdog_form_still_answers(self):
        with self.patched(types.SimpleNamespace(MessageBoxW=lambda *a: 6)):
            self.assertTrue(dialog_mod._message_box("t", "m", seconds=5))
        with self.patched(types.SimpleNamespace(MessageBoxW=lambda *a: 7)):
            self.assertFalse(dialog_mod._message_box("t", "m", seconds=5))

    def test_the_watchdog_closes_a_box_nobody_answers(self):
        posted = []
        gate = threading.Event()

        def box(*a):
            gate.wait(10)
            return 7
        user32 = types.SimpleNamespace(
            MessageBoxW=box, FindWindowW=lambda cls, title: 99,
            PostMessageW=lambda h, m, w, l: (posted.append((h, m)), gate.set()))
        with self.patched(user32):
            self.assertIsNone(dialog_mod._message_box("t", "m", seconds=0.05))
        self.assertEqual(posted, [(99, 0x10)])


# ------------------------------------------------------------------ F4 / F1 consent store

class TestConsentReplayAndStores(base.Base):
    def read_bytes(self):
        with open(self.consent, "rb") as f:
            return f.read()

    def write_bytes(self, data):
        with open(self.consent, "wb") as f:
            f.write(data)

    def test_an_old_copy_of_the_file_does_not_verify_after_a_revoke(self):
        self.allow("github")
        old = self.read_bytes()
        consent_mod.revoke(self.proj, "github", self.consent, self.secret)
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))
        self.write_bytes(old)                      # put the undone grant back
        self.assertEqual(consent_mod.read_grants(self.consent, self.secret), ([], "stale"))
        self.assertEqual(self.start(self.manager())["state"], "consent_needed")

    def test_an_old_copy_is_stale_after_any_later_grant(self):
        self.allow("github")
        old = self.read_bytes()
        self.allow("stripe")
        self.write_bytes(old)
        self.assertEqual(consent_mod.read_grants(self.consent, self.secret)[1], "stale")

    def test_the_counter_is_in_the_signed_text(self):
        self.allow()
        data = json.loads(self.read_bytes())
        data["counter"] += 1
        self.write_bytes(json.dumps(data).encode())
        self.assertEqual(consent_mod.read_grants(self.consent, self.secret)[1], "forged")

    def test_the_counter_climbs_on_every_write(self):
        self.allow("github")
        a = consent_mod.split(self.secret.load())[1]
        self.allow("stripe")
        consent_mod.revoke(self.proj, "stripe", self.consent, self.secret)
        self.assertEqual(consent_mod.split(self.secret.load())[1], a + 2)

    def test_the_key_part_is_kept_when_the_counter_climbs(self):
        self.allow("github")
        key = consent_mod.split(self.secret.load())[0]
        self.allow("stripe")
        self.assertEqual(consent_mod.split(self.secret.load())[0], key)
        self.assertIsNotNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_a_save_that_fails_changes_nothing_on_disk(self):
        self.allow("github")
        before = self.read_bytes()

        class Broken(base.MemorySecret):
            def save(self, secret):
                raise OSError("locked")
        broken = Broken()
        broken.secret = self.secret.secret
        with self.assertRaises(OSError):
            consent_mod.grant(self.proj, "stripe", False, self.consent, None, broken)
        self.assertEqual(self.read_bytes(), before)

    def test_two_writers_at_once_both_end_up_verified(self):
        store = consent_mod.FileSecret(os.path.join(os.path.dirname(self.consent), "k"))
        errors = []

        def one(service):
            try:
                consent_mod.grant(self.proj, service, False, self.consent, None, store)
            except Exception as e:                      # pragma: no cover
                errors.append(e)
        threads = [threading.Thread(target=one, args=(s,)) for s in ("github", "stripe", "vercel", "aws")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(g["service"] for g in consent_mod.read_grants(self.consent, store)[0]),
                         ["aws", "github", "stripe", "vercel"])

    def test_a_stale_lock_file_does_not_block_forever(self):
        folder = os.path.dirname(self.consent)
        lock = os.path.join(folder, ".lock")
        with open(lock, "w") as f:
            f.write("")
        os.utime(lock, (time.time() - 3600, time.time() - 3600))
        self.allow()
        self.assertFalse(os.path.exists(lock))
        self.assertIsNotNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_the_secret_file_is_created_private_and_not_over_an_existing_one(self):
        path = os.path.join(_isolation.mktemp(), "k")
        store = consent_mod.FileSecret(path)
        store.save(b"a" * 40)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        store.save(b"b" * 40)                      # exists: replaced, still private
        self.assertEqual(store.load(), b"b" * 40)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")


class TestSecretStoreChoice(unittest.TestCase):
    def fake_run(self, rc=0, out=b"", log=None):
        def run(argv, **kw):
            if log is not None:
                log.append((argv, kw))
            return types.SimpleNamespace(returncode=rc, stdout=out, stderr=b"")
        return run

    def find(self, *have):
        return lambda name: "/usr/bin/" + name if name in have else None

    def test_choices_by_platform(self):
        self.assertIsInstance(consent_mod.pick_secret_store("win32", self.find()), consent_mod.DpapiSecret)
        mac = consent_mod.pick_secret_store("darwin", self.find("security"))
        self.assertEqual((type(mac).__name__, mac.primary.kind), ("ChainSecret", "keychain"))
        lin = consent_mod.pick_secret_store("linux", self.find("secret-tool"))
        self.assertEqual(lin.primary.kind, "secret-tool")
        plain = consent_mod.pick_secret_store("linux", self.find())
        self.assertIsInstance(plain, consent_mod.FileSecret)
        self.assertTrue(plain.advisory)

    def test_the_keychain_commands_use_the_trusted_path(self):
        log = []
        s = consent_mod.CommandSecret("keychain", self.fake_run(0, b"6162\n", log), self.find("security"))
        self.assertEqual(s.load(), b"ab")
        s.save(b"xy")
        self.assertEqual(log[0][0][0], "/usr/bin/security")
        self.assertEqual(log[1][0][:2], ["/usr/bin/security", "add-generic-password"])
        t = consent_mod.CommandSecret("secret-tool", self.fake_run(0, b"6162", log), self.find("secret-tool"))
        self.assertEqual(t.load(), b"ab")
        t.save(b"xy")
        self.assertEqual(log[-1][1]["input"], b"7879")

    def test_an_untrusted_or_missing_tool_is_no_secret_and_no_save(self):
        s = consent_mod.CommandSecret("secret-tool", self.fake_run(), self.find())
        self.assertIsNone(s.load())
        with self.assertRaises(OSError):
            s.save(b"x")

    def test_a_tool_that_fails_or_answers_oddly(self):
        s = consent_mod.CommandSecret("keychain", self.fake_run(1), self.find("security"))
        self.assertIsNone(s.load())
        with self.assertRaises(OSError):
            s.save(b"x")
        odd = consent_mod.CommandSecret("keychain", self.fake_run(0, b"not hex"), self.find("security"))
        self.assertIsNone(odd.load())

    def test_when_the_keyring_cannot_save_the_file_is_used_and_the_grant_works(self):
        folder = _isolation.mktemp()
        failing = consent_mod.CommandSecret("secret-tool", self.fake_run(1), self.find("secret-tool"))
        chain = consent_mod.ChainSecret(failing, consent_mod.FileSecret(os.path.join(folder, "k")))
        path = os.path.join(folder, "consent.json")
        proj = _isolation.mktemp()
        consent_mod.grant(proj, "github", False, path, None, chain)
        self.assertIsNotNone(consent_mod.consent_for(proj, "github", path, chain))
        self.assertEqual(chain.kind, "file")
        self.assertTrue(chain.advisory)

    def test_the_newer_of_two_readings_wins(self):
        a, b = base.MemorySecret(), base.MemorySecret()
        a.secret = consent_mod.pack(b"k" * 32, 5)
        b.secret = consent_mod.pack(b"k" * 32, 9)
        chain = consent_mod.ChainSecret(a, b)
        self.assertEqual(consent_mod.split(chain.load())[1], 9)

    def test_file_and_blob_helpers(self):
        key, counter = consent_mod.split(consent_mod.pack(b"k" * 32, 7))
        self.assertEqual((key, counter), (b"k" * 32, 7))
        self.assertEqual(consent_mod.split(b"short-old-secret-1"), (b"short-old-secret-1", 0))
        self.assertIsNone(consent_mod.FileSecret(os.path.join(_isolation.mktemp(), "nope")).load())

    def test_integrity_says_when_it_is_only_advisory(self):
        consent_mod.set_secret_store(consent_mod.FileSecret(os.path.join(_isolation.mktemp(), "k")))
        self.addCleanup(consent_mod.set_secret_store, None)
        self.assertIn("advisory", consent_mod.integrity())


class TestAllowAgentWhenTheGrantFails(base.Base):
    def test_it_says_so_and_changes_nothing(self):
        class Broken(base.MemorySecret):
            def save(self, secret):
                raise OSError(13, "keyring locked")
        args = type("A", (), dict(service="github", revoke=False, list=False,
                                  allow_clipboard_history=False))()
        out = io.StringIO()
        code = allowcmd.cmd_allow_agent(args, CATALOG, ask=lambda p: "yes", terminal=lambda: True,
                                        out=out, consent_file=self.consent, cwd=self.proj,
                                        store=Broken())
        self.assertEqual(code, 1)
        self.assertIn("could NOT be saved", out.getvalue())
        self.assertFalse(os.path.exists(self.consent))


# ------------------------------------------------------------------ capture manager

class Window:
    """A fake permission window that can be held open."""

    def __init__(self, answer=True):
        self.answer = answer
        self.asked = []
        self.release = threading.Event()
        self.hold = False

    def __call__(self, title, text):
        self.asked.append((title, text))
        if self.hold:
            self.release.wait(20)
        return self.answer


class TestWindowConsentLifecycle(base.Base):
    def mgr_with(self, window):
        self.addCleanup(window.release.set)
        return self.manager(window_available=lambda: True, ask_person=window)

    def test_window_consent_is_memory_only_and_ends_with_the_session(self):
        w = Window(True)
        mgr = self.mgr_with(w)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_granted"))
        self.assertEqual(self.start(mgr, timeout=30)["state"], "waiting")
        mgr.cancel()
        self.assertFalse(os.path.exists(self.consent))
        fresh = self.manager()                      # a new server: the yes is gone
        self.assertEqual(self.start(fresh)["state"], "consent_needed")

    def test_no_window_answer_is_not_a_denial_and_can_be_asked_again(self):
        w = Window(None)
        mgr = self.mgr_with(w)
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_needed"))
        self.assertEqual(self.start(mgr)["state"], "consent_pending")     # asked again
        self.assertTrue(wait_for(lambda: len(w.asked) == 2))
        self.assertNotEqual(mgr.status(0)["state"], "consent_denied")

    def test_a_pending_question_makes_status_wait_for_the_answer(self):
        w = Window(True)
        w.hold = True
        mgr = self.mgr_with(w)
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        threading.Timer(0.3, w.release.set).start()
        began = time.monotonic()
        out = mgr.status(8)
        took = time.monotonic() - began
        self.assertEqual(out["state"], "consent_granted")
        self.assertGreater(took, 0.15)              # it waited ...
        self.assertLess(took, 6)                    # ... but not the whole time

    def test_a_pending_question_that_nobody_answers_ends_the_wait(self):
        w = Window(True)
        w.hold = True
        mgr = self.mgr_with(w)
        self.start(mgr)
        began = time.monotonic()
        self.assertEqual(mgr.status(0.3)["state"], "consent_pending")
        self.assertLess(time.monotonic() - began, 5)

    def test_asking_twice_while_a_window_is_open_shows_one_window(self):
        w = Window(True)
        w.hold = True
        mgr = self.mgr_with(w)
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: len(w.asked) == 1))
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertEqual(len(w.asked), 1)

    def test_an_old_answer_is_not_reported_forever(self):
        w = Window(True)
        mgr = self.mgr_with(w)
        clock = [100.0]
        mgr.now = lambda: clock[0]
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_granted"))
        clock[0] += capture_mod.STALE_AFTER + 1
        self.assertEqual(mgr.status(0)["state"], "idle")

    def test_replace_granted_tells_the_agent_to_pass_replace_true(self):
        w = Window(True)
        mgr = self.mgr_with(w)
        with open(os.path.join(self.proj, ".env"), "w") as f:
            f.write("GITHUB_TOKEN=already-there-12345\n")
        self.allow()
        self.assertEqual(self.start(mgr, replace=True)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "replace_granted"))
        self.assertIn("replace=true", mgr.status(0)["message"])

    def test_the_window_text_is_plain_and_cut(self):
        w = Window(False)
        mgr = self.mgr_with(w)
        deep = os.path.join(self.proj, *["d" * 20] * 12)
        os.makedirs(deep)
        mgr.start("github", CATALOG["github"], deep)
        self.assertTrue(wait_for(lambda: w.asked))
        text = w.asked[0][1]
        self.assertIn("...", text)
        self.assertTrue(all(ord(c) < 128 for c in text))


class TestAccountConfirmation(base.Base):
    def setUp(self):
        super().setUp()
        self.allow()
        self.window = Window(True)
        self.addCleanup(self.window.release.set)
        result = validate_mod.Result("valid")
        result.identity = "octo-cat"
        self.vendor.answer = result

    def mgr(self):
        return self.manager(window_available=lambda: True, ask_person=self.window)

    def test_the_person_sees_the_account_and_says_yes(self):
        mgr = self.mgr()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "stored")
        self.assertIs(done["account_confirmed_by_person"], True)
        self.assertEqual(len(self.window.asked), 1)
        title, text = self.window.asked[0]
        self.assertIn("octo-cat", text)
        self.assertNotIn(GH_KEY, title + text)
        self.assertNoKey(done)

    def test_a_no_stores_nothing(self):
        self.window.answer = False
        mgr = self.mgr()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "failed")
        self.assertIn("did not confirm", done["message"])
        self.assertEqual(self.env_text(), "")
        self.assertNoKey(done)

    def test_no_answer_in_time_stores_nothing(self):
        self.window.answer = None
        mgr = self.mgr()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "failed")
        self.assertIn("in time", done["message"])
        self.assertEqual(self.env_text(), "")

    def test_the_state_is_confirming_while_the_window_is_open(self):
        self.window.hold = True
        mgr = self.mgr()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "confirming"))
        self.assertEqual(self.env_text(), "")
        self.window.release.set()
        self.assertEqual(until(mgr)["state"], "stored")

    def test_without_a_window_the_account_is_not_confirmed_and_it_says_so(self):
        mgr = self.manager()                        # window_available False
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "stored")
        self.assertNotIn("account_confirmed_by_person", done)


class TestStatusWait(base.Base):
    def test_status_blocks_returns_on_the_change_and_not_at_the_end_of_the_wait(self):
        self.allow()
        gate = threading.Event()
        self.addCleanup(gate.set)

        def slow(spec, key, timeout=10.0):
            gate.wait(20)
            return validate_mod.Result("valid")
        mgr = self.manager(validate_fn=slow)
        self.start(mgr, timeout=60)
        threading.Timer(0.4, self.clip.copy, args=(GH_KEY,)).start()
        began = time.monotonic()
        out = mgr.status(wait=8)
        took = time.monotonic() - began
        self.assertEqual(out["state"], "validating")        # the CHANGE, not the old "waiting"
        self.assertGreater(took, 0.25)                      # it blocked ...
        self.assertLess(took, 6)                            # ... and came back early
        gate.set()
        self.assertEqual(until(mgr)["state"], "stored")

    def test_status_gives_up_at_the_end_of_the_wait_when_nothing_changes(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=60)
        began = time.monotonic()
        out = mgr.status(wait=0.4)
        took = time.monotonic() - began
        self.assertEqual(out["state"], "waiting")
        self.assertGreaterEqual(took, 0.3)
        self.assertLess(took, 5)


class TestCancelAndFinish(base.Base):
    def test_cancel_while_storing_is_too_late(self):
        self.allow()
        gate, inside = threading.Event(), threading.Event()
        self.addCleanup(gate.set)

        def blocking(recipe, env_file, store):
            def store_fn(var, key):
                inside.set()
                gate.wait(20)
                return "stored"
            return store_fn
        mgr = self.manager(store_factory=blocking)
        self.start(mgr, timeout=60)
        self.clip.copy(GH_KEY)
        self.assertTrue(inside.wait(20))
        out = mgr.cancel()
        self.assertEqual(out["state"], "storing")
        self.assertEqual(out["cancel"], "too_late")
        gate.set()
        self.assertEqual(until(mgr)["state"], "stored")

    def test_every_ending_carries_finished_at(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=60)
        self.clip.copy(GH_KEY)
        self.assertIn("finished_at", until(mgr))
        os.unlink(os.path.join(self.proj, ".env"))          # so the next start is not "already_stored"
        mgr2 = self.manager()
        self.start(mgr2, timeout=0.05)
        self.assertIn("finished_at", until(mgr2))
        mgr3 = self.manager()
        self.start(mgr3, timeout=60)
        self.assertIn("finished_at", mgr3.cancel())


class TestClearVerifiedTruth(unittest.TestCase):
    def test_a_clear_that_says_it_failed_is_not_verified_even_if_the_read_is_empty(self):
        self.assertFalse(clip_mod.clear_verified(lambda: "", lambda: False, wait=0.02, poll=0.001))

    def test_an_unreadable_clipboard_is_not_proof_of_empty(self):
        def boom():
            raise OSError("cannot open")
        self.assertFalse(clip_mod.clear_verified(boom, lambda: True, wait=0.02, poll=0.001))

    def test_empty_after_a_good_clear_is_verified(self):
        self.assertTrue(clip_mod.clear_verified(lambda: "  ", lambda: True, wait=0.02))
        self.assertTrue(clip_mod.clear_verified(lambda: "", lambda: None, wait=0.02))

    def test_a_command_backend_that_fails_raises_instead_of_reporting_empty(self):
        def run(argv, **kw):
            return types.SimpleNamespace(returncode=127, stdout=b"")
        get, clear = clip_mod._command(["/usr/bin/x"], ["/usr/bin/x"], run)
        with self.assertRaises(OSError):
            get()
        empty = lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout=b"")
        self.assertEqual(clip_mod._command(["/usr/bin/x"], ["/usr/bin/x"], empty)[0](), "")
        self.assertFalse(clear())

    def test_connect_style_waiting_survives_an_unreadable_moment(self):
        calls = iter([OSError("busy"), "", GH_KEY])

        def get():
            v = next(calls)
            if isinstance(v, Exception):
                raise v
            return v
        got = clip_mod.wait_for_key("^gh" + "p_", set(), get, lambda: True, wait=5, poll=0.001)
        self.assertEqual(got, GH_KEY)


class TestStrictGatesAndIdentity(unittest.TestCase):
    def gate(self, service):
        return capture_mod._gate(capture_mod.recipes_mod.fields(CATALOG[service])[0])

    def test_github_wants_the_documented_length_and_nothing_after_it(self):
        g = self.gate("github")
        self.assertTrue(clip_mod.looks_like(GH_KEY, g))
        self.assertFalse(clip_mod.looks_like(GH_KEY + "x", g))
        self.assertFalse(clip_mod.looks_like(GH_KEY[:-1], g))
        self.assertFalse(clip_mod.looks_like(GH_KEY + "\u00e9", g))

    def test_other_services_are_anchored_too(self):
        stripe = self.gate("stripe")
        self.assertTrue(clip_mod.looks_like("sk" + "_test_" + "A1b2C3d4E5f6G7h8", stripe))
        self.assertFalse(clip_mod.looks_like("sk" + "_test_" + "A1b2C3d4E5f6G7h8-oops", stripe))
        self.assertFalse(clip_mod.looks_like("r8" + "_" + "A" * 37 + "Z", self.gate("replicate")))
        self.assertTrue(clip_mod.looks_like("r8" + "_" + "A" * 37, self.gate("replicate")))

    def test_the_loose_gate_of_connect_is_unchanged(self):
        loose = capture_mod.recipes_mod.fields(CATALOG["stripe"])[0]["accept"]
        self.assertTrue(clip_mod.looks_like("sk" + "_test_" + "A1b2C3d4E5f6G7h8-oops", loose))

    def test_identity_is_a_plain_login_or_nothing(self):
        ok = validate_mod._identity("login", json.dumps({"login": "octo-cat9"}).encode())
        self.assertEqual(ok, "octo-cat9")
        for bad in ("a b", "octo.cat", "x" * 40, "o\u0441to", "octo\ncat", "", "a@b", "-" * 5 + "\n"):
            self.assertIsNone(validate_mod._identity("login", json.dumps({"login": bad}).encode()), repr(bad))
        self.assertEqual(validate_mod._identity("login", json.dumps({"login": "a" * 39}).encode()), "a" * 39)


# ------------------------------------------------------------------ hook

class TestHookRound2(unittest.TestCase):
    def denied(self, text, tool="Bash", field="command"):
        status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                                                 "tool_input": {field: text}}))
        return bool(out)

    def test_the_keyring_readers_are_seen_through_quotes(self):
        for cmd in ("sec''ret-tool lookup service x", "'secret-tool' lookup a b",
                    'secret-"tool" search x y', "sec^ret-tool lookup a b",
                    "s\\ecret-tool lookup a b", "secu''rity find-generic-password -w"):
            self.assertTrue(self.denied(cmd), cmd)

    def test_the_consent_files_by_bare_name_and_relative_path(self):
        for cmd in ("cat consent.key", "cat agent-consent.json", "ls .safeeasyapi",
                    "type .\\safeeasyapi\\x", "cat .s''afeeasyapi/x", "cat ../.safeeasyapi/consent.key"):
            self.assertTrue(self.denied(cmd), cmd)

    def test_writing_there_with_a_relative_path_is_refused(self):
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            field = "notebook_path" if tool == "NotebookEdit" else "file_path"
            self.assertTrue(self.denied(".safeeasyapi/agent-consent.json", tool, field), tool)
            self.assertTrue(self.denied("sub/.safeeasyapi/consent.key", tool, field), tool)

    def test_ordinary_use_is_untouched(self):
        for cmd in ("safeeasyapi list", "pip install safeeasyapi", "python -m safeeasyapi mcp",
                    "echo safe and easy", "git commit -m 'safeeasyapi 0.7.2'"):
            self.assertFalse(self.denied(cmd), cmd)
        self.assertFalse(self.denied("src/app.py", "Write", "file_path"))


# ------------------------------------------------------------------ MCP / agent

class TestMcpTexts(unittest.TestCase):
    def tool(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, CATALOG)
        return next(t for t in r["result"]["tools"] if t["name"] == "capture_key")

    def test_the_text_matches_the_real_waits_and_lists_every_state(self):
        t = self.tool()
        text = t["description"]
        self.assertIn("25 s", text)
        self.assertIn("45", text)
        self.assertNotIn("60", text)
        self.assertEqual(capture_mod.DEFAULT_STATUS_WAIT, 25.0)
        self.assertEqual(capture_mod.MAX_STATUS_WAIT, 45.0)
        for state in ("consent_granted", "replace_granted", "confirming", "validating", "storing"):
            self.assertIn(state, text)
        self.assertIn("45", t["inputSchema"]["properties"]["wait_seconds"]["description"])

    def test_every_supported_protocol_is_echoed_and_others_get_the_oldest(self):
        for version in mcp_mod.SUPPORTED_PROTOCOLS:
            r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": {"protocolVersion": version}}, CATALOG)
            self.assertEqual(r["result"]["protocolVersion"], version)
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "1999-01-01"}}, CATALOG)
        self.assertEqual(r["result"]["protocolVersion"], "2024-11-05")
        self.assertIn("2025-06-18", mcp_mod.SUPPORTED_PROTOCOLS)

    def test_the_word_false_is_false(self):
        for value in ("false", "False", "no", "0", "", None, False, 0, [], "null"):
            self.assertFalse(agent_mod._truthy(value), repr(value))
        for value in (True, "true", "True", "1", 1):
            self.assertTrue(agent_mod._truthy(value), repr(value))

    def test_replace_as_the_string_false_does_not_replace(self):
        seen = {}

        class M:
            def start(self, slug, recipe, cwd, timeout, replace):
                seen["replace"] = replace
                return {"state": "idle"}
        agent_mod.capture_key({"service": "github", "replace": "false"}, CATALOG, None, M())
        self.assertIs(seen["replace"], False)


class TestMcpDefaultStore(unittest.TestCase):
    def test_default_store_reaches_the_manager(self):
        self.addCleanup(capture_mod.set_manager, None)
        with mock.patch.object(mcp_mod, "serve", return_value=0):
            self.assertEqual(cli_mod.main(["mcp", "--default-store", "keychain"]), 0)
        self.assertEqual(capture_mod.default_manager().default_store, "keychain")

    def test_the_default_leaves_the_manager_alone(self):
        capture_mod.set_manager(None)
        self.addCleanup(capture_mod.set_manager, None)
        with mock.patch.object(mcp_mod, "serve", return_value=0):
            cli_mod.main(["mcp"])
        self.assertEqual(capture_mod.default_manager().default_store, "env")


# ------------------------------------------------------------------ agentsetup

class A:
    def __init__(self, client, write=False):
        self.client, self.write = client, write


class TestSetupAgent(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.cwd = _isolation.mktemp()

    def run_setup(self, client, write=False, keychain_ok=False, platform=None):
        out = io.StringIO()
        code = agentsetup.cmd_setup_agent(A(client, write), out, home=self.home, cwd=self.cwd,
                                          keychain_ok=keychain_ok, platform=platform)
        return code, out.getvalue()

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_server_entry_uses_this_python_and_the_keychain_only_for_the_others(self):
        e = agentsetup.server_entry("cursor", True)
        self.assertEqual(e["command"], os.path.abspath(sys.executable))
        self.assertEqual(e["args"][-2:], ["--default-store", "keychain"])
        self.assertNotIn("--default-store", agentsetup.server_entry("claude-code", True)["args"])
        self.assertNotIn("--default-store", agentsetup.server_entry("cursor", False)["args"])

    def test_config_paths(self):
        c = agentsetup.config_path
        self.assertTrue(c("cursor", "/h", "/w").endswith(os.path.join(".cursor", "mcp.json")))
        self.assertTrue(c("gemini", "/h", "/w").endswith(os.path.join(".gemini", "settings.json")))
        self.assertTrue(c("codex", "/h", "/w").endswith(os.path.join(".codex", "config.toml")))
        self.assertIn("Application Support", c("claude-desktop", "/h", "/w", "darwin"))
        self.assertIn(".config", c("claude-desktop", "/h", "/w", "linux"))
        self.assertIsNone(c("claude-code", "/h", "/w"))

    def test_claude_code_prints_a_command_quoted_for_the_shell(self):
        with mock.patch.object(agentsetup.sys, "executable", "/opt/my py/bin/python"):
            code, text = self.run_setup("claude-code", platform="linux")
        self.assertEqual(code, 0)
        self.assertIn("claude mcp add safeeasyapi -- '/opt/my py/bin/python' -m safeeasyapi mcp", text)
        with mock.patch.object(agentsetup.sys, "executable", "C:\\Program Files\\Python\\python.exe"):
            code, text = self.run_setup("claude-code", platform="win32")
        self.assertIn('"', text)
        self.assertIn("claude mcp add safeeasyapi --", text)

    def test_without_write_nothing_is_written(self):
        for client in ("cursor", "gemini", "codex", "claude-desktop"):
            code, text = self.run_setup(client)
            self.assertEqual(code, 0)
            self.assertIn("safeeasyapi", text)
        self.assertEqual(os.listdir(self.cwd), [])

    def test_json_clients_get_the_entry_and_keep_the_rest(self):
        for client in ("cursor", "gemini", "claude-desktop"):
            path = agentsetup.config_path(client, self.home, self.cwd)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"theme": "dark", "mcpServers": {"other": {"command": "x"}}}, f)
            code, text = self.run_setup(client, write=True)
            self.assertEqual(code, 0, client)
            data = json.loads(self.read(path))
            self.assertEqual(data["theme"], "dark")
            self.assertEqual(data["mcpServers"]["other"], {"command": "x"})
            self.assertEqual(data["mcpServers"]["safeeasyapi"]["args"][:3], ["-m", "safeeasyapi", "mcp"])
            code, text = self.run_setup(client, write=True)
            self.assertIn("already has", text)

    def test_a_stale_json_entry_is_updated(self):
        path = agentsetup.config_path("cursor", self.home, self.cwd)
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as f:
            json.dump({"mcpServers": {"safeeasyapi": {"command": "/old/python", "args": []}}}, f)
        self.run_setup("cursor", write=True)
        self.assertEqual(json.loads(self.read(path))["mcpServers"]["safeeasyapi"]["command"],
                         os.path.abspath(sys.executable))

    def test_a_new_config_is_created(self):
        self.run_setup("gemini", write=True)
        path = agentsetup.config_path("gemini", self.home, self.cwd)
        self.assertIn("safeeasyapi", json.loads(self.read(path))["mcpServers"])

    def test_bad_json_is_left_alone_with_a_reason(self):
        path = agentsetup.config_path("cursor", self.home, self.cwd)
        os.makedirs(os.path.dirname(path))
        for content, reason in ((b"{nope", "not valid JSON"), (b"[1, 2]", "list"),
                                (b'{"mcpServers": []}', "not an object"), (b"\xff\xfe\x00", "UTF-8")):
            with open(path, "wb") as f:
                f.write(content)
            code, text = self.run_setup("cursor", write=True)
            self.assertEqual(code, 1, content)
            self.assertIn(reason, text)
            self.assertEqual(self.read(path), content)

    def test_a_byte_order_mark_and_windows_line_ends_survive(self):
        path = agentsetup.config_path("cursor", self.home, self.cwd)
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(b'\xef\xbb\xbf{\r\n  "mcpServers": {}\r\n}\r\n')
        self.assertEqual(self.run_setup("cursor", write=True)[0], 0)
        raw = self.read(path)
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        json.loads(raw.decode("utf-8-sig"))

    def test_codex_adds_updates_and_keeps_the_other_tables(self):
        path = agentsetup.config_path("codex", self.home, self.cwd)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write('model = "x"\n\n[mcp_servers.safeeasyapi]\ncommand = "/old/python"\n'
                    'args = ["-m", "safeeasyapi", "mcp"]\n\n[mcp_servers.other]\ncommand = "o"\n')
        code, text = self.run_setup("codex", write=True)
        self.assertEqual(code, 0)
        body = self.read(path).decode()
        self.assertNotIn("/old/python", body)
        self.assertIn(os.path.abspath(sys.executable).replace("\\", "\\\\"), body)
        self.assertIn('model = "x"', body)
        self.assertIn("[mcp_servers.other]", body)
        self.assertEqual(body.count("[mcp_servers.safeeasyapi]"), 1)
        self.assertIn("updated", text)
        self.assertIn("already", self.run_setup("codex", write=True)[1])

    def test_codex_new_file_and_undecodable_file(self):
        self.assertEqual(self.run_setup("codex", write=True)[0], 0)
        path = agentsetup.config_path("codex", self.home, self.cwd)
        self.assertIn("[mcp_servers.safeeasyapi]", self.read(path).decode())
        with open(path, "wb") as f:
            f.write(b"\xff\xfe\x00bad")
        code, text = self.run_setup("codex", write=True)
        self.assertEqual(code, 1)
        self.assertEqual(self.read(path), b"\xff\xfe\x00bad")

    def test_toml_keeps_real_letters(self):
        block = agentsetup._toml({"command": "/home/Z\u00f6e/py", "args": ["-m"]})
        self.assertIn("Z\u00f6e", block)
        self.assertNotIn("\\u00f6", block)
        self.assertEqual(agentsetup._command_line(["a b", "c"], "linux"), "'a b' c")
        self.assertEqual(agentsetup._command_line(["a b", "c"], "win32"), '"a b" c')


class TestInstallRules(unittest.TestCase):
    TEXT = "---\nname: x\n---\nBe careful with keys.\n"

    def setUp(self):
        self.base = _isolation.mktemp()
        self.out = io.StringIO()

    def path(self, client="codex"):
        return agentsetup.rules_target(client, self.base)

    def read(self, client="codex"):
        with open(self.path(client), "rb") as f:
            return f.read()

    def test_fresh_install_for_each_client(self):
        for client, name in (("codex", "AGENTS.md"), ("gemini", "GEMINI.md"),
                             ("cursor", os.path.join(".cursor", "rules", "safeeasyapi.mdc"))):
            self.assertEqual(agentsetup.install_rules(client, self.base, self.TEXT, self.out), 0)
            self.assertTrue(self.path(client).endswith(name))
            body = self.read(client).decode()
            self.assertIn(agentsetup.BEGIN, body)
            self.assertIn("Be careful with keys.", body)
            self.assertNotIn("name: x", body)
        self.assertTrue(self.read("cursor").decode().startswith("---\ndescription"))

    def test_an_update_replaces_only_our_block(self):
        with open(self.path(), "w") as f:
            f.write("# My rules\n\nkeep me\n")
        agentsetup.install_rules("codex", self.base, self.TEXT, self.out)
        agentsetup.install_rules("codex", self.base, self.TEXT.replace("careful", "very careful"), self.out)
        body = self.read().decode()
        self.assertIn("keep me", body)
        self.assertIn("very careful", body)
        self.assertNotIn("Be careful", body)
        self.assertEqual(body.count(agentsetup.BEGIN), 1)
        again = io.StringIO()
        agentsetup.install_rules("codex", self.base, self.TEXT.replace("careful", "very careful"), again)
        self.assertIn("up to date", again.getvalue())

    def test_windows_line_ends_and_a_bom_are_kept(self):
        with open(self.path(), "wb") as f:
            f.write(b"\xef\xbb\xbf# Mine\r\n\r\nkeep\r\n")
        agentsetup.install_rules("codex", self.base, self.TEXT, self.out)
        raw = self.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        self.assertIn(b"keep", raw)

    def test_markers_in_the_wrong_order_or_doubled_are_refused_untouched(self):
        for content in (agentsetup.END + "\nx\n" + agentsetup.BEGIN + "\n",
                        agentsetup.BEGIN + "\nonly begin\n",
                        agentsetup.BEGIN + "\na\n" + agentsetup.END + "\n" + agentsetup.BEGIN + "\nb\n" + agentsetup.END + "\n"):
            with open(self.path(), "w") as f:
                f.write(content)
            out = io.StringIO()
            self.assertEqual(agentsetup.install_rules("codex", self.base, self.TEXT, out), 1)
            self.assertEqual(self.read().decode(), content)
            self.assertIn("markers", out.getvalue())

    def test_a_file_that_is_not_text_is_not_touched(self):
        with open(self.path(), "wb") as f:
            f.write(b"\xff\xfe\x00")
        self.assertEqual(agentsetup.install_rules("codex", self.base, self.TEXT, self.out), 1)
        self.assertEqual(self.read(), b"\xff\xfe\x00")

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_a_link_is_not_written_through(self):
        target = os.path.join(_isolation.mktemp(), "elsewhere.md")
        with open(target, "w") as f:
            f.write("x")
        os.symlink(target, self.path())
        self.assertEqual(agentsetup.install_rules("codex", self.base, self.TEXT, self.out), 1)
        with open(target) as f:
            self.assertEqual(f.read(), "x")


class Args:
    def __init__(self, for_client, project=True, yes=True):
        self.for_client, self.project, self.yes = for_client, project, yes


class TestSkillInstallFor(unittest.TestCase):
    def test_for_codex_cursor_gemini_write_their_files(self):
        for client, name in (("codex", "AGENTS.md"), ("cursor", ".cursor/rules/safeeasyapi.mdc"),
                             ("gemini", "GEMINI.md")):
            d = _isolation.mktemp()
            out = io.StringIO()
            self.assertEqual(skillcmd.cmd_skill(Args(client), out, cwd=d), 0)
            with open(os.path.join(d, *name.split("/")), encoding="utf-8") as f:
                self.assertIn("safeeasyapi", f.read())

    def test_for_all_writes_every_file_and_the_claude_skill(self):
        d, home = _isolation.mktemp(), _isolation.mktemp()
        self.assertEqual(skillcmd.cmd_skill(Args("all"), io.StringIO(), home=home, cwd=d), 0)
        for name in ("AGENTS.md", "GEMINI.md"):
            self.assertTrue(os.path.isfile(os.path.join(d, name)))
        self.assertTrue(os.path.isfile(os.path.join(d, ".claude", "skills", "safeeasyapi", "SKILL.md")))

    def test_the_parser_knows_the_option(self):
        d = _isolation.mktemp()
        old = os.getcwd()
        os.chdir(d)
        self.addCleanup(os.chdir, old)
        with mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(cli_mod.main(["skill", "install", "--for", "codex", "--project"]), 0)
        self.assertTrue(os.path.isfile(os.path.join(d, "AGENTS.md")))


if __name__ == "__main__":
    unittest.main()
