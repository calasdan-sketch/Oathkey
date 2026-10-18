"""A recipe is somebody else's text: it must not be able to drive the terminal.

Panel finding (SEA-1): connect printed the recipe's steps, scopes, name and
URLs raw, so a hostile recipe could end a step with ESC[8m (conceal), hide the
validation preview and the cross-domain warning that follow, or forge such a
line with a newline. Now a recipe holding a control or invisible character is
refused when it is loaded, and everything a recipe contributes to the screen
goes through recipes.printable(), which shows such a character as a visible
escape instead of sending it.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from safeeasyapi import cli as cli_mod
from safeeasyapi import connect as connect_mod
from safeeasyapi import recipes as recipes_mod

# Built from code points so that no control or invisible character is typed
# into this file.
ESC = "\x1b"
CONCEAL = ESC + "[8m"            # "conceal": text after it is invisible
OSC_TITLE = ESC + "]0;pwned" + "\x07"
NL, CR, TAB, NUL, BEL = "\n", "\r", "\t", "\x00", "\x07"
C1_CSI = chr(0x9B)
RLO = chr(0x202E)                # right-to-left override
ZERO_WIDTH_SPACE = chr(0x200B)
NBSP = chr(0xA0)
LINE_SEPARATOR = chr(0x2028)
E_ACUTE = chr(0xE9)
CJK = chr(0x4E2D) + chr(0x6587)
EMOJI = chr(0x1F331)


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def only_printable_or_newline(text):
    return all(ch.isprintable() or ch == "\n" for ch in text)


class TestPrintable(unittest.TestCase):
    def test_ordinary_text_is_untouched(self):
        for text in ("", "plain", "Click 'New key' -> Create", "caf" + E_ACUTE,
                     CJK, EMOJI, "a  b", "https://x.test/a?b=c&d=e#f"):
            self.assertEqual(recipes_mod.printable(text), text)

    def test_a_character_that_would_drive_the_terminal_is_shown_as_an_escape(self):
        shown = recipes_mod.printable
        self.assertEqual(shown("a" + CONCEAL), "a\\x1b[8m")
        self.assertEqual(shown(OSC_TITLE), "\\x1b]0;pwned\\x07")
        self.assertEqual(shown("a" + NL + "b"), "a\\x0ab")
        self.assertEqual(shown("a" + CR + "b"), "a\\x0db")
        self.assertEqual(shown("a" + TAB + "b"), "a\\x09b")
        self.assertEqual(shown(NUL), "\\x00")
        self.assertEqual(shown(C1_CSI + "2J"), "\\x9b2J")
        self.assertEqual(shown(RLO), "\\u202e")
        self.assertEqual(shown(ZERO_WIDTH_SPACE), "\\u200b")
        self.assertEqual(shown(NBSP), "\\xa0")
        self.assertEqual(shown(LINE_SEPARATOR), "\\u2028")
        self.assertEqual(shown(chr(0xDC80)), "\\udc80")
        self.assertEqual(shown(chr(0xE000)), "\\ue000")

    def test_whatever_goes_in_only_printable_text_comes_out(self):
        every = "".join(chr(n) for n in range(0x3000) if not 0xD800 <= n < 0xE000)
        every += CJK + EMOJI + chr(0xDC80) + chr(0x10FFFF) + chr(0xE0001)
        shown = recipes_mod.printable(every)
        self.assertTrue(shown.isprintable())
        # nothing printable was changed: what was printable is still there
        for ch in "aZ09 ~" + E_ACUTE + CJK + EMOJI:
            self.assertIn(ch, shown)

    def test_a_value_that_is_not_text_is_shown_as_text(self):
        self.assertEqual(recipes_mod.printable(5), "5")
        self.assertEqual(recipes_mod.printable(None), "None")


# Where in a recipe a hostile string could sit, and how to put it there.
FIELDS = {
    "display": lambda bad: recipe(display="Acme" + bad),
    "step": lambda bad: recipe(steps=["Click" + bad]),
    "second step": lambda bad: recipe(steps=["ok", "Click" + bad]),
    "scope": lambda bad: recipe(scopes=["read" + bad]),
    "docs": lambda bad: dict(recipe(), docs="https://acme.test/docs" + bad),
    "key_url": lambda bad: recipe(key_url="https://acme.test/keys" + bad),
    "validate.url": lambda bad: recipe(validate=dict(
        recipe()["validate"], url="https://acme.test/me" + bad)),
    "validate.method": lambda bad: recipe(validate=dict(
        recipe()["validate"], method="GET" + bad)),
    "validate.headers": lambda bad: recipe(validate=dict(
        recipe()["validate"], headers={"X-Version": "1" + bad})),
    "validate.trusted_hosts": lambda bad: recipe(validate=dict(
        recipe()["validate"], trusted_hosts=["api.acme.test" + bad])),
    "validate.auth.header": lambda bad: recipe(validate=dict(
        recipe()["validate"], auth={"type": "header", "header": "X-Key" + bad})),
}
HOSTILE = [CONCEAL, NL, CR, TAB, NUL, BEL, C1_CSI, OSC_TITLE, RLO,
           ZERO_WIDTH_SPACE, NBSP, LINE_SEPARATOR]


class TestARecipeWithInvisibleTextIsRefused(unittest.TestCase):
    def test_every_field_is_checked_for_every_kind_of_character(self):
        for field, build in FIELDS.items():
            for bad in HOSTILE:
                with self.subTest(field=field, bad=ascii(bad)):
                    with self.assertRaises(recipes_mod.RecipeError) as cm:
                        recipes_mod.validate_recipe(build(bad))
                    message = str(cm.exception)
                    # the refusal is itself safe to print
                    self.assertTrue(message.isprintable(), ascii(message))
                    self.assertIn("control or invisible character", message)

    def test_the_message_names_where_it_is(self):
        with self.assertRaises(recipes_mod.RecipeError) as cm:
            recipes_mod.validate_recipe(recipe(steps=["fine", "bad" + CONCEAL]))
        self.assertIn("steps", str(cm.exception))
        with self.assertRaises(recipes_mod.RecipeError) as cm:
            recipes_mod.validate_recipe(recipe(display="bad" + NL))
        self.assertIn("display", str(cm.exception))

    def test_a_hostile_key_name_is_refused_too(self):
        data = recipe()
        data["validate"] = dict(data["validate"], headers={"X" + CONCEAL: "1"})
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(data)

    def test_ordinary_and_international_text_is_accepted(self):
        recipes_mod.validate_recipe(recipe(
            display="Caf" + E_ACUTE + " " + CJK + " " + EMOJI,
            steps=["Click 'New key', then \"Create\" (it is free)", "Copy it"],
            scopes=["read:user", "repo"]))

    def test_every_shipped_recipe_still_loads(self):
        shipped = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        names = [n[:-5] for n in os.listdir(recipes_mod.RECIPES_DIR)
                 if n.endswith(".json")]
        self.assertTrue(names)
        self.assertEqual(sorted(shipped), sorted(names))

    def write(self, directory, name, data):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_loading_skips_it_with_a_warning_that_is_safe_to_print(self):
        directory = _isolation.mktemp()
        self.write(directory, "good.json", recipe(service="good"))
        self.write(directory, "evil.json", recipe(
            service="evil", steps=["Create a key" + CONCEAL]))
        err = io.StringIO()
        with redirect_stderr(err):
            loaded = recipes_mod.load_recipes(directory)
        self.assertEqual(sorted(loaded), ["good"])
        self.assertIn("evil.json", err.getvalue())
        self.assertTrue(only_printable_or_newline(err.getvalue()),
                        ascii(err.getvalue()))

    def test_a_hostile_file_name_is_shown_as_an_escape(self):
        directory = _isolation.mktemp()
        name = "evil" + CONCEAL + ".json"
        try:
            self.write(directory, name, ["not", "a", "recipe"])
        except OSError:
            self.skipTest("this file system does not allow a control "
                          "character in a file name")
        err = io.StringIO()
        with redirect_stderr(err):
            recipes_mod.load_recipes(directory)
        self.assertIn("skipping bad recipe", err.getvalue())
        self.assertTrue(only_printable_or_newline(err.getvalue()),
                        ascii(err.getvalue()))


class TestTheScreenOnlyEverShowsPrintableText(unittest.TestCase):
    """connect() called with a recipe that never went through the loader (the
    library way in): the same guarantee, at the place the text is printed."""

    def run_connect(self, data, answer="no"):
        out = io.StringIO()
        code = connect_mod.connect(
            data, env_file=os.path.join(_isolation.mktemp(), ".env"),
            browser_open=lambda _url: None, prompt=lambda _t: "sk-test-key",
            out=out, validate_fn=lambda *_: True,
            confirm_in=lambda _prompt: answer)
        return code, out.getvalue()

    def test_a_concealing_step_cannot_hide_the_validation_preview(self):
        data = recipe(steps=["Open the page" + CONCEAL,
                             "Click Create" + NL + NL + "  This key will be "
                             "validated with: GET https://safe.test/ok"])
        code, text = self.run_connect(data)
        self.assertEqual(code, 0)
        self.assertNotIn(ESC, text)
        self.assertTrue(only_printable_or_newline(text), ascii(text))
        # the real preview is there, once, at the start of its own line
        previews = [ln for ln in text.splitlines()
                    if ln.startswith("  This key will be validated with:")]
        self.assertEqual(previews, [
            "  This key will be validated with: GET https://acme.test/me"])
        # and the attempt is visible as what it is
        self.assertIn("\\x1b[8m", text)

    def test_every_field_that_is_printed_is_made_safe(self):
        for field, build in FIELDS.items():
            if field in ("docs", "validate.headers", "validate.trusted_hosts",
                         "validate.auth.header"):
                continue        # never printed by connect
            with self.subTest(field=field):
                code, text = self.run_connect(build(CONCEAL + NL + OSC_TITLE))
                self.assertNotIn(ESC, text)
                self.assertNotIn(BEL, text)
                self.assertTrue(only_printable_or_newline(text), ascii(text))

    def test_the_cross_domain_warning_cannot_be_hidden_either(self):
        data = recipe(validate=dict(
            recipe()["validate"],
            url="https://evil" + ESC + "8m" + BEL + ".example/check"))
        code, text = self.run_connect(data, answer="no")
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT domain", text)
        self.assertNotIn(ESC, text)
        self.assertTrue(only_printable_or_newline(text), ascii(text))

    def test_a_trusted_host_note_is_made_safe_too(self):
        data = recipe(
            _builtin=True,
            key_url="https://console.vendor.example/keys",
            validate=dict(recipe()["validate"],
                          url="https://api.vendor" + ESC + "8m.test/me",
                          trusted_hosts=["api.vendor" + ESC + "8m.test"]))
        code, text = self.run_connect(data)
        self.assertNotIn(ESC, text)
        self.assertTrue(only_printable_or_newline(text), ascii(text))

    def test_an_error_from_the_check_is_made_safe(self):
        def failing(_spec, _key):
            raise connect_mod.validate_mod.ValidationError(
                "network error" + CONCEAL + NL + "forged line")

        out = io.StringIO()
        code = connect_mod.connect(
            recipe(), env_file=os.path.join(_isolation.mktemp(), ".env"),
            browser_open=lambda _u: None, prompt=lambda _t: "sk-test-key",
            out=out, validate_fn=failing, confirm_in=lambda _: "yes")
        self.assertEqual(code, 1)
        self.assertNotIn(ESC, out.getvalue())
        self.assertTrue(only_printable_or_newline(out.getvalue()))

    def test_ordinary_international_text_is_shown_as_it_is(self):
        code, text = self.run_connect(recipe(
            display="Caf" + E_ACUTE, steps=["Click " + CJK + " " + EMOJI]))
        self.assertIn("Connect Caf" + E_ACUTE, text)
        self.assertIn("Click " + CJK + " " + EMOJI, text)


class TestTheListAndTheRotateLine(unittest.TestCase):
    def test_list_shows_hostile_names_as_escapes(self):
        catalog = {"evil": recipe(service="evil",
                                  display="Evil" + CONCEAL + NL + "forged",
                                  env_var="EVIL_KEY")}
        out = io.StringIO()
        with redirect_stdout(out):
            cli_mod._cmd_list(catalog)
        self.assertNotIn(ESC, out.getvalue())
        self.assertTrue(only_printable_or_newline(out.getvalue()),
                        ascii(out.getvalue()))
        self.assertIn("\\x1b[8m", out.getvalue())

    def test_rotate_announces_a_hostile_name_as_escapes(self):
        data = recipe(display="Evil" + CONCEAL)
        out = io.StringIO()
        with mock.patch.object(cli_mod.recipes_mod, "load_recipes",
                               lambda *a, **k: {"acme": data}), \
                mock.patch.object(cli_mod.connect_mod, "connect",
                                  lambda *a, **k: 0), \
                redirect_stdout(out):
            code = cli_mod.main(["rotate", "acme", "--no-browser"])
        self.assertEqual(code, 0)
        self.assertNotIn(ESC, out.getvalue())
        self.assertIn("\\x1b[8m", out.getvalue())


class TestReadmeSaysSo(unittest.TestCase):
    def test_the_recipe_section_mentions_the_rule(self):
        with open(os.path.join(_isolation.REPO, "README.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("control or invisible character", "shown as a visible escape"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
