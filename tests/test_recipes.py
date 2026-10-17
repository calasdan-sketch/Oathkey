import json
import os
import unittest

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from safeeasyapi import recipes as recipes_mod

REPO = _isolation.REPO
BUILTIN = recipes_mod.RECIPES_DIR  # ships inside the package


def good_recipe(**over):
    r = {"service": "acme", "display": "Acme", "key_url": "https://acme.test/keys",
         "env_var": "ACME_KEY", "steps": ["Click new key"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


class TestRecipes(unittest.TestCase):
    def test_builtin_recipes_load(self):
        catalog = recipes_mod.load_recipes(BUILTIN)
        self.assertTrue({"github", "stripe", "resend", "openrouter"} <= set(catalog))
        for r in catalog.values():
            self.assertTrue(r["steps"])
            self.assertIn(r["validate"]["auth"]["type"],
                          ("bearer", "header", "basic"))

    def test_missing_field_rejected(self):
        bad = good_recipe()
        del bad["key_url"]
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(bad)

    def test_empty_steps_rejected(self):
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(good_recipe(steps=[]))

    def test_bad_auth_rejected(self):
        r = good_recipe()
        r["validate"]["auth"] = {"type": "magic"}
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(r)

    def test_header_auth_needs_name(self):
        r = good_recipe()
        r["validate"]["auth"] = {"type": "header"}
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(r)

    def test_bad_file_skipped_not_fatal(self):
        tmp = _isolation.mktemp()
        with open(os.path.join(tmp, "bad.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        with open(os.path.join(tmp, "good.json"), "w", encoding="utf-8") as f:
            json.dump(good_recipe(), f)
        catalog = recipes_mod.load_recipes(tmp)
        self.assertEqual(set(catalog), {"acme"})

    def test_save_roundtrip(self):
        tmp = _isolation.mktemp()
        path = recipes_mod.save_recipe(good_recipe(), tmp)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(set(recipes_mod.load_recipes(tmp)), {"acme"})


if __name__ == "__main__":
    unittest.main()
