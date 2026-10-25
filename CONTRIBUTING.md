# Contributing

The most useful contribution is a correct recipe. A recipe is a small JSON
file in `safeeasyapi/recipes/` that says where a key is made, the click path,
and one harmless call that proves the key works.

## The rules for a recipe change

1. **Cite the vendor's docs.** Every URL, header, status code and step must be
   shown on a page by the vendor itself. Put the link in your pull request.
   If you cannot find it, do not guess: list it under `"unverified"` in the
   recipe and `connect` will tell the user.
2. **`accept` is not `detect`.** `accept` decides what `connect --clipboard`
   will take from the clipboard. It must never refuse a valid key, so use
   only a shape the vendor documents, loosely (`^sk-ant-`), or leave it out.
   `detect` is what `scan` looks for; a commonly seen shape is fine there if
   you leave `detect_confidence` at `"guess"`.
3. **Check one thing, read only.** GET (or HEAD). The one exception is AWS's
   documented STS call. No call may cost money or use quota if there is any
   alternative.
4. **Say what a limited key looks like.** If a restricted key gets 403 (or a
   401 with a telltale word), add it under `validate.limited` or
   `validate.body_rules` so a real key is not reported as dead.
5. **Least privilege.** Fill in `least_privilege` with the smallest scope or
   permission that works.

## Smoke test with a FAKE key

Never use a real key to test. Start a local stand-in for the vendor and point
a copy of your recipe at it:

```bash
python -m unittest discover -s tests          # the whole suite, no network
python -m safeeasyapi doctor-recipes <slug>   # visits the real addresses, no key
```

For a new recipe add a test in `tests/` that loads it with
`recipes.load_recipes(recipes.RECIPES_DIR)`, runs `validate.validate_key` against
a local `http.server` that answers like the vendor (200 for the fake key, 401
otherwise, and your `limited` cases), and checks the verdict. Tests must not
make real network calls.

## Everything else

Python 3.10 to 3.14, standard library only: no dependencies, ever. Keep
messages in plain words. Anything that touches a key must never print it,
put it in a command line or write it to a log.
