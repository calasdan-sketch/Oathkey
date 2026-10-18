"""Recipe schema + loader.

A recipe is the per-service memory Claude always forgets: where the key
lives, the exact steps to mint one, how to prove it works, and where it
goes. Recipes are plain JSON — community-contributable, diffable.

Schema:
{
  "service": "github",            # slug [a-z0-9_-], required
  "display": "GitHub",           # human name, required
  "key_url": "https://...",      # where to mint the key, required
  "env_var": "GITHUB_TOKEN",     # where the key lands in .env, required
  "steps": ["...", "..."],       # exact click path, required non-empty
  "scopes": ["repo"],            # scopes to select, optional
  "docs": "https://...",        # docs link, optional
  "validate": {                  # proof the key works, required
    "method": "GET",
    "url": "https://api.github.com/user",
    "auth": {"type": "bearer", "scheme": "Bearer"}   # scheme optional:
          | {"type": "header", "header": "X-Key"}    #   "Token", "Bot"
          | {"type": "basic", "username": "api"},    # username optional
    "expect": [200],
    "reject": [401, 403],        # optional: statuses meaning "bad key"
    "headers": {"X-Version": "2024-01-01"},   # optional static headers
    "trusted_hosts": ["api.vendor.net"]       # optional, BUILT-IN recipes
  }                              #   only: validation hosts of the same
}                                #   vendor under another domain
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse

# Built-in recipes ship inside the package (so `pip install .` carries
# them); recipes you capture with `safeeasyapi add` go to the user dir,
# which also wins when both define the same service slug.
RECIPES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "recipes")


def user_recipes_dir() -> str:
    """~/.safeeasyapi/recipes, resolved at call time (honours HOME /
    USERPROFILE overrides)."""
    return os.path.join(os.path.expanduser("~"), ".safeeasyapi", "recipes")

REQUIRED = ("service", "display", "key_url", "env_var", "steps", "validate")
VALIDATE_REQUIRED = ("method", "url", "auth", "expect")
AUTH_TYPES = ("bearer", "header", "basic")
# A validation call proves a key by READING something. A recipe from
# somebody else must not be able to make `connect` send the real key with a
# DELETE or a POST to an endpoint on the key's own domain, where the
# cross-domain prompt never fires.
ALLOWED_METHODS = ("GET", "HEAD")

# An env_var ends up as a literal line "NAME=<key>" in the user's .env.
# Anything but a plain shell identifier (e.g. "GOOD=1\nEVIL=pwned") would
# inject attacker-controlled lines the runtime then loads, so the shape is
# enforced here at recipe load time — before anything is written.
ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")

# The service slug becomes the recipe FILE NAME (<slug>.json) and a CLI
# argument. Lowercase letters, digits, '-' and '_' only, 1-64 chars: a slug
# like "../../evil" could otherwise write outside the recipes directory.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")


class RecipeError(ValueError):
    pass


def printable(text) -> str:
    """`text` as it is safe to put on a terminal. A recipe is somebody
    else's text, and connect prints a lot of it (the steps, the scopes, the
    URLs) right next to the lines that protect the person: the validation
    preview and the cross-domain warning. A character that drives the
    terminal - ESC (colours, "conceal", a window title), a carriage return
    or newline that forges a line, a bidirectional override, a zero-width
    or no-break space - is therefore shown as a visible escape (``\\x1b``,
    ``\\u202e``) instead of being sent. Everything printable, accented and
    CJK letters and emoji included, comes back unchanged."""
    if not isinstance(text, str):
        text = str(text)
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if ch.isprintable():
            out.append(ch)
            continue
        code = ord(ch)
        if code < 0x100:
            out.append(f"\\x{code:02x}")
        elif code < 0x10000:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out)


def _first_invisible(value, where: str = "") -> tuple[str, str] | None:
    """(where, how it looks) for the first string anywhere in `value` (a
    key, a value, inside lists and objects) that holds a control or
    invisible character, or None. Both parts are safe to print."""
    if isinstance(value, str):
        if value.isprintable():
            return None
        shown = printable(value)
        if len(shown) > 60:
            shown = shown[:57] + "..."
        return where, shown
    if isinstance(value, dict):
        for key, item in value.items():
            name = printable(key)
            found = (_first_invisible(key, f"name {name}")
                     or _first_invisible(item, f"{where}.{name}" if where else name))
            if found:
                return found
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found = _first_invisible(item, f"{where}[{i}]")
            if found:
                return found
    return None


def _invisible_problem(data) -> str | None:
    """The sentence for a recipe that holds a control or invisible character
    somewhere, or None. Safe to print."""
    found = _first_invisible(data)
    if found is None:
        return None
    where, shown = found
    service = data.get("service") if isinstance(data, dict) else None
    who = (f"recipe '{printable(service)}'"
           if isinstance(service, str) and service else "recipe")
    return (f"{who} field {where or '(the recipe itself)'} contains a control "
            f"or invisible character ({shown}) - a recipe is plain text")


def validate_recipe(data: dict) -> dict:
    problem = _invisible_problem(data)
    if problem:
        # before anything else, so no later message can echo such a character
        raise RecipeError(problem)
    for field in REQUIRED:
        if field not in data or data[field] in (None, "", []):
            raise RecipeError(f"recipe missing required field: {field}")
    slug = data["service"]
    if not isinstance(slug, str) or not SLUG_RE.match(slug):
        raise RecipeError(
            f"recipe field 'service' must be a slug of lowercase letters, "
            f"digits, '-' or '_' (1-64 chars), got {slug!r}")
    env_var = data["env_var"]
    if not isinstance(env_var, str) or not ENV_VAR_RE.match(env_var):
        raise RecipeError(
            f"recipe '{data['service']}' field 'env_var' is not a valid "
            f"shell variable name: {env_var!r} — refusing it so a recipe "
            f"can never inject extra lines into .env")
    if not isinstance(data["steps"], list) or not data["steps"]:
        raise RecipeError("recipe 'steps' must be a non-empty list")
    v = data["validate"]
    for field in VALIDATE_REQUIRED:
        if field not in v:
            raise RecipeError(f"validate missing required field: {field}")
    method = v["method"]
    if not isinstance(method, str) or method.upper() not in ALLOWED_METHODS:
        raise RecipeError(
            f"validate.method must be GET or HEAD - a validation call only "
            f"reads - got {printable(method)!r}")
    auth = v["auth"]
    if auth.get("type") not in AUTH_TYPES:
        raise RecipeError(f"auth.type must be one of {AUTH_TYPES}")
    if auth["type"] == "header" and not auth.get("header"):
        raise RecipeError("auth.type 'header' needs auth.header name")
    if not isinstance(v["expect"], list) or not v["expect"]:
        raise RecipeError("validate.expect must be a non-empty status list")
    for field in ("expect", "reject"):
        codes = v.get(field, [])
        if codes is not None and not (isinstance(codes, list) and all(
                isinstance(c, int) and 100 <= c <= 599 for c in codes)):
            raise RecipeError(f"validate.{field} must be a list of HTTP statuses")
    headers = v.get("headers")
    if headers is not None and not (isinstance(headers, dict) and all(
            isinstance(k, str) and isinstance(val, str)
            for k, val in headers.items())):
        raise RecipeError("validate.headers must be a {name: value} object")
    for field in ("scheme", "username"):
        if field in auth and (not isinstance(auth[field], str)
                              or not auth[field].strip()
                              or any(ch in auth[field] for ch in " \r\n:")):
            raise RecipeError(f"auth.{field} must be a single token")
    hosts = v.get("trusted_hosts")
    if hosts is not None and not (isinstance(hosts, list) and all(
            isinstance(h, str) and h for h in hosts)):
        raise RecipeError("validate.trusted_hosts must be a list of hostnames")
    # A pasted key must never travel in cleartext: the mint page and the
    # validation endpoint must both be HTTPS.
    for label, url in (("key_url", data["key_url"]),
                       ("validate.url", v["url"])):
        try:
            scheme = urllib.parse.urlsplit(url).scheme.lower()
        except ValueError:
            # urlsplit refuses some malformed addresses ("https://[bad/").
            # Say so as a recipe problem, not as a traceback out of
            # `safeeasyapi add` or a whole broken catalog.
            raise RecipeError(
                f"{label} is not a valid URL: {url}") from None
        if scheme != "https":
            raise RecipeError(
                f"{label} must use https:// — a key sent there would travel "
                f"in cleartext. Offending URL: {url}")
    return data


def _load_dir(directory: str, recipes: dict[str, dict],
              builtin: bool = False) -> None:
    import sys
    if not os.path.isdir(directory):
        return
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(directory, fname)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            validate_recipe(data)
        except (json.JSONDecodeError, RecipeError, OSError, UnicodeDecodeError,
                AttributeError, TypeError) as e:
            sys.stderr.write(f"[safeeasyapi] skipping bad recipe "
                             f"{printable(fname)}: {printable(e)}\n")
            continue
        # Only recipes shipped INSIDE the package may vouch for a
        # validation host under another domain (trusted_hosts): they were
        # reviewed with the code. A user-dir recipe never gets that.
        data["_builtin"] = builtin
        recipes[data["service"]] = data


def _is_builtin_dir(directory: str) -> bool:
    return os.path.realpath(directory) == os.path.realpath(RECIPES_DIR)


def load_recipes(directory: str | None = None) -> dict[str, dict]:
    """Load all valid recipes. Invalid files are skipped with a warning on
    stderr - one bad recipe must never break the whole catalog.

    With `directory`, only that directory is read. Without it, the
    built-in recipes are loaded first and the user directory
    (~/.safeeasyapi/recipes) on top, so a user recipe overrides a
    built-in one with the same slug."""
    recipes: dict[str, dict] = {}
    if directory is not None:
        _load_dir(directory, recipes, builtin=_is_builtin_dir(directory))
        return recipes
    _load_dir(RECIPES_DIR, recipes, builtin=True)
    _load_dir(user_recipes_dir(), recipes)
    return recipes


def save_recipe(data: dict, directory: str | None = None) -> str:
    """Write a recipe as <slug>.json. Default destination is the user
    recipes dir, never the installed package."""
    validate_recipe(data)
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    directory = directory or user_recipes_dir()
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{data['service']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return path
