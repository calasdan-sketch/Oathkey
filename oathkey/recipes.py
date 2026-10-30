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

Credentials of more than one value (an App ID and a secret, an access key
and its secret) are listed in "fields"; without it the recipe has the one
field "key" stored as env_var:

  "fields": [
    {"name": "app_id", "env_var": "EBAY_APP_ID", "label": "App ID (Client ID)",
     "pattern": "^[A-Za-z0-9-]+-PRD-[0-9a-f-]+$"},     # optional: lets the
    {"name": "cert_id", "env_var": "EBAY_CERT_ID",     #   clipboard capture
     "label": "Cert ID (Client Secret)"}               #   recognise a copy
  ],                                    # env_var must be the first field's

More auth shapes, each naming the fields it uses (default "key"):
    {"type": "bearer", "field": "token"}
    {"type": "header", "header": "X-Key", "field": "key"}
    {"type": "headers", "headers": {"X-App-Id": "{app_id}", "X-Key": "{key}"}}
    {"type": "basic", "username_field": "sid", "password_field": "token"}
    {"type": "query", "param": "appid"}            # follows no redirect
    {"type": "oauth2_client_credentials", "token_url": "https://...",
     "client_id_field": "app_id", "client_secret_field": "cert_id",
     "scope": "...", "send": "basic" | "body", "token_only": false}
    {"type": "aws_sigv4", "region": "us-east-1", "service": "sts",
     "access_key_field": "access_key_id", "secret_key_field": "secret_access_key"}

Every field must be used by the auth, so nothing is collected that the
check does not prove. The token_url gets the only POST oathkey makes.

"cli_token" (BUILT-IN recipes only) gets the key from the vendor's own CLI
after its browser sign-in, so nothing is copied at all:
  "cli_token": {"login": ["gh", "auth", "login", "--web"], "token": ["gh", "auth", "token"]}
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
import urllib.parse

# Built-in recipes ship inside the package (so `pip install .` carries
# them); recipes you capture with `oathkey add` go to the user dir,
# which also wins when both define the same service slug.
RECIPES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "recipes")


def user_recipes_dir() -> str:
    """~/.oathkey/recipes, resolved at call time (honours HOME /
    USERPROFILE overrides)."""
    return os.path.join(os.path.expanduser("~"), ".oathkey", "recipes")

REQUIRED = ("service", "display", "key_url", "env_var", "steps", "validate")
VALIDATE_REQUIRED = ("method", "url", "auth", "expect")
AUTH_TYPES = ("bearer", "header", "headers", "basic", "query",
              "oauth2_client_credentials", "aws_sigv4")
DEFAULT_FIELD = "key"
FIELD_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,31}\Z")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}\Z")
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
MAX_FIELDS = 6
MAX_PATTERN = 200
# Programs a built-in recipe may run to fetch a key after the vendor's own
# browser sign-in. Fixed here, not in the recipe: a recipe never chooses
# what runs on your computer.
CLI_PROGRAMS = ("gh",)
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


# The recipe's own sentences: its name, its steps and its scopes. A person
# reads them, and ordinary writing needs two things Python does not call
# printable (see _word_character). Every other field - a URL, a host, a
# header, a method - is a machine's text and gets no such leeway.
WORD_FIELDS = ("display", "steps", "scopes")
JOINERS = ("\u200c", "\u200d")        # zero-width non-joiner, joiner


def _visible(ch: str) -> bool:
    """One character that shows as a mark: printable and not a blank."""
    return len(ch) == 1 and ch.isprintable() and not ch.isspace()


def _word_character(text: str, i: int) -> bool:
    """May text[i], which Python does not call printable, stand in a
    recipe's own sentences? Two kinds may:

    - a space of another width (category Zs: the no-break space of a French
      "Cl\u00e9 API : copiez", the narrow no-break space, the ideographic
      space). It cannot drive a terminal: it is a blank, as a space is.
    - the zero-width joiner or non-joiner BETWEEN two visible characters:
      it glues an emoji together (a woman and a laptop make a technologist)
      and shapes Persian and Indic words. At the start or end of a text,
      next to a blank or next to another joiner it only hides, so it is
      refused there."""
    ch = text[i]
    if unicodedata.category(ch) == "Zs":
        return True
    if ch in JOINERS:
        return _visible(text[i - 1:i]) and _visible(text[i + 1:i + 2])
    return False


def _plain(text: str, words: bool) -> bool:
    """Is `text` free of anything that must not reach a terminal?"""
    return text.isprintable() or (words and all(
        ch.isprintable() or _word_character(text, i)
        for i, ch in enumerate(text)))


def printable(text, *, words: bool = False) -> str:
    """`text` as it is safe to put on a terminal. A recipe is somebody
    else's text, and connect prints a lot of it (the steps, the scopes, the
    URLs) right next to the lines that protect the person: the validation
    preview and the cross-domain warning. A character that drives the
    terminal - ESC (colours, "conceal", a window title), a carriage return
    or newline that forges a line, a bidirectional override, a zero-width
    or no-break space - is therefore shown as a visible escape (``\\x1b``,
    ``\\u202e``) instead of being sent. Everything printable, accented and
    CJK letters and emoji included, comes back unchanged.

    With ``words=True`` - the recipe's own sentences: its name, steps and
    scopes - a space of another width and a joiner between two visible
    characters come back unchanged too (see _word_character). Everything
    else that prints text of unknown shape (a file name, a path, a URL, an
    error) leaves it off, so nothing there can hide."""
    if not isinstance(text, str):
        text = str(text)
    if text.isprintable():
        return text
    out = []
    for i, ch in enumerate(text):
        if ch.isprintable() or (words and _word_character(text, i)):
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


def _first_invisible(value, where: str = "", words: bool = False,
                    top: bool = True) -> tuple[str, str] | None:
    """(where, how it looks) for the first string anywhere in `value` (a
    key, a value, inside lists and objects) that holds a control or
    invisible character, or None. Both parts are safe to print. `words`
    lets the recipe's own sentences (WORD_FIELDS, at the top of the recipe)
    use a space of another width and a joiner between visible characters."""
    if isinstance(value, str):
        if _plain(value, words):
            return None
        shown = printable(value)
        if len(shown) > 60:
            shown = shown[:57] + "..."
        return where, shown
    if isinstance(value, dict):
        for key, item in value.items():
            name = printable(key)
            found = (_first_invisible(key, f"name {name}")
                     or _first_invisible(
                         item, f"{where}.{name}" if where else name,
                         words or (top and key in WORD_FIELDS), top=False))
            if found:
                return found
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found = _first_invisible(item, f"{where}[{i}]", words, top=False)
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


def fields(recipe: dict) -> list[dict]:
    """The values a recipe collects, in order: [{name, env_var, label,
    pattern}]. A recipe without "fields" has one: "key", stored as its
    env_var."""
    listed = recipe.get("fields")
    if not listed:
        return [{"name": DEFAULT_FIELD, "env_var": recipe["env_var"],
                 "label": "API key", "pattern": None}]
    return [{"name": f["name"], "env_var": f["env_var"],
             "label": f.get("label") or f["name"], "pattern": f.get("pattern")}
            for f in listed]


def env_vars(recipe: dict) -> list[str]:
    """Every variable the recipe stores, in field order."""
    return [f["env_var"] for f in fields(recipe)]


def _check_fields(data: dict) -> None:
    listed = data.get("fields")
    if listed is None:
        return
    if not isinstance(listed, list) or not 1 <= len(listed) <= MAX_FIELDS:
        raise RecipeError(f"'fields' must be a list of 1 to {MAX_FIELDS} fields")
    names, envs = set(), set()
    for f in listed:
        if not isinstance(f, dict):
            raise RecipeError("each entry in 'fields' must be an object")
        name, env = f.get("name"), f.get("env_var")
        if not isinstance(name, str) or not FIELD_NAME_RE.match(name):
            raise RecipeError(f"field name must be lowercase letters, digits or '_': {name!r}")
        if not isinstance(env, str) or not ENV_VAR_RE.match(env):
            raise RecipeError(f"field '{name}' env_var is not a valid shell variable name: {env!r}")
        if name in names or env in envs:
            raise RecipeError(f"field '{name}' repeats a name or env_var")
        names.add(name)
        envs.add(env)
        label = f.get("label")
        if label is not None and not (isinstance(label, str) and label.strip()):
            raise RecipeError(f"field '{name}' label must be text")
        pattern = f.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN:
                raise RecipeError(f"field '{name}' pattern must be a regular expression "
                                  f"of at most {MAX_PATTERN} characters")
            try:
                re.compile(pattern)
            except re.error as e:
                raise RecipeError(f"field '{name}' pattern does not compile: {e}") from None
    if data["env_var"] != listed[0]["env_var"]:
        raise RecipeError("env_var must be the first field's env_var")


def _need(auth: dict, key: str, what: str) -> str:
    value = auth.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RecipeError(f"auth.type '{auth['type']}' needs auth.{key} ({what})")
    return value


def _check_auth(auth: dict, known: set[str]) -> None:
    """Every field the auth names exists, and every field is used."""
    atype = auth["type"]
    used: set[str] = set()

    def field(key: str, default: str = DEFAULT_FIELD) -> None:
        name = auth.get(key, default)
        if not isinstance(name, str) or name not in known:
            raise RecipeError(f"auth.{key} names field {name!r}, which is not in 'fields'")
        used.add(name)

    if atype == "header":
        header = _need(auth, "header", "a header name")
        if not HEADER_NAME_RE.match(header):
            raise RecipeError(f"auth.header is not a header name: {header!r}")
        field("field")
    elif atype == "bearer":
        field("field")
    elif atype == "headers":
        headers = auth.get("headers")
        if not isinstance(headers, dict) or not headers:
            raise RecipeError("auth.type 'headers' needs auth.headers {name: \"{field}\"}")
        for name, tpl in headers.items():
            if not isinstance(name, str) or not HEADER_NAME_RE.match(name) or not isinstance(tpl, str):
                raise RecipeError(f"auth.headers entry {name!r} is not a header name and template")
            refs = PLACEHOLDER_RE.findall(tpl)
            if not refs:
                raise RecipeError(f"auth.headers[{name}] must hold a {{field}} placeholder")
            for ref in refs:
                if ref not in known:
                    raise RecipeError(f"auth.headers[{name}] names unknown field {ref!r}")
                used.add(ref)
    elif atype == "basic":
        if "username_field" in auth:
            field("username_field")
        field("password_field")
    elif atype == "query":
        param = _need(auth, "param", "the query parameter name")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", param):
            raise RecipeError(f"auth.param is not a plain parameter name: {param!r}")
        field("field")
    elif atype == "oauth2_client_credentials":
        _need(auth, "token_url", "the vendor's OAuth2 token endpoint")
        field("client_id_field", "client_id")
        field("client_secret_field", "client_secret")
        if auth.get("send", "basic") not in ("basic", "body"):
            raise RecipeError("auth.send must be 'basic' or 'body'")
        scope = auth.get("scope")
        if scope is not None and not isinstance(scope, str):
            raise RecipeError("auth.scope must be text")
        if not isinstance(auth.get("token_only", False), bool):
            raise RecipeError("auth.token_only must be true or false")
    elif atype == "aws_sigv4":
        for key in ("region", "service"):
            if not re.fullmatch(r"[a-z0-9-]{2,32}", str(auth.get(key, ""))):
                raise RecipeError(f"auth.type 'aws_sigv4' needs auth.{key} (e.g. us-east-1 / sts)")
        field("access_key_field", "access_key_id")
        field("secret_key_field", "secret_access_key")
        if "session_token_field" in auth:
            field("session_token_field")
    unused = known - used
    if unused:
        raise RecipeError(f"fields {sorted(unused)} are collected but never checked by the auth")


def _check_cli_token(data: dict) -> None:
    cli = data.get("cli_token")
    if cli is None:
        return
    if not isinstance(cli, dict) or set(cli) - {"login", "token"} or "token" not in cli:
        raise RecipeError("cli_token must be {\"login\": [...], \"token\": [...]}")
    for key, argv in cli.items():
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) and a for a in argv)):
            raise RecipeError(f"cli_token.{key} must be a list of arguments")
        if argv[0] not in CLI_PROGRAMS:
            raise RecipeError(f"cli_token may only run {', '.join(CLI_PROGRAMS)}")
    if data.get("fields") and len(data["fields"]) > 1:
        raise RecipeError("cli_token works for single-key recipes only")


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
    _check_fields(data)
    _check_auth(auth, {f["name"] for f in fields(data)})
    _check_cli_token(data)
    # A pasted key must never travel in cleartext: the mint page, the
    # validation endpoint and any token endpoint must all be HTTPS.
    urls = [("key_url", data["key_url"]), ("validate.url", v["url"])]
    if auth["type"] == "oauth2_client_credentials":
        urls.append(("validate.auth.token_url", auth["token_url"]))
    for label, url in urls:
        try:
            scheme = urllib.parse.urlsplit(url).scheme.lower()
        except ValueError:
            # urlsplit refuses some malformed addresses ("https://[bad/").
            # Say so as a recipe problem, not as a traceback out of
            # `oathkey add` or a whole broken catalog.
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
            sys.stderr.write(f"[oathkey] skipping bad recipe "
                             f"{printable(fname)}: {printable(e)}\n")
            continue
        # Only recipes shipped INSIDE the package may vouch for a
        # validation host under another domain (trusted_hosts): they were
        # reviewed with the code. A user-dir recipe never gets that.
        data["_builtin"] = builtin
        recipes[data["service"]] = data


def _is_builtin_dir(directory: str) -> bool:
    return os.path.realpath(directory) == os.path.realpath(RECIPES_DIR)


def _hosts(recipe: dict) -> frozenset:
    """Every server a recipe can send its key to."""
    import urllib.parse
    v = recipe.get("validate") or {}
    out = set()
    for u in [v.get("url"), v.get("token_url"), (v.get("auth") or {}).get("token_url")]:
        if isinstance(u, str) and u:
            h = urllib.parse.urlsplit(u).hostname
            if h:
                out.add(h.lower())
    for h in v.get("trusted_hosts") or []:
        if isinstance(h, str):
            out.add(h.lower())
    return frozenset(out)


def _merge_user_recipes(recipes: dict, user: dict) -> None:
    """Put user recipes on top of the built-in ones - but never let one send
    a built-in service's key to a different server. A planted
    ~/.oathkey/recipes/github.json (or a new recipe that reuses the
    OPENAI_API_KEY variable name) could otherwise steal the key."""
    builtin_hosts = {s: _hosts(r) for s, r in recipes.items() if r.get("_builtin")}
    builtin_vars: dict = {}
    for s, r in recipes.items():
        if r.get("_builtin"):
            for var in env_vars(r):
                builtin_vars.setdefault(var, builtin_hosts[s])
    for slug, r in user.items():
        if slug in builtin_hosts and _hosts(r) != builtin_hosts[slug]:
            sys.stderr.write(f"oathkey: ignored your recipe '{slug}': it would send the "
                             f"built-in {slug} key to a different server. Use another "
                             "name for it.\n")
            continue
        clash = [v for v in env_vars(r) if v in builtin_vars and builtin_vars[v] != _hosts(r)
                 and slug not in builtin_hosts]
        if clash:
            sys.stderr.write(f"oathkey: ignored your recipe '{slug}': it reuses the key "
                             f"name {clash[0]} of a built-in service but talks to a "
                             "different server.\n")
            continue
        recipes[slug] = r


def load_recipes(directory: str | None = None) -> dict[str, dict]:
    """Load all valid recipes. Invalid files are skipped with a warning on
    stderr - one bad recipe must never break the whole catalog.

    With `directory`, only that directory is read. Without it, the
    built-in recipes are loaded first and the user directory
    (~/.oathkey/recipes) on top, so a user recipe overrides a
    built-in one with the same slug."""
    recipes: dict[str, dict] = {}
    if directory is not None:
        _load_dir(directory, recipes, builtin=_is_builtin_dir(directory))
        return recipes
    _load_dir(RECIPES_DIR, recipes, builtin=True)
    user: dict[str, dict] = {}
    _load_dir(user_recipes_dir(), user)
    _merge_user_recipes(recipes, user)
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
