"""Recipe schema + loader.

A recipe is the per-service memory Claude always forgets: where the key
lives, the exact steps to mint one, how to prove it works, and where it
goes. Recipes are plain JSON — community-contributable, diffable.

Schema:
{
  "service": "github",            # slug, required
  "display": "GitHub",           # human name, required
  "key_url": "https://...",      # where to mint the key, required
  "env_var": "GITHUB_TOKEN",     # where the key lands in .env, required
  "steps": ["...", "..."],       # exact click path, required non-empty
  "scopes": ["repo"],            # scopes to select, optional
  "docs": "https://...",        # docs link, optional
  "validate": {                  # proof the key works, required
    "method": "GET",
    "url": "https://api.github.com/user",
    "auth": {"type": "bearer"} | {"type": "header", "header": "X-Key"} |
            {"type": "basic"},
    "expect": [200]
  }
}
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse

RECIPES_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "recipes")

REQUIRED = ("service", "display", "key_url", "env_var", "steps", "validate")
VALIDATE_REQUIRED = ("method", "url", "auth", "expect")
AUTH_TYPES = ("bearer", "header", "basic")

# An env_var ends up as a literal line "NAME=<key>" in the user's .env.
# Anything but a plain shell identifier (e.g. "GOOD=1\nEVIL=pwned") would
# inject attacker-controlled lines the runtime then loads, so the shape is
# enforced here at recipe load time — before anything is written.
ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RecipeError(ValueError):
    pass


def validate_recipe(data: dict) -> dict:
    for field in REQUIRED:
        if field not in data or data[field] in (None, "", []):
            raise RecipeError(f"recipe missing required field: {field}")
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
    auth = v["auth"]
    if auth.get("type") not in AUTH_TYPES:
        raise RecipeError(f"auth.type must be one of {AUTH_TYPES}")
    if auth["type"] == "header" and not auth.get("header"):
        raise RecipeError("auth.type 'header' needs auth.header name")
    if not isinstance(v["expect"], list) or not v["expect"]:
        raise RecipeError("validate.expect must be a non-empty status list")
    # A pasted key must never travel in cleartext: the mint page and the
    # validation endpoint must both be HTTPS.
    for label, url in (("key_url", data["key_url"]),
                       ("validate.url", v["url"])):
        if urllib.parse.urlsplit(url).scheme.lower() != "https":
            raise RecipeError(
                f"{label} must use https:// — a key sent there would travel "
                f"in cleartext. Offending URL: {url}")
    return data


def load_recipes(directory: str | None = None) -> dict[str, dict]:
    """Load all valid recipes. Invalid files are skipped with a warning on
    stderr — one bad recipe must never break the whole catalog."""
    import sys
    directory = directory or RECIPES_DIR
    recipes: dict[str, dict] = {}
    if not os.path.isdir(directory):
        return recipes
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(directory, fname)
        try:
            with open(path) as f:
                data = json.load(f)
            validate_recipe(data)
        except (json.JSONDecodeError, RecipeError, OSError) as e:
            sys.stderr.write(f"[safeeasyapi] skipping bad recipe {fname}: {e}\n")
            continue
        recipes[data["service"]] = data
    return recipes


def save_recipe(data: dict, directory: str | None = None) -> str:
    validate_recipe(data)
    directory = directory or RECIPES_DIR
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{data['service']}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return path
