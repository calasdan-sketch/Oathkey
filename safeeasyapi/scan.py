"""`safeeasyapi scan`: find API keys that leaked into files an AI agent reads.

An AI coding agent reads the instruction files and settings in your project
(CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, the .claude folder) and, if
you let it, your .env files. A key pasted into any of those is in the
agent's memory and in its conversation log. This module finds them.

What it does, in order of how careful it has to be:

1. It only ever READS regular files. A named pipe, a device, a symbolic link
   that leaves the folder, a file over 1 MB, a binary file, .git and
   node_modules are skipped and never opened, so a scan cannot hang.
2. It is OFFLINE. Detection is pattern matching only. Nothing leaves the
   computer unless you pass --validate and agree to the list of hosts.
3. It NEVER prints a whole key. A key is shown as its first 4 and last 2
   characters ("sk-p...Zk"), in every output format and every message.

Detection uses (a) the key format of each built-in recipe, (b) a short list
of well-known key prefixes for services that have no recipe, and (c) any
NAME=value where NAME ends in KEY, TOKEN or SECRET and the value looks random.
Placeholders ("your_key_here", "xxxx", "<token>", "example") are ignored.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import stat
import sys
import urllib.parse

from . import __version__
from . import connect as connect_mod
from . import validate as validate_mod
from . import recipes as recipes_mod
from .recipes import printable

MAX_FILE_BYTES = 1024 * 1024       # a bigger file is skipped, never read
MAX_LINE_CHARS = 20000             # longer lines are cut before matching
MAX_ENTRIES = 50000                # folder entries looked at, then stop
MAX_DEPTH = 12
MAX_VALIDATIONS = 50               # distinct keys sent per run
BINARY_PROBE = 8192

PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
})
AGENT_FILES = frozenset({
    "claude.md", "claude.local.md", "agents.md", "gemini.md", ".cursorrules",
    ".windsurfrules", ".mcp.json",
})
AGENT_DIRS = frozenset({".claude"})

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/calasdan-sketch/safeeasyapi"

STATUSES = ("unchecked", "live", "dead", "unknown")


# ------------------------------------------------------------------ redaction

def redact(value: str) -> str:
    """First 4 and last 2 characters, nothing else. A short value shows even
    less. This is the ONLY way a key may appear in any output."""
    if len(value) < 12:
        return value[:2] + "..."
    return value[:4] + "..." + value[-2:]


# --------------------------------------------------------------- placeholders

PLACEHOLDER_WORDS = (
    "your", "here", "xxx", "changeme", "change_me", "change-me", "example",
    "placeholder", "dummy", "fake", "sample", "replace", "insert", "redacted",
    "todo", "fixme", "notreal", "not_real", "paste", "<", ">", "{", "}", "*",
    "...", "…", "$(", "${", "%", "mykey", "my_key", "my-key", "abc123",
    "123456", "test_key", "testkey", "abcdef", "qwerty", "generate", "openssl",
    "process.env", "environ", "getenv",
)
# Keys printed in vendors' own documentation: public, never secret.
DOC_KEYS = frozenset({"sk_" "test_4eC39HqLyjWDarjtT1zdp7dc"})


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """Does this look like a stand-in rather than a real key?"""
    v = value.strip().strip("\"'`")
    low = v.lower()
    if not v or v in DOC_KEYS:
        return True
    if any(word in low for word in PLACEHOLDER_WORDS):
        return True
    if re.search(r"(.)\1{5,}", v):          # xxxxxxx, 000000, aaaaaa
        return True
    if len(set(v)) < 6:
        return True
    return False


def looks_random(body: str, minimum: float = 3.0) -> bool:
    """A real key mixes letters and digits and is not a repeating word."""
    return (any(c.isdigit() for c in body) and any(c.isalpha() for c in body)
            and entropy(body) >= minimum)


# ------------------------------------------------------------------- patterns

@dataclasses.dataclass
class Rule:
    provider: str | None        # recipe slug, or None for a service without a recipe
    name: str                   # shown to people
    regex: re.Pattern
    kind: str                   # "recipe-pattern" | "known-prefix"
    confidence: str             # "known" | "guess"
    can_validate: bool = True   # False when the match cannot be proven by the recipe
    prefix_len: int = 0         # literal prefix length: longest wins an overlap
    check_body: bool = True


def _literal_prefix(pattern: str) -> int:
    n = 0
    for ch in pattern.lstrip("^("):
        if ch in "[\\(.*+?{|":
            break
        n += 1
    return n


def _wrap(pattern: str) -> re.Pattern | None:
    core = pattern
    if core.startswith("^"):
        core = core[1:]
    if core.endswith("$") and not core.endswith("\\$"):
        core = core[:-1]
    try:
        return re.compile(r"(?<![A-Za-z0-9_])(?:" + core + r")(?![A-Za-z0-9])")
    except re.error:
        return None


# Well-known prefixes. "known" = the format is documented or has been stable
# for years. "guess" = recent or lightly documented: such a finding says so.
# (provider slug or None, display name, pattern, confidence, can_validate)
KNOWN_PREFIXES = (
    ("google-gemini", "Google API key", r"AIza[0-9A-Za-z_-]{35}", "known", False),
    (None, "Slack token", r"xox[abprs]-[A-Za-z0-9-]{10,}", "known", False),
    (None, "npm token", r"npm_[A-Za-z0-9]{36}", "known", False),
    (None, "Shopify token", r"shp(?:at|ca|pa|ss)_[a-f0-9]{32}", "known", False),
    ("discord", "Discord bot token",
     r"[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", "known", True),
    ("supabase", "Supabase access token", r"sbp_[a-f0-9]{40}", "known", True),
    ("notion", "Notion token", r"ntn_[A-Za-z0-9]{30,}", "guess", True),
    ("netlify", "Netlify token", r"nfp_[A-Za-z0-9]{30,}", "guess", True),
    ("pinecone", "Pinecone key", r"pcsk_[A-Za-z0-9_]{40,}", "guess", True),
)
# Fields whose "pattern" matches an identifier, not a secret.
IDENTIFIER_FIELDS = frozenset({("twilio", "sid")})

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")
BASE64_LINE_RE = re.compile(r"^\s*[A-Za-z0-9+/=]{20,}\s*$")

ASSIGN_RE = re.compile(
    r"""(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[=:]\s*["']?"""
    r"""(?P<value>[A-Za-z0-9_\-+/=.~]{20,})""")
SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[_.\-])(?:api_?key|key|token|secret)$|"
    r"(?:api|access|auth|private|client|secret|bearer)Key$|[a-z](?:Token|Secret)$")
NOT_SECRET_NAME_RE = re.compile(
    r"(?i)public|publishable|site_?key|sort_?key|primary_?key|foreign_?key|"
    r"cache_?key|partition_?key|key_?name|ssh_?key_?path|idempotency|file_?key|"
    r"object_?key|row_?key|record_?key|project_?key|issue_?key|lookup_?key|"
    r"translation_?key|node_?key|storage_?key|s3_?key")
HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
# A reference to a key, not a key: AUTH0_CLIENT_SECRET, settings.api_key
CODE_REF_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)$")
# a package file or version string, not a key: hf_xet-1.2.0-cp37-abi3.whl
VERSIONED_RE = re.compile(r"\d+\.\d+\.\d+")


def build_rules(catalog: dict) -> list[Rule]:
    """Every recipe's key format plus the well-known prefixes, most specific
    first (so sk-ant-... is Anthropic, not just "sk-")."""
    rules: list[Rule] = []
    for slug, recipe in catalog.items():
        for field in recipes_mod.fields(recipe):
            pattern = field.get("pattern")
            if not pattern or (slug, field["name"]) in IDENTIFIER_FIELDS:
                continue
            rx = _wrap(pattern)
            if rx is not None:
                rules.append(Rule(slug, recipe["display"], rx, "recipe-pattern",
                                  "known", True, _literal_prefix(pattern),
                                  check_body=",}" in pattern))
    for provider, name, pattern, confidence, can_validate in KNOWN_PREFIXES:
        if provider is not None and provider not in catalog:
            provider_ok = None
        else:
            provider_ok = provider
        display = (catalog[provider_ok]["display"] if provider_ok else name)
        rx = _wrap(pattern)
        if rx is not None:
            rules.append(Rule(provider_ok, display if provider_ok else name, rx,
                              "known-prefix", confidence, can_validate,
                              _literal_prefix(pattern),
                              check_body=",}" in pattern))
    rules.sort(key=lambda r: -r.prefix_len)
    return rules


def _name_tokens(catalog: dict) -> dict[str, str]:
    """Lower-case words in an environment-variable name -> recipe slug."""
    words: dict[str, str] = {}
    for slug, recipe in catalog.items():
        for var in recipes_mod.env_vars(recipe):
            if var.upper() == var:
                words.setdefault(var.lower(), slug)
        first = recipe["env_var"].split("_")[0].lower()
        words.setdefault(first, slug)
        words.setdefault(slug.lower(), slug)
        for part in slug.split("-"):
            if len(part) > 3:
                words.setdefault(part.lower(), slug)
    return words


def provider_for_name(name: str, catalog: dict, words: dict[str, str]) -> str | None:
    """Which recipe does this variable name belong to? Exact variable name
    first (GROQ_API_KEY), then the service's name inside it (OPENAI_KEY)."""
    upper = re.sub(r"[.\-]", "_", name).upper()
    for slug, recipe in catalog.items():
        if upper in (v.upper() for v in recipes_mod.env_vars(recipe)):
            return slug
    for token in re.split(r"[_]", upper.lower()):
        if token in words:
            return words[token]
    return None


# -------------------------------------------------------------------- finding

@dataclasses.dataclass
class Finding:
    file: str
    line: int
    column: int
    provider: str | None
    provider_name: str
    rule: str
    confidence: str
    redacted: str
    status: str = "unchecked"
    detail: str = ""
    key_url: str | None = None
    can_validate: bool = True
    _value: str = dataclasses.field(default="", repr=False, compare=False)

    @property
    def next_step(self) -> str:
        return next_step_text(self)


def next_step_text(f: Finding) -> str:
    """Plain words: what to do about this one."""
    if f.status == "dead":
        return ("The service says this key no longer works. Delete the line so "
                "it is not left lying around.")
    if f.provider and f.key_url:
        base = (f"Rotate it at {printable(f.key_url)}, then run "
                f"`safeeasyapi connect {f.provider}` to save the new one safely.")
    elif f.provider:
        base = (f"Rotate it in your {printable(f.provider_name, words=True)} "
                f"account, then run `safeeasyapi connect {f.provider}`.")
    else:
        base = (f"Rotate it in the account of the service that issued it "
                f"(make a new key, then revoke this one). "
                f"`safeeasyapi list` shows the services that have a guided setup.")
    if f.status == "unchecked":
        base += " Add --validate to see whether it still works."
    return base


# ------------------------------------------------------------------- scanning

def scan_text(text: str, rel: str, rules: list[Rule], catalog: dict,
              words: dict[str, str] | None = None) -> list[Finding]:
    """Find keys in one file's text. Pure: no files, no network."""
    words = words if words is not None else _name_tokens(catalog)
    findings: list[Finding] = []
    lines = text.splitlines()
    for number, raw in enumerate(lines, 1):
        line = raw[:MAX_LINE_CHARS]
        taken: list[tuple[int, int]] = []

        def free(a: int, b: int) -> bool:
            return all(b <= s or a >= e for s, e in taken)

        def add(rule_name, confidence, provider, display, start, end, can_validate):
            value = line[start:end]
            taken.append((start, end))
            recipe = catalog.get(provider) if provider else None
            findings.append(Finding(
                file=rel, line=number, column=start + 1, provider=provider,
                provider_name=display, rule=rule_name, confidence=confidence,
                redacted=redact(value),
                key_url=recipe["key_url"] if recipe else None,
                can_validate=can_validate, _value=value))

        if "-----BEGIN" in line and PRIVATE_KEY_RE.search(line):
            nxt = lines[number] if number < len(lines) else ""
            if BASE64_LINE_RE.match(nxt) or nxt.startswith("Proc-Type"):
                m = PRIVATE_KEY_RE.search(line)
                taken.append((m.start(), m.end()))
                findings.append(Finding(
                    file=rel, line=number, column=m.start() + 1, provider=None,
                    provider_name="Private key", rule="private-key-block",
                    confidence="known", redacted="(private key)",
                    can_validate=False, _value=""))
        for rule in rules:
            for m in rule.regex.finditer(line):
                value = m.group(0)
                if (not free(m.start(), m.end()) or is_placeholder(value)
                        or VERSIONED_RE.search(value)):
                    continue
                body = value[rule.prefix_len:] or value
                if rule.check_body and not looks_random(
                        body, 2.5 if rule.confidence == "known" else 3.2):
                    continue
                add(rule.kind, rule.confidence, rule.provider, rule.name,
                    m.start(), m.end(), rule.can_validate)
        for m in ASSIGN_RE.finditer(line):
            name, value = m.group("name"), m.group("value")
            if (not SECRET_NAME_RE.search(name) or NOT_SECRET_NAME_RE.search(name)
                    or not free(m.start("value"), m.end("value"))):
                continue
            if (is_placeholder(value) or value[0] in "/~." or ".." in value
                    or value.isdigit() or HOSTNAME_RE.match(value)
                    or (CODE_REF_RE.match(value) and not value.startswith("eyJ"))
                    or not looks_random(value, 3.5)):
                continue
            provider = provider_for_name(name, catalog, words)
            display = (catalog[provider]["display"] if provider
                       else f"Unrecognised key ({printable(name)})")
            add("named-assignment", "name-and-randomness", provider, display,
                m.start("value"), m.end("value"), True)
    return findings


@dataclasses.dataclass
class Skipped:
    path: str
    reason: str


def _is_agent_path(parts: tuple[str, ...]) -> bool:
    name = parts[-1].lower()
    if name in AGENT_FILES:
        return True
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return any(p in AGENT_DIRS for p in parts[:-1])


def _within(real: str, root_real: str) -> bool:
    try:
        return os.path.commonpath([real, root_real]) == root_real
    except ValueError:
        return False


def read_text_safely(path: str, root_real: str) -> tuple[str | None, str | None]:
    """(text, None) or (None, why-it-was-skipped). Opens only a regular file
    of at most MAX_FILE_BYTES, without blocking and without following a link
    that leaves `root_real`."""
    try:
        st = os.lstat(path)
        real = path
        if stat.S_ISLNK(st.st_mode):
            real = os.path.realpath(path)
            if not _within(real, root_real):
                return None, "a link that leads outside the folder"
            st = os.stat(real)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file (pipe, device or folder)"
        if st.st_size > MAX_FILE_BYTES:
            return None, "bigger than 1 MB"
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(real, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None, "not a regular file (pipe, device or folder)"
            chunks, total = [], 0
            while total <= MAX_FILE_BYTES:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
    except OSError as e:
        return None, f"could not be read ({e.strerror or 'error'})"
    data = b"".join(chunks)
    if len(data) > MAX_FILE_BYTES:
        return None, "bigger than 1 MB"
    if b"\0" in data[:BINARY_PROBE]:
        return None, "a binary file"
    return data.decode("utf-8-sig", errors="replace"), None


def collect_files(root: str, everything: bool = False) -> tuple[list[str], list[Skipped]]:
    """Files worth reading under `root`, in a stable order. Folders that are
    links are never entered; the walk stops at MAX_ENTRIES / MAX_DEPTH."""
    files: list[str] = []
    notes: list[Skipped] = []
    seen = 0
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            notes.append(Skipped(os.path.relpath(directory, root), "a folder that could not be opened"))
            continue
        subdirs = []
        for entry in entries:
            seen += 1
            if seen > MAX_ENTRIES:
                notes.append(Skipped(".", f"stopped after looking at {MAX_ENTRIES} entries"))
                return files, notes
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if entry.name in PRUNE_DIRS:
                    continue
                if depth < MAX_DEPTH:
                    subdirs.append((entry.path, depth + 1))
                else:
                    notes.append(Skipped(os.path.relpath(entry.path, root),
                                         "too many folders deep"))
                continue
            rel = os.path.relpath(entry.path, root)
            parts = tuple(rel.replace("\\", "/").split("/"))
            if everything or _is_agent_path(parts):
                files.append(entry.path)
        stack.extend(reversed(subdirs))
    return files, notes


@dataclasses.dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list[Finding]
    skipped: list[Skipped]
    validated: bool = False


def scan_path(target: str, catalog: dict, everything: bool = False) -> ScanResult:
    """Scan a folder (the agent-readable files in it) or one file."""
    target = os.path.abspath(target)
    if os.path.isdir(target):
        root = target
        files, skipped = collect_files(root, everything)
    else:
        root = os.path.dirname(target)
        files, skipped = [target], []
    root_real = os.path.realpath(root)
    rules = build_rules(catalog)
    words = _name_tokens(catalog)
    findings: list[Finding] = []
    scanned = 0
    done: set[str] = set()
    for path in files:
        rel = os.path.relpath(path, root).replace("\\", "/")
        real = os.path.realpath(path)
        if real in done:
            continue
        done.add(real)
        text, why = read_text_safely(path, root_real)
        if text is None:
            skipped.append(Skipped(rel, why or "skipped"))
            continue
        scanned += 1
        findings.extend(scan_text(text, rel, rules, catalog, words))
    return ScanResult(root, scanned, findings, skipped)


# ----------------------------------------------------------------- validation

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def plan_validation(findings: list[Finding], catalog: dict):
    """Which findings can be checked, grouped by recipe, and which cannot
    (with the reason). Returns (plan, impossible): plan maps slug -> {value:
    [findings]}; impossible is a list of (finding, reason)."""
    plan: dict[str, dict[str, list[Finding]]] = {}
    impossible: list[tuple[Finding, str]] = []
    for f in findings:
        recipe = catalog.get(f.provider) if f.provider else None
        if recipe is None or not f._value:
            impossible.append((f, "no check is known for this kind of key"))
        elif not f.can_validate:
            impossible.append((f, "this key format is shared by several "
                                  "services, so one check cannot prove it"))
        elif len(recipes_mod.fields(recipe)) != 1:
            impossible.append((f, "this service needs a second value "
                                  "(a secret) to check the key"))
        else:
            plan.setdefault(f.provider, {}).setdefault(f._value, []).append(f)
    return plan, impossible


def _ask_stderr(prompt: str) -> str:
    sys.stderr.write(prompt)
    sys.stderr.flush()
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def _stdin_is_terminal() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def run_validation(findings: list[Finding], catalog: dict, *, yes: bool,
                   err, ask=_ask_stderr, interactive=_stdin_is_terminal,
                   validate_fn=validate_mod.validate_key) -> str | None:
    """Check keys against their own service. Returns None when done, or a
    message when the person has to be told that nothing was sent (no
    consent). Statuses are written onto the findings."""
    plan, impossible = plan_validation(findings, catalog)
    for f, why in impossible:
        f.status, f.detail = "unknown", why
    if not plan:
        return None
    sendable: dict[str, dict[str, list[Finding]]] = {}
    err.write("\n  --validate will send keys to the services below, one "
              "read-only request each,\n  over https, to that host only. "
              "Nothing is saved or changed.\n\n")
    for slug, values in plan.items():
        recipe = catalog[slug]
        urls = connect_mod.destinations(recipe)
        if any(urllib.parse.urlsplit(u).scheme.lower() != "https" for u in urls):
            for group in values.values():
                for f in group:
                    f.status, f.detail = "unknown", "not sent: the check is not https"
            continue
        hosts = ", ".join(sorted({_host(u) for u in urls}))
        err.write(f"    {printable(recipe['display'], words=True)}: "
                  f"{len(values)} key{'s' if len(values) != 1 else ''} "
                  f"-> {printable(hosts)}  ({printable(urls[-1])})\n")
        sendable[slug] = values
    err.write("\n")
    if not sendable:
        return None
    if not yes:
        if not interactive():
            return ("--validate sends keys over the internet, so it needs your "
                    "OK and there is no terminal to ask on. Add --yes to agree, "
                    "or leave out --validate to scan without sending anything.")
        try:
            answer = ask("  Send these keys to those hosts? [y/N]: ")
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            err.write("  Nothing was sent.\n")
            for values in sendable.values():
                for group in values.values():
                    for f in group:
                        f.status, f.detail = "unchecked", "you chose not to send it"
            return None

    def deny(_prompt):                      # no one to ask: that is a "no"
        raise EOFError
    confirm = ask if interactive() else deny
    budget = MAX_VALIDATIONS
    for slug, values in sendable.items():
        recipe = catalog[slug]
        # the existing cross-domain warning: a check on another domain than the
        # key page needs a typed "yes", which --yes does not replace
        if not connect_mod._require_cross_domain_confirmation(recipe, err, confirm):
            for group in values.values():
                for f in group:
                    f.status = "unknown"
                    f.detail = "not sent: the check is on a different domain"
            continue
        for value, group in values.items():
            if budget <= 0:
                status, detail = "unknown", "not checked: too many keys in one run"
            else:
                budget -= 1
                try:
                    ok = validate_fn(recipe["validate"], value)
                    status, detail = ("live", "") if ok else ("dead", "")
                except validate_mod.ValidationError as e:
                    status, detail = "unknown", f"could not check: {printable(e)}"
                except Exception as e:      # never let one check stop the rest
                    status, detail = "unknown", f"could not check ({type(e).__name__})"
            for f in group:
                f.status, f.detail = status, detail
    return None


# -------------------------------------------------------------------- reports

STATUS_WORDS = {
    "unchecked": "not checked",
    "live": "STILL WORKS",
    "dead": "no longer works",
    "unknown": "could not be checked",
}


def _confidence_note(f: Finding) -> str:
    return "  (format is a guess)" if f.confidence == "guess" else ""


def render_text(result: ScanResult) -> str:
    out = []
    n = len(result.findings)
    out.append(f"\n  safeeasyapi scan: looked at {result.files_scanned} "
               f"file{'s' if result.files_scanned != 1 else ''} in "
               f"{printable(result.root)}")
    if n == 0:
        out.append("  No keys found in files an AI agent can read.")
    else:
        out.append(f"  Found {n} key{'s' if n != 1 else ''} an AI agent can "
                   f"read. Anything it reads can end up in its memory and logs.")
    for f in result.findings:
        out.append(f"\n  {printable(f.file)}:{f.line}   "
                   f"{printable(f.provider_name, words=True)}   {f.redacted}   "
                   f"{STATUS_WORDS[f.status]}{_confidence_note(f)}")
        if f.detail:
            out.append(f"      note: {f.detail}")
        out.append(f"      next: {f.next_step}")
    if result.skipped:
        out.append(f"\n  Skipped {len(result.skipped)} "
                   f"item{'s' if len(result.skipped) != 1 else ''} "
                   f"(too big, binary, a pipe, or a link leading outside); "
                   f"--json lists them.")
    if n:
        out.append("\n  To stop an agent reading .env files, run: "
                   "safeeasyapi hook install")
    out.append("")
    return "\n".join(out) + "\n"


def to_json(result: ScanResult) -> dict:
    return {
        "tool": "safeeasyapi",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "validated": result.validated,
        "findings": [{
            "file": f.file, "line": f.line, "column": f.column,
            "provider": f.provider, "provider_name": f.provider_name,
            "rule": f.rule, "confidence": f.confidence,
            "redacted": f.redacted, "status": f.status, "status_detail": f.detail,
            "next_step": f.next_step, "key_url": f.key_url,
        } for f in result.findings],
        "skipped": [{"path": s.path, "reason": s.reason} for s in result.skipped],
    }


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0. The message holds the redacted key only."""
    rule_ids: list[str] = []
    rules = []
    results = []
    for f in result.findings:
        rid = f"leaked-key/{f.provider or 'other'}"
        if rid not in rule_ids:
            rule_ids.append(rid)
            rules.append({
                "id": rid,
                "name": "LeakedKey",
                "shortDescription": {"text": f"A {f.provider_name if f.provider else 'service'} key is stored in a file an AI agent can read"},
                "fullDescription": {"text": "A secret key written into an instruction, settings or .env file is read by AI agents and can end up in their memory and logs. Rotate it and keep it out of files."},
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": "warning"},
            })
        fingerprint = hashlib.sha256(
            f"{f.file}:{f.line}:{rid}:{f.redacted}".encode()).hexdigest()
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_ids.index(rid),
            "level": "error" if f.status == "live" else "warning",
            "message": {"text": (f"{f.provider_name} key {f.redacted} found "
                                 f"({STATUS_WORDS[f.status]}). {f.next_step}")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(f.file)},
                "region": {"startLine": f.line, "startColumn": f.column},
            }}],
            "partialFingerprints": {"safeeasyapiKey/v1": fingerprint},
            "properties": {"status": f.status, "confidence": f.confidence},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "safeeasyapi", "version": __version__,
                                "informationUri": INFO_URI, "rules": rules}},
            "results": results,
        }],
    }


def exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "live":
        return 1 if any(f.status == "live" for f in result.findings) else 0
    return 1 if result.findings else 0


def cmd_scan(args, catalog: dict, out=None, err=None, **hooks) -> int:
    """Entry point for `safeeasyapi scan`. Exit 0 clean, 1 findings, 2 error."""
    out = out or sys.stdout
    err = err or sys.stderr
    target = args.path
    if not os.path.exists(target):
        err.write(f"error: {printable(target)} does not exist.\n")
        return 2
    # the host list and the questions go to stderr: stdout is the report
    # (and is pure JSON or SARIF when asked for)
    try:
        result = scan_path(target, catalog, everything=args.all)
    except OSError as e:
        err.write(f"error: could not scan {printable(target)}: {e.strerror or e}\n")
        return 2
    if args.fail_on == "live" and not args.validate:
        err.write("note: --fail-on live needs --validate; without it no key "
                  "is checked, so none counts as live.\n")
    if args.validate and result.findings:
        refusal = run_validation(result.findings, catalog, yes=args.yes, err=err,
                                 **hooks)
        if refusal:
            err.write(f"error: {refusal}\n")
            return 2
        result.validated = True
    if args.json:
        out.write(json.dumps(to_json(result), indent=2) + "\n")
    elif args.sarif:
        out.write(json.dumps(to_sarif(result), indent=2) + "\n")
    else:
        out.write(render_text(result))
    return exit_code(result, args.fail_on)
