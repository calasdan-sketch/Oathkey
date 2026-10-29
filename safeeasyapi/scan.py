"""`safeeasyapi scan` and `safeeasyapi doctor`.

scan: look for API keys lying around in places an AI assistant (or a thief)
can read: project files, .env files, AI-tool config and settings files, shell
history. It NEVER prints a secret: a finding shows the file, the line, the kind
of key and a masked hint (first 4 characters + length) only.

doctor: a one-paste health check (keychain, ssh, git, proxy, file permissions).
Both support --json and use exit codes: 0 clean, 1 findings/problems, 2 usage.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import sys

# (kind, regex). Specific shapes only, so false alarms stay rare.
PATTERNS = [
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,251})\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Twilio auth/api key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/@]+:[^\s@]{3,}@")),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".idea", ".vscode-test"}
MAX_BYTES = 1_000_000

# where AI tools keep things an assistant can read or that get committed
AGENT_FILES = [".claude/settings.local.json", ".claude/settings.json", ".mcp.json",
               ".cursor/mcp.json", ".vscode/mcp.json", ".codex/config.toml"]
HOME_FILES = [".bash_history", ".zsh_history", ".claude.json",
              os.path.join(".claude", "settings.json"),
              os.path.join(".claude", "settings.local.json"),
              os.path.join(".cursor", "mcp.json"), os.path.join(".codex", "config.toml"),
              os.path.join("AppData", "Roaming", "Microsoft", "Windows", "PowerShell",
                           "PSReadLine", "ConsoleHost_history.txt")]


def mask(value: str) -> str:
    return f"{value[:4]}... ({len(value)} chars)"


def _is_text(sample: bytes) -> bool:
    return b"\0" not in sample


def scan_file(path: str) -> list[dict]:
    out: list[dict] = []
    try:
        if os.path.islink(path) or os.path.getsize(path) > MAX_BYTES:
            return out
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return out
    if not _is_text(raw[:4096]):
        return out
    text = raw.decode("utf-8", "replace")
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 5000:
            continue
        for kind, rx in PATTERNS:
            m = rx.search(line)
            if m:
                out.append({"file": path, "line": n, "kind": kind,
                            "hint": mask(m.group(0))})
    return out


def _walk(root: str):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            yield os.path.join(dirpath, name)


def scan(paths: list[str], home: str | None = None, include_home: bool = True) -> dict:
    findings: list[dict] = []
    warnings: list[dict] = []
    seen: set = set()
    targets: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            targets.extend(_walk(p))
        elif os.path.isfile(p):
            targets.append(p)
    if include_home:
        home = home or os.path.expanduser("~")
        for rel in HOME_FILES:
            f = os.path.join(home, rel)
            if os.path.isfile(f):
                targets.append(f)
    for f in targets:
        real = os.path.realpath(f)
        if real in seen:
            continue
        seen.add(real)
        found = scan_file(f)
        findings.extend(found)
        base = os.path.basename(f)
        norm = f.replace("\\", "/")
        if found and any(norm.endswith(a) for a in AGENT_FILES):
            warnings.append({"file": f, "why": "an AI-tool settings/config file holds a "
                             "key. Keys saved here are readable by the assistant and often "
                             "get committed. Move it to the keychain: `safeeasyapi connect`."})
        if base == ".env" or base.startswith(".env."):
            if os.name != "nt":
                try:
                    if os.stat(f).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                        warnings.append({"file": f, "why": "this .env file is readable by "
                                         "other users (run: chmod 600)."})
                except OSError:
                    pass
            else:
                pass
            if found:
                warnings.append({"file": f, "why": "some AI coding tools read .env files "
                                 "automatically. Keep real keys in the keychain instead."})
    return {"scanned": len(seen), "findings": findings, "warnings": warnings}


def format_report(result: dict) -> str:
    lines = [f"  scanned {result['scanned']} files; "
             f"{len(result['findings'])} key(s) found, "
             f"{len(result['warnings'])} warning(s)."]
    for f in result["findings"]:
        lines.append(f"    ! {f['kind']}  {f['file']}:{f['line']}  {f['hint']}")
    for w in result["warnings"]:
        lines.append(f"    - {w['file']}: {w['why']}")
    if result["findings"]:
        lines.append("\n  What to do: treat each key above as exposed - make a new one "
                     "(`safeeasyapi rotate <service>`), delete the old one at the "
                     "vendor, and keep the new one out of files.")
    else:
        lines.append("  Nothing key-shaped found. (This cannot see inside git history, "
                     "encoded values, or places not scanned.)")
    return "\n".join(lines)


def doctor(env=None, which=shutil.which) -> dict:
    env = os.environ if env is None else env
    from . import keychain as keychain_mod
    checks = []

    def add(name: str, ok: bool, detail: str, fix: str = ""):
        checks.append({"check": name, "ok": ok, "detail": detail, "fix": fix})

    add("python", sys.version_info >= (3, 10), platform.python_version(),
        "safeeasyapi needs Python 3.10 or newer.")
    backend = keychain_mod.detect_backend()
    add("keychain", backend is not None, keychain_mod.label(backend) if backend else "none",
        "Without an OS keychain, keys are kept in a .env file (owner-only).")
    add("ssh", bool(which("ssh")), "found" if which("ssh") else "missing",
        "Needed for `remote`/`deploy`. Windows: Settings > Apps > Optional features > OpenSSH Client.")
    add("git", bool(which("git")), "found" if which("git") else "missing",
        "Needed for `deploy` and git-based updates.")
    proxy = env.get("HTTPS_PROXY") or env.get("https_proxy")
    add("proxy", True, "set" if proxy else "none",
        "")
    cafile = env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE")
    add("custom CA bundle", True, "set" if cafile else "none", "")
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def format_doctor(result: dict) -> str:
    lines = []
    for c in result["checks"]:
        mark = "ok " if c["ok"] else "FIX"
        lines.append(f"  [{mark}] {c['check']}: {c['detail']}" +
                     (f"  -> {c['fix']}" if (not c["ok"] and c["fix"]) else ""))
    return "\n".join(lines)
