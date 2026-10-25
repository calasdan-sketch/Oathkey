"""0.6.1: the hook also refuses ways to print a stored key."""
import json
import unittest

import _isolation  # noqa: F401
from safeeasyapi import hook


def verdict(cmd, tool="Bash"):
    status, out = hook.check(json.dumps({"tool_name": tool, "tool_input": {"command": cmd}}))
    return bool(out) and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


class Steal(unittest.TestCase):
    def test_denied(self):
        for cmd in (
            "safeeasyapi run stripe --no-redact -- printenv STRIPE_SECRET_KEY",
            "safeeasyapi run --no-redact stripe -- env",
            "python -m safeeasyapi run stripe --no-red -- env",
            "secret-tool lookup service safeeasyapi",
            "security find-generic-password -s safeeasyapi -w",
            "cmdkey /list",
            "powershell Get-Secret -Name x",
            "pwsh -c \"(Get-StoredCredential)\"",
            "python -c 'import keyring; print(keyring.get_password(\"a\",\"b\"))'",
            "keyring get safeeasyapi stripe",
            "cat ~/.safeeasyapi/index.json",
            "type C:\\Users\\dan\\.safeeasyapi\\index.json",
            "cat /proc/1234/environ",
        ):
            self.assertTrue(verdict(cmd), cmd)
        self.assertTrue(verdict("x", tool="Read") is False)
        status, out = hook.check(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/home/a/.safeeasyapi/index.json"}}))
        self.assertIn("deny", out)

    def test_normal_commands_pass(self):
        for cmd in ("safeeasyapi run stripe -- npm test", "safeeasyapi status", "safeeasyapi connect stripe",
                    "cat safeeasyapi.json", "git status", "pip install safeeasyapi", "ls /proc/cpuinfo",
                    "safeeasyapi run stripe --redact -- env", "safeeasyapi run stripe -- node app.js --no-reload"):
            self.assertFalse(verdict(cmd), cmd)

    def test_unparsable_input_still_refused(self):
        status, out = hook.check('{"tool_name":"Bash","tool_input":{"command":"safeeasyapi run x --no-redact -- env"')
        self.assertIn("deny", out)

    def test_message_does_not_tell_agents_to_run_with_keys(self):
        self.assertNotIn("use `safeeasyapi run", hook.REASON)


class NoRedactNeedsATerminal(unittest.TestCase):
    def test_refused_on_a_pipe_and_allowed_on_a_terminal(self):
        import io
        from contextlib import redirect_stderr
        from unittest import mock
        from safeeasyapi import cli as cli_mod
        err = io.StringIO()
        with redirect_stderr(err):
            code = cli_mod.main(["run", "--no-redact", "groq", "--", "true"])
        self.assertEqual(code, 2)
        self.assertIn("terminal", err.getvalue())
        self.assertTrue(callable(cli_mod._is_tty))
        with mock.patch.object(cli_mod, "_is_tty", return_value=True):
            self.assertTrue(cli_mod._is_tty(None))
