"""The MCP server survives a message it cannot take apart or write back.

Panel finding (SEA-3): `python -c "print('['*100000)" | safeeasyapi mcp`
ended in a traceback and exit status 1. json.loads raises RecursionError, not
ValueError, for text nested that deep, and serve() only expected ValueError.
The server must answer "Parse error" and carry on, like any other bad line.
"""

import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from safeeasyapi import mcp as mcp_mod

PING = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"})


def run_server(lines, **patches):
    """Feed `lines` (bytes, one message each) to serve() in-process; returns
    the parsed replies. Any exception out of serve() fails the test."""
    stdin = io.BytesIO(b"".join(line + b"\n" for line in lines))
    stdout = io.BytesIO()
    mcp_mod.serve({}, stdin=stdin, stdout=stdout)
    return [json.loads(row) for row in stdout.getvalue().splitlines()]


class TestTooDeepToParse(unittest.TestCase):
    def check(self, bomb):
        replies = run_server([bomb, PING.encode()])
        self.assertEqual(len(replies), 2, replies)
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.PARSE_ERROR)
        self.assertIsNone(replies[0]["id"])
        # and the server carried on
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})

    def test_a_hundred_thousand_open_brackets(self):
        self.check(b"[" * 100000)

    def test_a_hundred_thousand_open_objects(self):
        self.check(b'{"a":' * 100000)

    def test_deep_nesting_inside_a_request(self):
        self.check(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":'
                   + b"[" * 100000 + b"]" * 100000 + b"}")

    def test_a_bomb_between_good_messages(self):
        replies = run_server([PING.encode(), b"[" * 100000, PING.encode()])
        self.assertEqual([r.get("id") for r in replies], [7, None, 7])


class TestAReplyThatCannotBeWritten(unittest.TestCase):
    """An `id` is echoed back, and it can be any JSON value. If echoing it is
    what fails, the server answers without it instead of dying."""

    def serve_with_reply(self, reply):
        replies = None
        with mock.patch.object(mcp_mod, "handle", lambda *a, **k: reply):
            replies = run_server([PING.encode()])
        return replies

    def test_a_reply_nested_too_deep_to_write(self):
        deep = []
        for _ in range(100000):
            deep = [deep]
        replies = self.serve_with_reply(
            {"jsonrpc": "2.0", "id": deep, "result": {}})
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.INTERNAL_ERROR)
        self.assertIsNone(replies[0]["id"])

    def test_a_reply_that_refers_to_itself(self):
        loop = []
        loop.append(loop)
        replies = self.serve_with_reply(
            {"jsonrpc": "2.0", "id": loop, "result": {}})
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.INTERNAL_ERROR)

    def test_the_server_carries_on_afterwards(self):
        calls = []

        def handle(request, *a, **k):
            calls.append(request.get("id"))
            if len(calls) == 1:
                loop = []
                loop.append(loop)
                return {"jsonrpc": "2.0", "id": loop, "result": {}}
            return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

        with mock.patch.object(mcp_mod, "handle", handle):
            replies = run_server([PING.encode(), PING.encode()])
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})


class TestTheRealCommand(unittest.TestCase):
    """The report's reproduction, with a real process and real pipes."""

    def test_the_reported_reproduction_ends_cleanly(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        env["PYTHONPATH"] = _isolation.REPO + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "safeeasyapi", "mcp"],
            input=b"[" * 100000 + b"\n" + PING.encode() + b"\n",
            capture_output=True, env=env, cwd=_isolation.mktemp(), timeout=120)
        self.assertEqual(proc.stderr.decode("utf-8", "replace"), "")
        self.assertEqual(proc.returncode, 0)
        rows = [json.loads(r) for r in proc.stdout.splitlines()]
        self.assertEqual([r.get("id") for r in rows], [None, 7])
        self.assertEqual(rows[0]["error"]["code"], mcp_mod.PARSE_ERROR)


if __name__ == "__main__":
    unittest.main()
