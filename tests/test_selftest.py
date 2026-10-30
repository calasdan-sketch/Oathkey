"""The selftest must pass on good code AND fail when the protections are broken."""
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from oathkey import broker, selftest


class SelftestTests(unittest.TestCase):
    def test_all_attacks_stopped(self):
        bad = [r for r in selftest.run_all() if not r["pass"]]
        self.assertEqual(bad, [])

    def test_exit_code_and_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = selftest.cmd_selftest(as_json=True)
        data = json.loads(buf.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(data["passed"], data["total"])
        self.assertGreaterEqual(data["total"], 30)

    def test_fails_when_scrubbing_is_broken(self):
        class NoScrub:
            def __init__(self, secrets):
                pass

            def feed(self, raw):
                return raw

            def flush(self):
                return b""
        with mock.patch.object(broker, "Scrubber", NoScrub), \
                mock.patch.object(broker, "loosely_contains", lambda *a, **k: False):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "echoes" in r["attack"] for r in results))

    def test_fails_when_address_check_is_broken(self):
        with mock.patch.object(broker, "is_public_ip", lambda ip: True):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "pointing at" in r["attack"] for r in results))

    def test_fails_when_path_check_is_broken(self):
        with mock.patch.object(broker, "check_path", lambda p: p):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "Odd path" in r["attack"] for r in results))

    def test_exit_code_is_one_on_failure(self):
        with mock.patch.object(broker, "is_public_ip", lambda ip: True):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(selftest.cmd_selftest(), 1)


if __name__ == "__main__":
    unittest.main()
