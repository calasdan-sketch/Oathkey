import shutil
import subprocess

import pytest

from safeeasyapi import remote

GITHUB = {"service": "github", "env_var": "GITHUB_TOKEN",
          "fields": [{"env_var": "GITHUB_TOKEN", "name": "key", "label": "token"}]}
TOKEN = "gho_" + "A" * 36


def _env(tmp_path, token=TOKEN):
    f = tmp_path / ".env"
    f.write_text(f"GITHUB_TOKEN={token}\n")
    return str(f)


def test_secret_goes_on_stdin_only(tmp_path):
    seen = {}

    def runner(argv, input=None):
        seen["argv"], seen["input"] = argv, input
        return subprocess.CompletedProcess(argv, 0)

    code = remote.run_remote(GITHUB, "root@203.0.113.7", ["git", "pull"],
                             env_file=_env(tmp_path), run_as="calas",
                             runner=runner, backend=None)
    assert code == 0
    assert TOKEN not in " ".join(seen["argv"])          # never on a command line
    assert seen["input"] == (TOKEN + "\n").encode()      # only on stdin
    assert "BatchMode=yes" in seen["argv"]               # never waits on a password
    assert "runuser -u calas -- git pull" in seen["argv"][-1]


def test_bad_host_and_user_refused(tmp_path):
    for bad in ("-oProxyCommand=x", "a b", "x;y", ""):
        with pytest.raises(remote.RemoteError):
            remote.check_host(bad)
    with pytest.raises(remote.RemoteError):
        remote.build_script(GITHUB, ["git"], run_as="root; rm -rf /")


def test_line_break_in_stored_key_refused(tmp_path):
    f = tmp_path / ".env"
    f.write_text('GITHUB_TOKEN="abc\\ndef"\n')
    # whatever the file parser yields, a value with a newline must not be sent
    try:
        vals = remote.collect_values(GITHUB, str(f), backend=None)
    except remote.RemoteError:
        return
    assert "\n" not in vals["GITHUB_TOKEN"]


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("base64") is None,
                    reason="needs a POSIX shell")
def test_script_really_exports_token_and_git_header():
    script = remote.build_script(
        GITHUB, ["sh", "-c", 'echo "$GITHUB_TOKEN|$GIT_CONFIG_COUNT|$GIT_CONFIG_VALUE_0"'])
    out = subprocess.run(["sh", "-c", script], input=(TOKEN + "\n").encode(),
                         capture_output=True).stdout.decode().strip()
    tok, count, header = out.split("|")
    assert tok == TOKEN and count == "1"
    assert header.startswith("Authorization: Basic ")
