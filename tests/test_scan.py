import json
import os

from safeeasyapi import cli, scan

# built at run time so this test file itself never contains a key-shaped string
GH = "gh" + "o_" + "B" * 36
STRIPE = "sk_" + "live_" + "C" * 24


def test_finds_keys_and_never_prints_them(tmp_path):
    (tmp_path / "app.py").write_text(f'TOKEN = "{GH}"\nx = 1\n')
    (tmp_path / "pay.js").write_text(f"const k = '{STRIPE}'\n")
    res = scan.scan([str(tmp_path)], include_home=False)
    kinds = {f["kind"] for f in res["findings"]}
    assert {"GitHub token", "Stripe secret key"} <= kinds
    report = scan.format_report(res) + json.dumps(res)
    assert GH not in report and STRIPE not in report          # never the whole secret
    assert any(f["line"] == 1 for f in res["findings"])


def test_skips_git_and_binary_and_large(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(GH)
    (tmp_path / "bin.dat").write_bytes(b"\0\0" + GH.encode())
    (tmp_path / "big.txt").write_text(("a" * 2_000_000) + GH)
    res = scan.scan([str(tmp_path)], include_home=False)
    assert res["findings"] == []


def test_agent_settings_file_gets_a_warning(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    (d / "settings.local.json").write_text('{"allow": ["curl -H \\"x: %s\\""]}' % GH)
    res = scan.scan([str(tmp_path)], include_home=False)
    assert res["findings"] and any("AI-tool" in w["why"] for w in res["warnings"])


def test_home_history_is_checked(tmp_path):
    (tmp_path / ".bash_history").write_text(f"export T={GH}\n")
    res = scan.scan([], home=str(tmp_path), include_home=True)
    assert len(res["findings"]) == 1


def test_cli_exit_codes_and_json(tmp_path, capsys):
    (tmp_path / "ok.txt").write_text("nothing here\n")
    assert cli.main(["scan", str(tmp_path), "--no-home", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    (tmp_path / "bad.txt").write_text(GH)
    assert cli.main(["scan", str(tmp_path), "--no-home"]) == 1


def test_doctor_shape():
    res = scan.doctor(env={}, which=lambda _n: None)
    names = {c["check"] for c in res["checks"]}
    assert {"python", "keychain", "ssh", "git"} <= names
    assert res["ok"] is False                                  # ssh/git missing
    assert "FIX" in scan.format_doctor(res)
