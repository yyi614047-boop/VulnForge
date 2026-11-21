import json
import sys

from app import cli


def test_metasploit_rpc_version_cli_reports_live_version(monkeypatch, capsys):
    class Client:
        def call(self, method):
            assert method == "core.version"
            return {"version": "6.4.0", "ruby": "3.3.0"}

    monkeypatch.setattr(sys, "argv", ["vulnforge", "--action", "metasploit-rpc-version"])
    monkeypatch.setattr(cli.MetasploitRpcClient, "from_env", classmethod(lambda cls: Client()))
    cli.main()
    output = json.loads(capsys.readouterr().out)
    assert output["rpc"] == "connected"
    assert output["version"]["version"] == "6.4.0"



def test_cli_exposes_separate_check_only_verification_flag():
    from app.cli import _parser
    args = _parser().parse_args([
        "CVE-2024-12345", "--action", "run", "--discover-metasploit",
        "--enable-metasploit-verification",
    ])
    assert args.enable_metasploit_verification is True
    assert args.enable_metasploit_execution is False


def test_happy_path_cli_parses_short_flags_without_redundant_action_or_discovery():
    from app.cli import _parser
    args = _parser().parse_args([
        "CVE-2021-25646", "--policy", "policies/local.json", "--msf-check",
    ])
    assert args.identifier == "CVE-2021-25646"
    assert args.action == "run"
    assert str(args.policy_file) == "policies/local.json"
    assert args.enable_metasploit_verification
    assert not args.enable_metasploit_execution


def test_legacy_metasploit_flags_remain_compatible():
    from app.cli import _parser
    args = _parser().parse_args([
        "CVE-2021-25646", "--action", "run", "--policy-file", "policies/local.json",
        "--discover-metasploit", "--enable-metasploit-verification",
    ])
    assert args.action == "run"
    assert args.enable_metasploit_verification
    assert args.discover_metasploit
