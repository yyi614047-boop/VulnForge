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


def test_minimal_happy_path_defaults_to_reviewed_policy_and_run():
    args = cli._parser().parse_args(["CVE-2021-25646"])
    assert args.action == "run"
    assert str(args.policy_file) == "policies/local.json"
    assert not args.no_msf_check


def test_batch_parses_file_path():
    args = cli._parser().parse_args(["--batch", "targets.txt"])
    assert str(args.batch) == "targets.txt"


def test_batch_rejects_missing_reviewed_policy(monkeypatch, tmp_path):
    import pytest
    batch = tmp_path / "targets.txt"
    batch.write_text("CVE-2021-25646\\n")
    monkeypatch.setattr(sys, "argv", ["vulnforge", "--batch", str(batch),
                                    "--policy", str(tmp_path / "missing.json")])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2


def test_batch_runs_sequentially_and_reports_partial_failure(monkeypatch, tmp_path, capsys):
    import subprocess
    import pytest
    batch = tmp_path / "targets.txt"
    batch.write_text("# approved\\nCVE-2021-25646\\nCVE-2024-12345\\n")
    policy = tmp_path / "reviewed.json"
    policy.write_text("{}")
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0 if len(calls) == 1 else 1)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["vulnforge", "--batch", str(batch), "--policy", str(policy)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert len(calls) == 2
    assert calls[0][-3:] == ["CVE-2021-25646", "--policy", str(policy)]
    assert calls[1][-3:] == ["CVE-2024-12345", "--policy", str(policy)]
    assert '"failed": 1' in capsys.readouterr().out
