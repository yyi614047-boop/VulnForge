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
