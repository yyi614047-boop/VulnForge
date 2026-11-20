import subprocess
from types import SimpleNamespace

import pytest

from app.lab.metasploit import MetasploitRunner


def fake_runner(outputs):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        output = outputs.pop(0)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    return run, calls


def test_discover_returns_cve_modules_without_duplicates():
    runner, calls = fake_runner([
        "Matching Modules\\n================\\n exploit/linux/http/example\\n auxiliary/scanner/http/example\\n exploit/linux/http/example\\n"
    ])
    client = MetasploitRunner(runner=runner)
    assert client.discover("CVE-2020-1234") == [
        "exploit/linux/http/example", "auxiliary/scanner/http/example"
    ]
    assert calls[0][0] == ["msfconsole", "-q", "-x", "search cve:CVE-2020-1234; exit"]
    assert calls[0][1]["shell"] is False


@pytest.mark.parametrize(("output", "expected"), [
    ("The target appears to be vulnerable. CheckCode::Vulnerable", "vulnerable"),
    ("The target appears to be safe. CheckCode::Safe", "not_vulnerable"),
    ("CheckCode::Detected", "detected"),
    ("CheckNotSupported", "unsupported"),
    ("No definitive result", "inconclusive"),
])
def test_check_output_classification(output, expected):
    assert MetasploitRunner.classify_check(output) == expected


def test_no_module_is_unsupported():
    runner, _ = fake_runner(["No results from search"])
    result = MetasploitRunner(runner=runner).verify("CVE-2020-1234", port=8080)
    assert result["status"] == "unsupported"
    assert result["modules"] == []


def test_positive_native_check_is_vulnerable():
    runner, calls = fake_runner([
        "exploit/linux/http/example",
        "The target appears to be vulnerable. CheckCode::Vulnerable",
    ])
    result = MetasploitRunner(runner=runner).verify("CVE-2020-1234", port=8080)
    assert result["status"] == "vulnerable"
    assert result["modules"][0]["status"] == "vulnerable"
    assert len(calls) == 2


def test_remote_target_is_rejected_before_running_msf():
    runner, calls = fake_runner([])
    with pytest.raises(ValueError, match="localhost"):
        MetasploitRunner(runner=runner).verify("CVE-2020-1234", host="192.0.2.1", port=8080)
    assert not calls


def test_invalid_cve_and_module_are_rejected():
    runner, calls = fake_runner([])
    client = MetasploitRunner(runner=runner)
    with pytest.raises(ValueError):
        client.discover("not-a-cve")
    with pytest.raises(ValueError):
        client.check_module("exploit/../../bad", "127.0.0.1", 8080)
    assert not calls


def test_nonzero_msf_exit_is_an_error():
    def run(argv, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        MetasploitRunner(runner=run).discover("CVE-2020-1234")
