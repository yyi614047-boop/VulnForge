import pytest
from app.targets.vulhub import VulhubTargetLoader


def test_loader_builds_untrusted_target_candidate(tmp_path):
    env = tmp_path / "demo" / "CVE-2024-12345"
    env.mkdir(parents=True)
    (env / "README.md").write_text("\n".join(["# Demo vulnerability", "CVE-2024-12345 affects demo.", ""]), encoding="utf-8")
    (env / "docker-compose.yml").write_text("\n".join([
        "services:", "  web:", "    image: nginx:1.25", "    ports:", "      - '127.0.0.1:8080:80'", ""]), encoding="utf-8")
    (env / "poc.py").write_text("print('candidate only')\n", encoding="utf-8")

    loader = VulhubTargetLoader(tmp_path)
    candidate = loader.load("demo/CVE-2024-12345")
    assert candidate.target_id == "demo:CVE-2024-12345"
    assert candidate.vulnerability_id == "CVE-2024-12345"
    assert candidate.environment.services == ["web"]
    assert candidate.environment.published_ports == {"web": [8080]}
    assert candidate.reproduction_entrypoints == ["demo/CVE-2024-12345/poc.py"]
    assert loader.search("CVE-2024-12345")[0].target_id == candidate.target_id


def test_loader_rejects_environment_path_escape(tmp_path):
    root = tmp_path / "vulhub"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "docker-compose.yml").write_text("services: {web: {image: nginx}}", encoding="utf-8")
    loader = VulhubTargetLoader(root)
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        # Creating directory symlinks may require elevated privileges on Windows.
        # Keep the traversal assertion meaningful even when the OS blocks symlink creation.
        if getattr(exc, "winerror", None) != 1314:
            raise
        with pytest.raises(ValueError):
            loader.load("../outside")
    else:
        with pytest.raises(ValueError):
            loader.load("escape")
