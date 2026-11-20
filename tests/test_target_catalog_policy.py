import json
import pytest

from app.domain.policies import ExecutionPolicy
from app.targets.vulhub.catalog import TargetCatalog


def write_fixture(root, published_port="127.0.0.1:8080:80"):
    (root / "README.md").write_text("# Demo target\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n    ports:\n      - '" + published_port + "'\n",
        encoding="utf-8",
    )
    spec = {
        "id": "CVE-2024-12345",
        "title": "Demo reproduction",
        "product": "demo",
        "affected_versions": ["1.0"],
        "dependencies": ["docker"],
        "prerequisites": ["local lab"],
        "sources": ["README.md"],
        "environment": "docker-compose.yml",
        "service": "web",
        "port": 8080,
        "health": {"id": "health", "path": "/health"},
        "reproduction": [{"id": "probe", "path": "/vulnerable", "body_contains": "vulnerable"}],
    }
    (root / "CVE-2024-12345.yaml").write_text(json.dumps(spec), encoding="utf-8")


def test_target_catalog_fingerprints_local_sources_and_policy_binds_both_specs(tmp_path):
    write_fixture(tmp_path)
    catalog = TargetCatalog(tmp_path)
    reproduction = catalog.get("CVE-2024-12345")
    target = catalog.to_target_spec(reproduction)

    assert all(source.sha256 for source in target.sources)
    policy = ExecutionPolicy(
        policy_id="local-demo",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={reproduction.id: reproduction.fingerprint()},
        allowed_actions={"pull", "up", "status", "health", "http", "verify", "down"},
        retryable_actions={"pull", "status", "health", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
    )
    policy.authorize_target(target, reproduction)

    (tmp_path / "README.md").write_text("# Changed source\n", encoding="utf-8")
    changed_target = catalog.to_target_spec(reproduction)
    with pytest.raises(PermissionError, match="fingerprint"):
        policy.authorize_target(changed_target, reproduction)


def test_target_catalog_rejects_non_loopback_published_ports(tmp_path):
    write_fixture(tmp_path, published_port="8080:80")
    catalog = TargetCatalog(tmp_path)
    with pytest.raises(ValueError, match="loopback"):
        catalog.to_target_spec("CVE-2024-12345")
