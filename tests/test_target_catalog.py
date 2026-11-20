import yaml

from app.domain.policies import ExecutionPolicy
from app.domain.reproduction import Probe, ReproductionSpec
from app.targets.vulhub.catalog import TargetCatalog


def make_spec():
    return ReproductionSpec(
        id="CVE-2024-12345",
        title="Demo vulnerability",
        product="demo",
        affected_versions=["1.0"],
        dependencies=["docker"],
        prerequisites=["local lab"],
        sources=["README.md"],
        environment="compose.yml",
        service="web",
        port=8080,
        health=Probe(id="health", path="/health"),
        reproduction=[Probe(id="repro", path="/poc", body_contains="vulnerable")],
    )


def build_catalog(tmp_path):
    (tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / "compose.yml").write_text(yaml.safe_dump({
        "services": {"web": {"image": "nginx:1.25", "ports": ["127.0.0.1:8080:80"]}}
    }), encoding="utf-8")
    spec = make_spec()
    (tmp_path / "CVE-2024-12345.yaml").write_text(
        yaml.safe_dump(spec.model_dump(mode="json")), encoding="utf-8"
    )
    return TargetCatalog(tmp_path), spec


def test_target_catalog_builds_target_and_policy_fingerprints(tmp_path):
    catalog, spec = build_catalog(tmp_path)
    loaded = catalog.get(spec.id)
    target = catalog.to_target_spec(loaded)

    assert target.target_id == spec.id
    assert target.environment.services == ["web"]
    assert target.environment.published_ports == {"web": [8080]}
    assert target.fingerprint()
    assert loaded.fingerprint() == spec.fingerprint()

    policy = ExecutionPolicy(
        policy_id="reviewed-demo",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={spec.id: spec.fingerprint()},
        allowed_actions={"up", "http", "verify_http", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
    )
    policy.authorize_target(target, loaded)


def test_policy_rejects_changed_reproduction_spec(tmp_path):
    catalog, spec = build_catalog(tmp_path)
    target = catalog.to_target_spec(spec)
    policy = ExecutionPolicy(
        policy_id="reviewed-demo",
        approved_target_hashes={target.target_id: target.fingerprint()},
        approved_reproduction_hashes={spec.id: spec.fingerprint()},
        allowed_actions={"up", "http", "verify_http", "down"},
        allowed_services={"web"},
        allowed_ports={8080},
    )
    changed = spec.model_copy(update={"title": "Modified after review"})
    try:
        policy.authorize_target(target, changed)
    except PermissionError:
        pass
    else:
        raise AssertionError("Changed reproduction spec must be rejected")
