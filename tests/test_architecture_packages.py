def test_canonical_architecture_packages_import_without_cycles():
    from app.cli import main
    from app.agents.planner import StructuredPlanner
    from app.agents.researcher import Researcher
    from app.environments.docker.engine import DockerEngine
    from app.environments.docker.manager import DockerLab
    from app.execution.executor import StepExecutor
    from app.runtime.context import invoke_agent
    from app.tools.builtin.filesystem import WorkspaceFiles
    from app.workflows.reproduction.graph import Pipeline

    assert all((main, StructuredPlanner, Researcher, DockerEngine, DockerLab,
                StepExecutor, invoke_agent, WorkspaceFiles, Pipeline))


def test_reproduction_contracts_live_in_domain_and_catalog_is_an_adapter():
    from app.domain.reproduction import ReproductionSpec
    from app.targets.vulhub.catalog import TargetCatalog

    assert ReproductionSpec.__module__ == "app.domain.reproduction"
    assert TargetCatalog.__name__ == "TargetCatalog"
