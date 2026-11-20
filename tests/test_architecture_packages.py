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


def test_legacy_card_import_is_confined_to_target_adapter():
    from app.lab.knowledge import Card as CompatibilityCard
    from app.targets.vulhub.legacy_cards import Card as LegacyCard

    assert CompatibilityCard is LegacyCard
