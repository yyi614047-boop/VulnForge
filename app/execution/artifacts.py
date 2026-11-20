"""Content-addressed target and execution artifacts."""
import ast
import hashlib
import shutil
from app.tools.builtin.filesystem import local_path, file_hash
from app.environments.docker.manager import environment_assets


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


"""Content manifest binding local environment and scripts to a research result."""
import ast




def collect_assets(kb, card, config):
    """收集 Compose 和知识卡引用的脚本、挂载及构建等资产清单。"""
    environment = environment_assets(kb.environment(card), config)
    scripts = {}
    for script in [*card.initialization, *card.scripts]:
        if script.service not in config["services"]:
            raise ValueError("Script service is missing from Compose")
        path = local_path(kb.root, script.source)
        if path.suffix != ".py" or path.stat().st_size > 262144:
            raise ValueError("Scripts must be Python text files under 256 KiB")
        ast.parse(path.read_text(encoding="utf-8"), filename=script.source)
        scripts[script.source] = file_hash(path)
    for evidence in [*card.file_evidence, *card.version_probes]:
        if evidence.service not in config["services"]:
            raise ValueError("Evidence service is missing from Compose")
    return {"environment": environment, "scripts": scripts}


def snapshot(source: Path, destination: Path):
    """Copy bounded regular inputs; never follow linked paths or copy into source."""
    source, destination = source.resolve(), destination.resolve()
    if destination.is_relative_to(source):
        raise ValueError("Authoring workspace must be outside the knowledge directory")
    files, total = [], 0
    for path in sorted(source.rglob("*")):
        checked = local_path(source, path.relative_to(source).as_posix())
        if checked.is_file():
            total += checked.stat().st_size
            files.append(checked)
            if total > 32 * 1024 * 1024 or len(files) > 1000:
                raise ValueError("Knowledge snapshot exceeds 32 MiB / 1000 files")
    destination.mkdir(parents=True, exist_ok=False)
    for path in files:
        expected = file_hash(path)
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if file_hash(target) != expected:
            raise ValueError("Knowledge changed during snapshot")

