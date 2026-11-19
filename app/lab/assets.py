"""Content manifest binding local environment and scripts to a research result."""
import ast
from app.tools.files import local_path, file_hash
from app.tools.docker_lab import environment_assets


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
