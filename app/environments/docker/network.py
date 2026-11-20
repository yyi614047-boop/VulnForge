"""Prepare a knowledge snapshot when the requested loopback port cannot bind."""
import json
import socket
from pathlib import Path
from uuid import uuid4

import yaml

from app.targets.vulhub.catalog import TargetCatalog
from app.environments.docker.manager import load_compose


def choose_port(preferred):
    """检查首选端口是否可用，必要时选择可绑定的替代端口。"""
    with socket.socket() as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def prepare_port(knowledge, workspace, identifier, *, chooser=choose_port):
    """为知识副本准备可用端口并记录端口选择结果。"""
    # Import lazily: authoring orchestrates Pipeline, which uses this preparation.
    from app.execution.artifacts import snapshot
    kb = TargetCatalog(knowledge)
    card = kb.get(identifier)
    selected = chooser(card.port)
    if selected == card.port:
        return Path(knowledge), {"requested": card.port, "selected": selected, "changed": False}
    root = Path(workspace).resolve() / "port-inputs" / uuid4().hex[:12]
    snapshot(Path(knowledge), root)
    clone = TargetCatalog(root)
    source = clone.environment(card)
    config = load_compose(source)
    service = config["services"][card.service]
    service["ports"] = [p.replace(f"127.0.0.1:{card.port}:", f"127.0.0.1:{selected}:", 1)
                        if p.startswith(f"127.0.0.1:{card.port}:") else p for p in service.get("ports", [])]
    prepared = source.with_name(source.stem + "-selected-port.json")
    prepared.write_text(json.dumps(config, indent=2), encoding="utf-8")
    replacement = prepared.relative_to(root).as_posix()
    for path in root.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data.get("id") == card.id:
            data.update(port=selected, environment=replacement)
            data["sources"] = [replacement if p == card.environment else p for p in data["sources"]]
            data["prerequisites"] = [p.replace(str(card.port), str(selected)) for p in data["prerequisites"]]
            path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return root, {"requested": card.port, "selected": selected, "changed": True, "knowledge": str(root.resolve()),
                  "reason": "Requested port could not be bound; selected an available loopback port"}
