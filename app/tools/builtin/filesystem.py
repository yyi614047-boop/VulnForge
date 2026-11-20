"""Scoped file inspection and versioned text artifacts for agent tools."""
import ast
import hashlib
from pathlib import Path, PurePosixPath, PureWindowsPath

from pydantic import BaseModel, ConfigDict, Field

from app.tools.registry import ToolOutput, ToolRegistry


def local_path(root: Path, name: str, *, allow_root=False) -> Path:
    if not name or "\\" in name or PureWindowsPath(name).drive or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
        raise ValueError("Use a relative project path without traversal")
    root = root.resolve()
    path = root / name
    for item in [path, *path.parents]:
        if item == root:
            break
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("Linked paths are not allowed")
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or (resolved == root and not allow_root):
        raise ValueError("Path must stay inside the project")
    return resolved


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FileParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = "."
    start_line: int = Field(default=1, ge=1)
    max_lines: int = Field(default=200, ge=1, le=1000)


class WriteParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    content: str = Field(max_length=262144)
    expected_hash: str | None = None


class WorkspaceFiles:
    def __init__(self, root: Path, *, writable=False):
        self.root, self.writable = root.resolve(), writable

    def inspect(self, params: FileParams):
        base = local_path(self.root, params.path, allow_root=True)
        files = []
        for path in sorted(base.rglob("*") if base.is_dir() else [base]):
            checked = local_path(self.root, path.relative_to(self.root).as_posix())
            if checked.is_file() and ".versions" not in checked.relative_to(self.root).parts:
                files.append({"path": checked.relative_to(self.root).as_posix(), "bytes": checked.stat().st_size})
            if len(files) >= 1000:
                break
        return ToolOutput("Workspace inspected", {"files": files, "limit": 1000})

    def read(self, params: FileParams):
        path = local_path(self.root, params.path)
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("Text read limited to 1 MiB")
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        selected = lines[params.start_line-1:params.start_line-1+params.max_lines]
        return ToolOutput("".join(selected), {"path": params.path, "sha256": file_hash(path),
                         "start_line": params.start_line, "total_lines": len(lines)})

    def write(self, params: WriteParams):
        if not self.writable:
            raise ValueError("This workspace is read-only")
        path = local_path(self.root, params.path)
        if ".versions" in path.relative_to(self.root).parts:
            raise ValueError("Version history is managed by the artifact tool")
        if path.suffix == ".py":
            ast.parse(params.content, filename=params.path)
        previous = file_hash(path) if path.exists() else None
        if previous != params.expected_hash:
            raise ValueError("Artifact changed; read its current hash before overwriting")
        if path.exists():
            history = self.root / ".versions" / previous
            history.parent.mkdir(parents=True, exist_ok=True)
            if not history.exists():
                history.write_bytes(path.read_bytes())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(params.content)
        return ToolOutput("Artifact saved", {"path": params.path, "sha256": file_hash(path), "previous_hash": previous})

    def registry(self):
        registry = ToolRegistry()
        registry.register("inspect_workspace", FileParams, self.inspect)
        registry.register("read_document", FileParams, self.read)
        if self.writable:
            registry.register("write_artifact", WriteParams, self.write)
        return registry
