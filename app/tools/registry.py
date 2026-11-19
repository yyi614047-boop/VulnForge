"""Small allowlist registry for validated, explicitly registered tools."""

from dataclasses import dataclass, field
from typing import Callable

from pydantic import BaseModel, ValidationError


class ToolRegistryError(Exception):
    """Base class for expected registry and tool errors."""


class ToolNotFoundError(ToolRegistryError):
    """Raised when a name is not registered."""


class ToolInputValidationError(ToolRegistryError):
    """Raised when tool input does not satisfy its declared model."""


class ToolExecutionError(ToolRegistryError):
    """Expected failure reported by a tool."""


class ToolTimeoutError(ToolExecutionError):
    """Deterministic simulated timeout reported by a tool."""


@dataclass(frozen=True)
class ToolCallResult:
    """Uniform successful return value from a registered tool."""

    tool: str
    summary: str
    output: str
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolOutput:
    """Tool supplied display output and machine-checkable evidence."""

    output: str
    evidence: dict[str, object]


ToolFunction = Callable[[BaseModel], str | ToolOutput]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: type[BaseModel]
    function: ToolFunction


class ToolRegistry:
    """Maps fixed names to typed functions; it never resolves code dynamically."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    @property
    def tool_names(self) -> frozenset[str]:
        """Names available for validation; callers cannot mutate the registry."""
        return frozenset(self._tools)

    def register(
        self, name: str, input_model: type[BaseModel], function: ToolFunction
    ) -> None:
        if not name.strip():
            raise ValueError("tool name must not be empty")
        if name in self._tools:
            raise ValueError(f"tool '{name}' is already registered")
        self._tools[name] = ToolSpec(name, input_model, function)

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(f"tool '{name}' is not registered") from exc

    def call(self, name: str, parameters: BaseModel | dict[str, object]) -> ToolCallResult:
        spec = self.get(name)
        try:
            validated = spec.input_model.model_validate(parameters)
        except ValidationError as exc:
            raise ToolInputValidationError(str(exc)) from exc
        tool_output = spec.function(validated)
        if isinstance(tool_output, ToolOutput):
            output, evidence = tool_output.output, tool_output.evidence
        else:
            output, evidence = tool_output, {}
        return ToolCallResult(
            tool=name, summary=f"{name} completed", output=output, evidence=evidence
        )
