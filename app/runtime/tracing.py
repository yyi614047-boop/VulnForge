"""Append durable model and tool events for an active experiment."""
import json
import os
import time
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import re


_recorder = ContextVar("experiment_trace", default=None)


_SECRET_KEYS = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)", re.I)
_SECRET_VALUES = re.compile(r"(?i)(bearer\\s+\\S+|sk-[A-Za-z0-9_-]{12,})")


def serializable(value, *, depth=0):
    """Bounded, redacted trace data; model/tool payloads are not persisted."""
    if depth > 5:
        return "[truncated]"
    if is_dataclass(value) and not isinstance(value, type):
        return serializable(asdict(value), depth=depth + 1)
    if hasattr(value, "model_dump"):
        return serializable(value.model_dump(mode="json"), depth=depth + 1)
    if isinstance(value, dict):
        return {str(key)[:100]: ("[REDACTED]" if _SECRET_KEYS.search(str(key))
                else serializable(item, depth=depth + 1))
                for key, item in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [serializable(item, depth=depth + 1) for item in value[:40]]
    if isinstance(value, str):
        return _SECRET_VALUES.sub("[REDACTED]", value[:500])
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return f"<{type(value).__name__}>"


class TraceRecorder:
    def __init__(self, path, run_id):
        self.path, self.run_id = Path(path), run_id
        self.sequence = 0

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("x", encoding="utf-8")
        self.token = _recorder.set(self)
        return self

    def __exit__(self, *args):
        _recorder.reset(self.token)
        self.handle.close()

    def emit(self, event, **fields):
        self.sequence += 1
        payload = {"run_id": self.run_id, "sequence": self.sequence,
                   "time": datetime.now(timezone.utc).isoformat(), "event": event,
                   **serializable(fields)}
        self.handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.handle.flush()
        os.fsync(self.handle.fileno())


def emit(event, **fields):
    recorder = _recorder.get()
    if recorder is not None:
        recorder.emit(event, **fields)


def traced_call(category, name, parameters, function):
    if _recorder.get() is None:
        return function()
    call_id = uuid4().hex
    started = time.monotonic()
    emit(category + ".start", call_id=call_id, name=name, input_type=type(parameters).__name__)
    try:
        result = function()
    except BaseException as exc:
        emit(category + ".error", call_id=call_id, name=name,
             error={"type": type(exc).__name__},
             duration_ms=round((time.monotonic() - started) * 1000, 3))
        raise
    emit(category + ".end", call_id=call_id, name=name, output_type=type(result).__name__,
         duration_ms=round((time.monotonic() - started) * 1000, 3))
    return result
