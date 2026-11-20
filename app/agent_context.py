"""Application-level context boundaries, not a sandbox for Python plugins."""
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field
from functools import wraps
from uuid import uuid4

from app.trace import traced_call


@dataclass
class AgentContext:
    run_id: str
    agent_id: str
    turns: list = field(default_factory=list)


_run: ContextVar = ContextVar("agent_run", default=None)
_agent: ContextVar = ContextVar("active_agent", default=None)


def current_agent_context():
    """Return a detached snapshot of only the currently executing agent."""
    context = _agent.get()
    if context is None:
        raise RuntimeError("No active agent invocation")
    return deepcopy(context)


def isolated_run(function):
    """Start a fresh private context registry; release it even on failure."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        token = _run.set((uuid4().hex, {}))
        agent_token = _agent.set(None)
        try:
            return function(*args, **kwargs)
        finally:
            _agent.reset(agent_token)
            _run.reset(token)
    return wrapped


def invoke_agent(agent_id, model, prompt):
    """Invoke with an explicit prompt; private history is never auto-forwarded."""
    if _run.get() is None:
        return isolated_run(invoke_agent)(agent_id, model, prompt)
    run_id, contexts = _run.get()
    context = contexts.setdefault(agent_id, AgentContext(run_id, agent_id))
    token = _agent.set(context)
    try:
        result = traced_call("model", agent_id, {"prompt": prompt},
                             lambda: model.invoke(deepcopy(prompt)))
        context.turns.append({"prompt": deepcopy(prompt), "result": deepcopy(result)})
        del context.turns[:-16]
        return result
    finally:
        _agent.reset(token)


def agent_session(function):
    """Reuse an orchestrated run, or isolate a standalone component call."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        if _run.get() is None:
            return isolated_run(function)(*args, **kwargs)
        return function(*args, **kwargs)
    return wrapped


def state_boundary(*, reads, writes):
    """Project and detach node input; reject undeclared output before merging."""
    reads, writes = frozenset(reads), frozenset(writes)
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            # Nodes use either node(state) or a bound method node(self, state).
            if "state" in kwargs:
                state = kwargs["state"]
                kwargs = {**kwargs, "state": deepcopy({k: v for k, v in state.items() if k in reads})}
            else:
                state = args[-1]
                args = (*args[:-1], deepcopy({k: v for k, v in state.items() if k in reads}))
            update = function(*args, **kwargs)
            if not isinstance(update, dict) or set(update) - writes:
                raise ValueError(f"{function.__name__} returned undeclared shared-state fields")
            return deepcopy(update)
        return wrapped
    return decorate
