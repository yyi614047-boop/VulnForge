"""Compatibility import; canonical researcher agent lives in app.agents."""
from app.agents.researcher import Fact, Researcher, Synthesis
__all__ = ["Fact", "Researcher", "Synthesis"]
