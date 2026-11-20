"""OpenAI-compatible chat model configuration shared by authoring utilities."""
import os


def configured_model():
    from langchain_openai import ChatOpenAI
    model = os.environ.get("PLANNER_MODEL")
    if not model:
        raise ValueError("Set PLANNER_MODEL before selecting a model-backed operation")
    return ChatOpenAI(model=model, temperature=0, timeout=60, max_retries=1)
