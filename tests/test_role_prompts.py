from app.agents.role_prompts import load_role_prompt
from app.lab.hashing import digest


def test_role_prompts_are_markdown_and_nonempty():
    for role in ("researcher", "planner"):
        prompt = load_role_prompt(role)
        assert prompt.startswith("# ")
        assert len(prompt) > 100


def test_role_prompt_rejects_path_traversal():
    import pytest

    with pytest.raises(ValueError):
        load_role_prompt("../README")


def test_digest_is_stable_sha256():
    assert digest("vulnforge") == digest("vulnforge")
    assert len(digest("vulnforge")) == 64
