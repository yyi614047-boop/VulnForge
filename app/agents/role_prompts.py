"""Load Markdown role instructions shared by Pipeline agents."""
from pathlib import Path
import re

_ROLE_ROOT = Path(__file__).resolve().parent / "roles"


def load_role_prompt(name: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name):
        raise ValueError("Invalid role name")
    return (_ROLE_ROOT / f"{name}.md").read_text(encoding="utf-8").strip()
