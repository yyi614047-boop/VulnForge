"""Stable content hashing shared by planning and execution."""
import hashlib


def digest(text: str) -> str:
    """Return a SHA-256 digest for a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
