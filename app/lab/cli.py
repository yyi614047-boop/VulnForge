"""Compatibility import; canonical command-line entry point is app.cli."""
from app.cli import main
__all__ = ["main"]

if __name__ == "__main__":
    main()
