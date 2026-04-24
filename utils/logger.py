"""
Structured, coloured logger backed by Rich.
Call ``get_logger(__name__)`` anywhere in the project.
"""

import logging

from rich.logging import RichHandler


def get_logger(name: str) -> logging.Logger:
    """Return a logger with Rich formatting attached."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                markup=True,
                show_path=False,
            )
        ],
    )
    return logging.getLogger(name)
