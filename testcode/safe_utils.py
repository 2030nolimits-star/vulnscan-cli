"""Intentionally clean helper module used to confirm prefilter skipping.

Semgrep should find nothing here, so with --prefilter on this file should not
reach the deep-reasoning pass.
"""

from __future__ import annotations


def add(a: int, b: int) -> int:
    return a + b


def greet(name: str) -> str:
    safe = "".join(ch for ch in name if ch.isalnum() or ch in " -")
    return f"hello {safe}"
