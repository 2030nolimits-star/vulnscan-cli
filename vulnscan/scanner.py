"""File discovery and reading for vulnscan."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

MAX_FILE_BYTES = 200 * 1024

LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".c": "C",
    ".h": "C header",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++ header",
    ".hh": "C++ header",
    ".cs": "C#",
    ".rs": "Rust",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin script",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
}

SKIP_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "vendor",
        "target",
    }
)


@dataclass(frozen=True)
class SourceFile:
    """A source file that has been read into memory and is ready for analysis."""

    path: Path
    language: str
    content: str


def language_for(path: Path) -> str | None:
    """Return a human-readable language label for a path, or None if unsupported."""
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def _iter_candidate_paths(root: Path) -> Iterator[Path]:
    """Walk root (file or directory), yielding files while skipping vendored dirs."""
    if root.is_file():
        yield root
        return

    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        yield path


def discover(root: Path) -> Iterator[SourceFile]:
    """Yield SourceFile entries for every supported, readable file under root."""
    for path in _iter_candidate_paths(root):
        language = language_for(path)
        if language is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield SourceFile(path=path, language=language, content=content)
