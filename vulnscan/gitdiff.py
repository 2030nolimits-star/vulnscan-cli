"""Git-diff driven file discovery for vulnscan."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitError(RuntimeError):
    """Raised when a git operation fails or the path isn't inside a repo."""


@dataclass(frozen=True)
class DiffInfo:
    """Result of consulting `git` for a diff scope."""

    repo_root: Path
    changed_files: list[Path] = field(default_factory=list)
    ranges_by_file: dict[Path, list[tuple[int, int]]] = field(default_factory=dict)


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def repo_root_for(path: Path) -> Path | None:
    """Return the git repo root containing `path`, or None if it is not in a repo."""
    start = path if path.is_dir() else path.parent
    try:
        result = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
    except FileNotFoundError as exc:
        raise GitError(
            "git executable not found on PATH — install git to use --diff."
        ) from exc
    if result.returncode != 0:
        return None
    root = result.stdout.strip()
    if not root:
        return None
    return Path(root).resolve()


def _diff_scope_args(ref: str | None, staged_only: bool) -> list[str]:
    """Translate a (ref, staged_only) combination into git-diff arguments."""
    if ref:
        return [f"{ref}...HEAD"]
    if staged_only:
        return ["--cached"]
    # Working tree vs HEAD = staged + unstaged (matches the user's spec exactly:
    # `git diff --name-only HEAD` already includes both, and we additionally
    # union with `--cached` for safety in case of unusual index states).
    return ["HEAD"]


def _parse_name_status(stdout: str) -> list[str]:
    """Parse `git diff --name-status` output, dropping deletions, picking new names on renames."""
    changed: list[str] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0][:1]
        if status == "D":
            continue  # deleted
        # For R/C entries: status\told\tnew → take the new name.
        path_str = parts[-1]
        if path_str:
            changed.append(path_str)
    return changed


def parse_hunk_ranges(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Parse a unified diff (-U0 recommended) into changed-line ranges per file."""
    ranges: dict[str, list[tuple[int, int]]] = {}
    current_file: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current_file = None
            else:
                if target.startswith("b/"):
                    target = target[2:]
                current_file = target
        elif current_file and line.startswith("@@"):
            match = HUNK_RE.match(line)
            if not match:
                continue
            start = int(match.group(1))
            length = int(match.group(2)) if match.group(2) is not None else 1
            if length == 0:
                continue  # pure deletion at this anchor — no new lines to scan
            end = start + length - 1
            ranges.setdefault(current_file, []).append((start, end))
    return ranges


def diff_info(
    target: Path,
    ref: str | None = None,
    staged_only: bool = False,
) -> DiffInfo:
    """Return changed files (plus per-file line ranges) for the requested scope."""
    repo = repo_root_for(target)
    if repo is None:
        raise GitError(
            f"{target} is not inside a git repository — --diff needs git history "
            "to compute the changed file set."
        )

    scope_args = _diff_scope_args(ref, staged_only)

    name_result = _run_git(["diff", "--name-status", *scope_args], cwd=repo)
    if name_result.returncode != 0:
        raise GitError(
            f"`git diff --name-status {' '.join(scope_args)}` failed: "
            f"{name_result.stderr.strip() or name_result.stdout.strip()}"
        )
    files = _parse_name_status(name_result.stdout)

    # If we're in the default scope, the user spec also asked us to union staged
    # changes explicitly via `--cached`; `git diff HEAD` already covers them but
    # we union to remain faithful to the spec and survive odd index states.
    if not ref and not staged_only:
        cached_result = _run_git(["diff", "--name-status", "--cached"], cwd=repo)
        if cached_result.returncode == 0:
            for entry in _parse_name_status(cached_result.stdout):
                if entry not in files:
                    files.append(entry)

    hunk_result = _run_git(["diff", "-U0", *scope_args], cwd=repo)
    raw_ranges = parse_hunk_ranges(hunk_result.stdout) if hunk_result.returncode == 0 else {}
    if not ref and not staged_only:
        cached_hunks = _run_git(["diff", "-U0", "--cached"], cwd=repo)
        if cached_hunks.returncode == 0:
            for path, hunks in parse_hunk_ranges(cached_hunks.stdout).items():
                raw_ranges.setdefault(path, []).extend(hunks)

    ranges_by_file: dict[Path, list[tuple[int, int]]] = {}
    for rel_path, hunks in raw_ranges.items():
        resolved = (repo / rel_path).resolve()
        merged = _merge_ranges(hunks)
        ranges_by_file[resolved] = merged

    resolved_files = [(repo / p).resolve() for p in files]
    # Deduplicate while preserving order.
    seen: set[Path] = set()
    unique_files: list[Path] = []
    for path in resolved_files:
        if path in seen:
            continue
        seen.add(path)
        unique_files.append(path)

    return DiffInfo(
        repo_root=repo,
        changed_files=unique_files,
        ranges_by_file=ranges_by_file,
    )


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping/touching (start, end) ranges."""
    if not ranges:
        return []
    sorted_ranges = sorted(ranges)
    merged: list[tuple[int, int]] = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged
