"""End-to-end test for --diff mode driving a real temp git repo.

Scenario:
  1. Create a scratch repo, commit a clean file.
  2. Stage a change that introduces a SQL injection.
  3. Run `vulnscan --diff` and confirm:
       - Only the changed file is scanned.
       - The new critical finding is reported.
       - Exit code is non-zero.
  4. Reset, stage nothing scannable, run `vulnscan --diff --staged` and confirm
     the command exits 0 immediately.

The analyzer is mocked so no live API call happens; the git operations are real.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from vulnscan import analyzer as analyzer_mod
from vulnscan import cli as cli_mod
from vulnscan.analyzer import Analyzer, FileReport
from vulnscan.cli import main
from vulnscan.scanner import SourceFile

CLEAN_PY = '''"""Pure helper, no security issues."""


def add(a: int, b: int) -> int:
    return a + b


def greet(name: str) -> str:
    return f"hello {name}"
'''

VULNERABLE_PY = '''"""Pure helper, no security issues."""

import sqlite3


def add(a: int, b: int) -> int:
    return a + b


def lookup_user(name: str) -> list:
    """Newly added — vulnerable to SQL injection."""
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cur.execute(query)
    return cur.fetchall()


def greet(name: str) -> str:
    return f"hello {name}"
'''

UNRELATED_TXT = "this is a doc; vulnscan should ignore .txt files\n"


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {
        "GIT_AUTHOR_NAME": "vulnscan-test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "vulnscan-test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": __import__("os").environ.get("PATH", ""),
    }
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _fake_init(self, model=analyzer_mod.DEFAULT_MODEL, client=None):
    self.model = model
    self._client = None
    self.request_count = 0


def _fake_analyze(self, source: SourceFile, leads=None, changed_ranges=None):
    """Pretend to be Claude: claim a CRITICAL SQLi on the lookup_user query."""
    self.request_count += 1
    text = source.content
    findings_payload: list[dict] = []
    if "SELECT * FROM users WHERE name = '%s'" in text:
        # Find the line of the vulnerable query so the finding's line numbers
        # actually fall inside the diff hunk for the changed_ranges check.
        line_no = None
        for i, line in enumerate(text.splitlines(), start=1):
            if "SELECT * FROM users WHERE name = '%s'" in line:
                line_no = i
                break
        if line_no is None:
            line_no = 14
        findings_payload.append(
            {
                "title": "SQL injection via string formatting",
                "severity": "CRITICAL",
                "lines": str(line_no),
                "explanation": (
                    "User-controlled `name` is interpolated into the SQL string via "
                    "%-formatting, letting a caller change the query's structure."
                ),
                "remediation": (
                    "Use a parameterized query: cur.execute(\"SELECT * FROM users "
                    "WHERE name = ?\", (name,))."
                ),
                "source": "independent",
            }
        )
    payload = {"findings": findings_payload, "dismissed_leads": [], "summary": "mock"}
    findings, dismissed, summary, error = analyzer_mod._parse_response(
        json.dumps(payload),
        default_source="semgrep" if leads else "independent",
    )
    findings = analyzer_mod.tag_pre_existing(findings, changed_ranges)
    return FileReport(
        source=source,
        findings=findings,
        dismissed_leads=dismissed,
        summary=summary,
        error=error,
        had_leads=bool(leads),
    )


_API_CALLS_RE = re.compile(r"Anthropic API calls made:\s*(\d+)")


def _api_calls(output: str) -> int:
    m = _API_CALLS_RE.search(output)
    return int(m.group(1)) if m else -1


def _run_cli(args: list[str], cwd: Path) -> tuple[str, int]:
    runner = CliRunner()
    patches = [
        patch.object(Analyzer, "__init__", _fake_init),
        patch.object(Analyzer, "analyze", _fake_analyze),
        # Force the prefilter off — keeps the diff-mode test isolated from the
        # Semgrep code path and matches what a real pre-commit hook would set
        # (we don't want a Semgrep scan on every commit).
        patch.object(cli_mod, "semgrep_available", lambda: False),
    ]
    # Click's `path_type=Path` resolves PATH relative to the *current* cwd;
    # we want the temp repo to act as cwd for both git and PATH resolution.
    import os

    original_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        for p in patches:
            p.start()
        try:
            result = runner.invoke(main, args, color=False)
        finally:
            for p in patches:
                p.stop()
    finally:
        os.chdir(original_cwd)
    return result.output, result.exit_code


def setup_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    init = _git(["init", "-q", "-b", "main"], cwd=repo)
    if init.returncode != 0:
        # Older git versions don't support -b, fall back.
        _git(["init", "-q"], cwd=repo)
    _git(["config", "user.email", "test@example.com"], cwd=repo)
    _git(["config", "user.name", "vulnscan-test"], cwd=repo)
    (repo / "helpers.py").write_text(CLEAN_PY, encoding="utf-8")
    (repo / "notes.txt").write_text(UNRELATED_TXT, encoding="utf-8")
    _git(["add", "helpers.py", "notes.txt"], cwd=repo)
    commit = _git(["commit", "-q", "-m", "initial clean commit"], cwd=repo)
    if commit.returncode != 0:
        raise RuntimeError(f"git commit failed: {commit.stderr}")


def run_diff_scenarios() -> int:
    failures: list[str] = []
    workdir = Path(tempfile.mkdtemp(prefix="vulnscan-diff-"))
    try:
        repo = workdir / "repo"
        setup_repo(repo)

        # --- Scenario A: stage a SQLi-introducing change to helpers.py ---
        print("\n=== Scenario A: stage SQLi change, run `vulnscan --diff --staged` ===\n")
        (repo / "helpers.py").write_text(VULNERABLE_PY, encoding="utf-8")
        # Also touch a non-scannable file so we can verify it's filtered out.
        (repo / "notes.txt").write_text(UNRELATED_TXT + "more notes\n", encoding="utf-8")
        add_res = _git(["add", "helpers.py", "notes.txt"], cwd=repo)
        if add_res.returncode != 0:
            raise RuntimeError(f"git add failed: {add_res.stderr}")

        out_a, exit_a = _run_cli(["--diff", "--staged", "--no-prefilter"], cwd=repo)
        sys.stdout.write(out_a)
        calls_a = _api_calls(out_a)
        sys.stdout.write(f"\n--- exit: {exit_a} | API calls: {calls_a} ---\n")

        if exit_a != 1:
            failures.append(f"Scenario A: expected exit 1 (CRITICAL/HIGH), got {exit_a}")
        if "SQL injection via string formatting" not in out_a:
            failures.append("Scenario A: missing the new critical finding")
        if calls_a != 1:
            failures.append(
                f"Scenario A: expected exactly 1 API call (only helpers.py is scannable), "
                f"got {calls_a}"
            )
        if "Diff mode" not in out_a:
            failures.append("Scenario A: summary missing diff-mode note")
        if "notes.txt" in out_a and "│ " in out_a:
            # notes.txt is non-scannable — it must not appear in any panel header.
            for line in out_a.splitlines():
                if "notes.txt" in line and "│" in line:
                    failures.append("Scenario A: non-scannable notes.txt leaked into output")
                    break

        # --- Scenario B: unstage everything, stage only a .txt change ---
        print("\n=== Scenario B: no scannable files staged → fast no-op ===\n")
        # Reset both files to clean state and unstage.
        (repo / "helpers.py").write_text(CLEAN_PY, encoding="utf-8")
        (repo / "notes.txt").write_text(UNRELATED_TXT, encoding="utf-8")
        _git(["reset", "-q", "HEAD", "--", "."], cwd=repo)
        _git(["checkout", "-q", "--", "."], cwd=repo)
        # Stage only the non-scannable file change.
        (repo / "notes.txt").write_text(UNRELATED_TXT + "doc tweak\n", encoding="utf-8")
        _git(["add", "notes.txt"], cwd=repo)

        out_b, exit_b = _run_cli(["--diff", "--staged", "--no-prefilter"], cwd=repo)
        sys.stdout.write(out_b)
        calls_b = _api_calls(out_b)
        sys.stdout.write(f"\n--- exit: {exit_b} | API calls: {calls_b} ---\n")

        if exit_b != 0:
            failures.append(f"Scenario B: expected exit 0 with no scannable changes, got {exit_b}")
        if "No scannable changes" not in out_b:
            failures.append("Scenario B: missing the 'No scannable changes' fast-path message")
        if calls_b not in (-1, 0):
            failures.append(
                f"Scenario B: expected 0 API calls on the fast path, got {calls_b}"
            )

        # --- Scenario C: --install-hook writes a working pre-commit script ---
        print("\n=== Scenario C: --install-hook writes .git/hooks/pre-commit ===\n")
        out_c, exit_c = _run_cli(["--install-hook"], cwd=repo)
        sys.stdout.write(out_c)
        sys.stdout.write(f"\n--- exit: {exit_c} ---\n")
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        if exit_c != 0:
            failures.append(f"Scenario C: --install-hook exit code was {exit_c}, expected 0")
        if not hook_path.exists():
            failures.append("Scenario C: pre-commit hook file was not created")
        else:
            hook_text = hook_path.read_text(encoding="utf-8")
            for needle in ("vulnscan", "--diff", "--staged", "VULNSCAN_BLOCK_SEVERITY"):
                if needle not in hook_text:
                    failures.append(f"Scenario C: hook script missing `{needle}`")

        # --- Report ---
        print("\n=== Summary ===")
        print(f"Scenario A: exit={exit_a}, API calls={calls_a} "
              f"(expected exit 1, 1 call, critical SQLi reported)")
        print(f"Scenario B: exit={exit_b}, API calls={calls_b} "
              f"(expected exit 0 immediately, 0 calls)")
        print(f"Scenario C: install-hook exit={exit_c}, "
              f"hook exists={hook_path.exists()}")

        if failures:
            print("\nFAIL:")
            for line in failures:
                print(f"  - {line}")
            return 1
        print("\nPASS — diff mode scans only the changed file, fast-paths a no-op "
              "commit, and installs a working pre-commit hook.")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_diff_scenarios())
