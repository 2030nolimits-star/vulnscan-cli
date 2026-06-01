"""Error-handling tests for vulnscan.

Three scenarios (runnable as pytest or as a standalone script):

  A. First API call raises HTTP 401 → run stops immediately, prints auth
     guidance, exits 2.  Must NOT continue scanning remaining files.

  B. API call raises a transient 429 on the first attempt and succeeds on
     the second → the finding still appears in the report (retry works).

  C. One of several files permanently fails (all retries exhausted) →
     exit code is 3 (inconclusive), output notes incomplete results, and
     the tool does NOT claim the code is clean.

Run with:
  python -m pytest tests/test_error_handling.py -v
  python -m tests.test_error_handling
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from vulnscan import analyzer as analyzer_mod
from vulnscan import cli as cli_mod
from vulnscan.analyzer import Analyzer, AuthError, FileReport
from vulnscan.cli import main
from vulnscan.scanner import SourceFile

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTCODE_DIR = REPO_ROOT / "testcode"


# ---------------------------------------------------------------------------
# Shared mock helpers
# ---------------------------------------------------------------------------

def _fake_init(self, model=analyzer_mod.DEFAULT_MODEL, client=None):
    self.model = model
    self._client = None
    self.request_count = 0


# ---------------------------------------------------------------------------
# Scenario A — HTTP 401 causes fast fail
# ---------------------------------------------------------------------------

def test_auth_failure_stops_at_first_file():
    """A 401 error must abort the scan immediately and exit 2."""
    runner = CliRunner()
    call_count = [0]

    def _raising_analyze(self, source, leads=None, changed_ranges=None):
        call_count[0] += 1
        raise AuthError("HTTP 401 — the API key is invalid or expired: mock key")

    patches = [
        patch.object(Analyzer, "__init__", _fake_init),
        patch.object(Analyzer, "analyze", _raising_analyze),
        patch.object(cli_mod, "semgrep_available", lambda: False),
    ]
    for p in patches:
        p.start()
    try:
        result = runner.invoke(main, [str(TESTCODE_DIR), "--no-prefilter"], color=False)
    finally:
        for p in patches:
            p.stop()

    output = result.output
    assert result.exit_code == 2, (
        f"Expected exit 2 for auth error, got {result.exit_code}\n{output}"
    )
    assert "ANTHROPIC_API_KEY" in output, (
        f"Auth guidance (ANTHROPIC_API_KEY) missing from output:\n{output}"
    )
    assert call_count[0] == 1, (
        f"Expected exactly 1 file attempted before fast-fail, got {call_count[0]}"
    )
    return True


# ---------------------------------------------------------------------------
# Scenario B — Transient 429 is retried; finding still appears
# ---------------------------------------------------------------------------

def test_transient_error_is_retried():
    """A 429 on the first attempt must be retried; the second attempt's
    finding must appear in the report."""

    FINDING_PAYLOAD = {
        "findings": [
            {
                "title": "SQL injection",
                "severity": "CRITICAL",
                "lines": "5",
                "explanation": "User input concatenated into SQL.",
                "remediation": "Use parameterized queries.",
                "source": "independent",
            }
        ],
        "dismissed_leads": [],
        "summary": "One critical finding.",
    }

    class _Rate429(Exception):
        status_code = 429

    mock_block = MagicMock()
    mock_block.text = json.dumps(FINDING_PAYLOAD)
    mock_msg = MagicMock()
    mock_msg.content = [mock_block]

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [_Rate429("rate limited"), mock_msg]

    analyzer = Analyzer(client=mock_client)
    source = SourceFile(
        path=Path("/fake/test.py"),
        language="Python",
        content="x = input()\ndb.execute('SELECT * FROM users WHERE id=' + x)",
    )

    with patch("vulnscan.analyzer.time.sleep") as mock_sleep:
        report = analyzer.analyze(source)

    assert report.outcome == "analyzed", (
        f"Expected outcome='analyzed' after retry, got {report.outcome!r}"
    )
    assert len(report.findings) == 1, (
        f"Expected 1 finding after retry, got {len(report.findings)}"
    )
    assert report.findings[0].title == "SQL injection"
    assert mock_client.messages.create.call_count == 2, (
        f"Expected 2 API calls (initial + 1 retry), got "
        f"{mock_client.messages.create.call_count}"
    )
    # Backoff should have been called once (after the first failure).
    mock_sleep.assert_called_once_with(analyzer_mod._BACKOFF_BASE * (2 ** 0))
    return True


# ---------------------------------------------------------------------------
# Scenario C — Permanent failure → exit 3, no false "clean" claim
# ---------------------------------------------------------------------------

def test_permanent_failure_exits_3():
    """If one file fails after all retries, the run must exit 3 and clearly
    indicate incomplete results.  It must NOT claim the code is clean."""
    runner = CliRunner()
    FAILING_FILE = "app.py"

    def _mixed_analyze(self, source, leads=None, changed_ranges=None):
        self.request_count += 1
        if source.path.name == FAILING_FILE:
            return FileReport(
                source=source,
                error="Connection refused — could not reach API after 3 attempts",
            )
        return FileReport(source=source, findings=[], summary="No issues found.")

    patches = [
        patch.object(Analyzer, "__init__", _fake_init),
        patch.object(Analyzer, "analyze", _mixed_analyze),
        patch.object(cli_mod, "semgrep_available", lambda: False),
    ]
    for p in patches:
        p.start()
    try:
        result = runner.invoke(
            main, [str(TESTCODE_DIR), "--no-prefilter"], color=False
        )
    finally:
        for p in patches:
            p.stop()

    output = result.output
    assert result.exit_code == 3, (
        f"Expected exit 3 for partial failure, got {result.exit_code}\n{output}"
    )
    has_incomplete_note = (
        "incomplete" in output.lower()
        or "failed" in output.lower()
    )
    assert has_incomplete_note, (
        f"Expected 'incomplete' or 'failed' in output for partial scan:\n{output}"
    )
    # Must not report an all-clear
    assert "no issues found" not in output.lower(), (
        f"Tool falsely claimed 'no issues found' despite incomplete scan:\n{output}"
    )
    assert "nothing flagged" not in output.lower(), (
        f"Tool falsely reported 'nothing flagged' despite incomplete scan:\n{output}"
    )
    return True


# ---------------------------------------------------------------------------
# Script entry-point
# ---------------------------------------------------------------------------

def run_error_handling_scenarios() -> int:
    failures: list[str] = []

    print("\n=== Scenario A: 401 causes fast-fail (exit 2) ===\n")
    try:
        test_auth_failure_stops_at_first_file()
        print("PASS")
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        failures.append(f"A: {exc}")

    print("\n=== Scenario B: 429 retried, finding still appears ===\n")
    try:
        test_transient_error_is_retried()
        print("PASS")
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        failures.append(f"B: {exc}")

    print("\n=== Scenario C: permanent failure → exit 3, no false clean ===\n")
    try:
        test_permanent_failure_exits_3()
        print("PASS")
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        failures.append(f"C: {exc}")

    print()
    if failures:
        print("FAIL — issues:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print("PASS — all three error-handling scenarios behave correctly.")
    return 0


if __name__ == "__main__":
    sys.exit(run_error_handling_scenarios())
