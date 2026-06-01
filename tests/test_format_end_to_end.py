"""End-to-end test for --format {terminal, json, sarif}.

Runs vulnscan against testcode/ in each format (analyzer mocked), then:
  * For terminal: confirms the rich human report renders.
  * For json: parses with json.loads, checks the documented schema, and ALSO
    pipes the captured stdout through `python -m json.tool` to prove it's
    valid JSON the standard way.
  * For sarif: parses with json.loads, asserts top-level `version`/`runs`
    and at least one `result`.
  * In json/sarif modes: confirms stdout contains ONLY the document.

Run with: python -m tests.test_format_end_to_end
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTCODE_DIR = REPO_ROOT / "testcode"


RESPONSE_BY_FILENAME = {
    "app.py": {
        "findings": [
            {
                "title": "SQL injection via string formatting",
                "severity": "CRITICAL",
                "lines": "18-20",
                "explanation": "Username interpolated into SQL via %-formatting.",
                "remediation": "Use parameterized queries.",
                "source": "independent",
            },
            {
                "title": "OS command injection via os.system",
                "severity": "HIGH",
                "lines": "26-28",
                "explanation": "Host concatenated into a shell command.",
                "remediation": "Use subprocess.run with shell=False.",
                "source": "independent",
            },
        ],
        "dismissed_leads": [],
        "summary": "SQLi + command injection.",
    },
    "dangerous_eval.py": {
        "findings": [
            {
                "title": "Arbitrary code execution via eval",
                "severity": "CRITICAL",
                "lines": "8-9",
                "explanation": "eval on caller-supplied input runs any Python.",
                "remediation": "Use ast.literal_eval.",
                "source": "independent",
            }
        ],
        "dismissed_leads": [],
        "summary": "eval on user input.",
    },
    "insecure_yaml.py": {
        "findings": [
            {
                "title": "Unsafe yaml.load enables arbitrary object construction",
                "severity": "HIGH",
                "lines": "10-15",
                "explanation": "yaml.load with the default loader instantiates Python objects.",
                "remediation": "Use yaml.safe_load.",
                "source": "independent",
            }
        ],
        "dismissed_leads": [],
        "summary": "Unsafe deserialization.",
    },
    "shell_subprocess.py": {
        "findings": [
            {
                "title": "Command injection via subprocess shell=True",
                "severity": "HIGH",
                "lines": "9-11",
                "explanation": "shell=True with concatenated input lets metacharacters change the command.",
                "remediation": "Pass list argv with shell=False.",
                "source": "independent",
            }
        ],
        "dismissed_leads": [],
        "summary": "subprocess shell=True.",
    },
    "safe_utils.py": {"findings": [], "dismissed_leads": [], "summary": "No issues found."},
}


def _fake_init(self, model=analyzer_mod.DEFAULT_MODEL, client=None):
    self.model = model
    self._client = None
    self.request_count = 0


def _fake_analyze(self, source: SourceFile, leads=None, changed_ranges=None):
    self.request_count += 1
    payload = RESPONSE_BY_FILENAME.get(source.path.name)
    if payload is None:
        return FileReport(source=source, summary="No mock.", had_leads=bool(leads))
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


def _run_cli(args: list[str]) -> tuple[str, str, int]:
    """Invoke main with separated stdout/stderr capture. Returns (stdout, stderr, exit)."""
    runner = CliRunner()
    patches = [
        patch.object(Analyzer, "__init__", _fake_init),
        patch.object(Analyzer, "analyze", _fake_analyze),
        patch.object(cli_mod, "semgrep_available", lambda: False),
    ]
    for p in patches:
        p.start()
    try:
        result = runner.invoke(main, args, color=False)
    finally:
        for p in patches:
            p.stop()
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        import traceback
        traceback.print_exception(
            type(result.exception), result.exception, result.exception.__traceback__
        )
    return result.stdout, result.stderr, result.exit_code


def run_format_scenarios() -> int:
    failures: list[str] = []

    # --- Terminal ---
    print("\n=== Format: terminal ===\n")
    stdout_t, stderr_t, exit_t = _run_cli([str(TESTCODE_DIR), "--no-prefilter"])
    sys.stdout.write(stdout_t)
    sys.stdout.write(f"\n--- exit: {exit_t} | stdout bytes: {len(stdout_t)} | stderr bytes: {len(stderr_t)} ---\n")
    if exit_t != 1:
        failures.append(f"terminal: expected exit 1, got {exit_t}")
    if "Scan summary" not in stdout_t:
        failures.append("terminal: missing summary table on stdout")
    if "SQL injection via string formatting" not in stdout_t:
        failures.append("terminal: missing finding on stdout")

    # --- JSON ---
    print("\n=== Format: json ===\n")
    stdout_j, stderr_j, exit_j = _run_cli([str(TESTCODE_DIR), "--no-prefilter", "--format", "json"])
    print(f"[stderr captured, {len(stderr_j)} bytes]")
    if stderr_j.strip():
        # Show a couple of lines of stderr to prove it carries the human noise.
        for line in stderr_j.splitlines()[:6]:
            print(f"  err> {line}")
    print(f"[stdout captured, {len(stdout_j)} bytes — should be valid JSON only]")
    print(stdout_j[:800] + ("..." if len(stdout_j) > 800 else ""))

    if exit_j != 1:
        failures.append(f"json: expected exit 1, got {exit_j}")

    # Parse with json.loads as the in-test assertion.
    try:
        document = json.loads(stdout_j)
    except json.JSONDecodeError as exc:
        failures.append(f"json: stdout was not valid JSON: {exc}")
        document = None

    if document is not None:
        for required in ("tool", "version", "scanned_at", "target", "summary", "findings"):
            if required not in document:
                failures.append(f"json: missing top-level key `{required}`")
        if document.get("tool") != "vulnscan":
            failures.append(f"json: tool should be 'vulnscan', got {document.get('tool')!r}")
        summary = document.get("summary") or {}
        for required in ("critical", "high", "medium", "low", "files_scanned"):
            if required not in summary:
                failures.append(f"json: summary missing key `{required}`")
        findings = document.get("findings") or []
        if not any(f.get("title") == "SQL injection via string formatting" for f in findings):
            failures.append("json: missing the SQLi finding in findings[]")
        if findings:
            first = findings[0]
            for required in ("file", "language", "title", "severity", "lines", "explanation", "remediation"):
                if required not in first:
                    failures.append(f"json: finding missing key `{required}`")

    # Also pipe stdout through `python -m json.tool`, as the user requested,
    # to independently prove validity.
    proc = subprocess.run(
        [sys.executable, "-m", "json.tool"],
        input=stdout_j,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        failures.append(f"json: `python -m json.tool` rejected the output: {proc.stderr.strip()}")
    else:
        print(f"[`python -m json.tool` accepted the document, {len(proc.stdout)} bytes pretty-printed]")

    # --- SARIF ---
    print("\n=== Format: sarif ===\n")
    stdout_s, stderr_s, exit_s = _run_cli([str(TESTCODE_DIR), "--no-prefilter", "--format", "sarif"])
    print(f"[stderr captured, {len(stderr_s)} bytes]")
    print(f"[stdout captured, {len(stdout_s)} bytes — should be valid SARIF only]")
    print(stdout_s[:800] + ("..." if len(stdout_s) > 800 else ""))

    if exit_s != 1:
        failures.append(f"sarif: expected exit 1, got {exit_s}")
    try:
        sarif = json.loads(stdout_s)
    except json.JSONDecodeError as exc:
        failures.append(f"sarif: stdout was not valid JSON: {exc}")
        sarif = None

    if sarif is not None:
        if sarif.get("version") != "2.1.0":
            failures.append(f"sarif: expected version 2.1.0, got {sarif.get('version')!r}")
        runs = sarif.get("runs")
        if not isinstance(runs, list) or not runs:
            failures.append("sarif: missing or empty `runs` array")
        else:
            run0 = runs[0]
            driver = ((run0.get("tool") or {}).get("driver") or {})
            if driver.get("name") != "vulnscan":
                failures.append(f"sarif: tool.driver.name should be 'vulnscan', got {driver.get('name')!r}")
            results = run0.get("results") or []
            if len(results) < 1:
                failures.append("sarif: expected at least one result, got 0")
            else:
                first = results[0]
                if first.get("level") not in ("error", "warning", "note"):
                    failures.append(f"sarif: result.level was {first.get('level')!r}")
                if not first.get("ruleId"):
                    failures.append("sarif: result missing ruleId")
                if not (first.get("message") or {}).get("text"):
                    failures.append("sarif: result.message.text missing")
                locs = first.get("locations") or []
                if not locs:
                    failures.append("sarif: result has no locations")

    # --- stdout discipline checks ---
    forbidden_in_stdout = ("Scan summary", "Discovered", "[dim]", "──", "vulnscan  v")
    for kind, stdout in (("json", stdout_j), ("sarif", stdout_s)):
        for needle in forbidden_in_stdout:
            if needle in stdout:
                failures.append(
                    f"{kind}: forbidden human-facing fragment `{needle}` leaked to stdout"
                )

    # --- Report ---
    print("\n=== Summary ===")
    print(f"terminal: exit={exit_t}, stdout bytes={len(stdout_t)}, stderr bytes={len(stderr_t)}")
    print(f"json:     exit={exit_j}, stdout bytes={len(stdout_j)}, stderr bytes={len(stderr_j)}")
    print(f"sarif:    exit={exit_s}, stdout bytes={len(stdout_s)}, stderr bytes={len(stderr_s)}")

    if failures:
        print("\nFAIL:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print("\nPASS — all three formats render correctly, json/sarif stdout is "
          "machine-clean, json.tool accepts the JSON, and SARIF has the "
          "required top-level keys plus at least one result.")
    return 0


if __name__ == "__main__":
    sys.exit(run_format_scenarios())
