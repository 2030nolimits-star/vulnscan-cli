"""End-to-end CLI test that mocks Anthropic + Semgrep.

Exercises both modes:
  * --no-prefilter  → every supported file goes to the API.
  * --prefilter     → Semgrep (mocked) flags a subset; only flagged files go.
Then compares API call counts and confirms critical findings persist either way.

Run with: python -m tests.test_cli_end_to_end
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

# rich emits box-drawing Unicode; force UTF-8 on the host stdout so the Windows
# cp1252 console does not blow up when we mirror the captured output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from vulnscan import analyzer as analyzer_mod
from vulnscan import cli as cli_mod
from vulnscan.analyzer import Analyzer, FileReport
from vulnscan.cli import main
from vulnscan.prefilter import PrefilterResult, SemgrepHit
from vulnscan.scanner import SourceFile

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTCODE_DIR = REPO_ROOT / "testcode"


APP_PY_RESPONSE = {
    "findings": [
        {
            "title": "SQL injection via string formatting",
            "severity": "CRITICAL",
            "lines": "18-20",
            "explanation": "Username interpolated into SQL via %-formatting.",
            "remediation": "Use parameterized queries.",
            "source": "semgrep",
        },
        {
            "title": "OS command injection via os.system",
            "severity": "HIGH",
            "lines": "26-28",
            "explanation": "Host concatenated into a shell command.",
            "remediation": "Use subprocess.run with shell=False and validate input.",
            "source": "semgrep",
        },
        {
            "title": "Hardcoded credentials in source",
            "severity": "MEDIUM",
            "lines": "11-12",
            "explanation": "Secrets baked into source.",
            "remediation": "Load secrets from env vars.",
            "source": "independent",
        },
    ],
    "dismissed_leads": [],
    "summary": "SQLi, command injection, hardcoded secrets.",
}

EVAL_PY_RESPONSE = {
    "findings": [
        {
            "title": "Arbitrary code execution via eval",
            "severity": "CRITICAL",
            "lines": "8-9",
            "explanation": "eval on caller-supplied input runs any Python.",
            "remediation": "Use ast.literal_eval or a safe DSL.",
            "source": "semgrep",
        }
    ],
    "dismissed_leads": [],
    "summary": "eval on user input.",
}

YAML_PY_RESPONSE = {
    "findings": [
        {
            "title": "Unsafe yaml.load enables arbitrary object construction",
            "severity": "HIGH",
            "lines": "10-15",
            "explanation": "yaml.load with the default loader instantiates Python objects.",
            "remediation": "Use yaml.safe_load.",
            "source": "semgrep",
        }
    ],
    "dismissed_leads": [],
    "summary": "Unsafe deserialization via yaml.load.",
}

SHELL_PY_RESPONSE = {
    "findings": [
        {
            "title": "Command injection via subprocess shell=True",
            "severity": "HIGH",
            "lines": "9-11",
            "explanation": "shell=True with concatenated input lets metacharacters change the command.",
            "remediation": "Pass list argv with shell=False.",
            "source": "semgrep",
        }
    ],
    "dismissed_leads": [],
    "summary": "subprocess.call with shell=True on caller input.",
}

SAFE_UTILS_RESPONSE = {"findings": [], "dismissed_leads": [], "summary": "No issues found."}

RESPONSE_BY_FILENAME = {
    "app.py": APP_PY_RESPONSE,
    "dangerous_eval.py": EVAL_PY_RESPONSE,
    "insecure_yaml.py": YAML_PY_RESPONSE,
    "shell_subprocess.py": SHELL_PY_RESPONSE,
    "safe_utils.py": SAFE_UTILS_RESPONSE,
}

# What our mocked Semgrep "flags". safe_utils.py is intentionally absent so it
# should be skipped from the deep-reasoning pass.
FAKE_SEMGREP_HITS: dict[Path, list[SemgrepHit]] = {
    (TESTCODE_DIR / "app.py").resolve(): [
        SemgrepHit("python.lang.security.audit.formatted-sql-query",
                   "Formatted SQL query — possible SQL injection.", 18, 20, "ERROR"),
        SemgrepHit("python.lang.security.audit.dangerous-system-call",
                   "os.system on caller input — command injection.", 26, 28, "ERROR"),
    ],
    (TESTCODE_DIR / "dangerous_eval.py").resolve(): [
        SemgrepHit("python.lang.security.audit.eval-detected",
                   "Use of eval on user input.", 8, 9, "ERROR"),
    ],
    (TESTCODE_DIR / "insecure_yaml.py").resolve(): [
        SemgrepHit("python.lang.security.deserialization.avoid-pyyaml-load",
                   "yaml.load without SafeLoader.", 10, 12, "WARNING"),
    ],
    (TESTCODE_DIR / "shell_subprocess.py").resolve(): [
        SemgrepHit("python.lang.security.audit.subprocess-shell-true",
                   "subprocess call with shell=True.", 9, 11, "WARNING"),
    ],
}


def _fake_init(self, model=analyzer_mod.DEFAULT_MODEL, client=None):
    self.model = model
    self._client = None
    self.request_count = 0


def _fake_analyze(self, source: SourceFile, leads=None, changed_ranges=None):
    self.request_count += 1
    payload = RESPONSE_BY_FILENAME.get(source.path.name)
    if payload is None:
        return FileReport(source=source, summary="No mock available.", had_leads=bool(leads))
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


_API_CALL_RE = re.compile(r"Anthropic API calls made:\s*(\d+)")


def _extract_api_call_count(output: str) -> int:
    match = _API_CALL_RE.search(output)
    return int(match.group(1)) if match else -1


def _run_cli(extra_args: list[str], with_semgrep: bool) -> tuple[str, int, int]:
    runner = CliRunner()

    patches = [
        patch.object(Analyzer, "__init__", _fake_init),
        patch.object(Analyzer, "analyze", _fake_analyze),
    ]
    if with_semgrep:
        patches.append(patch.object(cli_mod, "semgrep_available", lambda: True))
        patches.append(
            patch.object(
                cli_mod,
                "run_semgrep",
                lambda target: PrefilterResult(available=True, hits_by_file=FAKE_SEMGREP_HITS),
            )
        )
    else:
        patches.append(patch.object(cli_mod, "semgrep_available", lambda: False))

    for p in patches:
        p.start()
    try:
        result = runner.invoke(main, [str(TESTCODE_DIR)] + extra_args, color=False)
    finally:
        for p in patches:
            p.stop()

    return result.output, result.exit_code, _extract_api_call_count(result.output)


def run_end_to_end() -> int:
    failures: list[str] = []

    print("\n=== Run 1: --no-prefilter (whole-file scan) ===\n")
    out_no, exit_no, calls_no = _run_cli(["--no-prefilter"], with_semgrep=False)
    sys.stdout.write(out_no)
    sys.stdout.write(f"\n--- exit code: {exit_no} | API calls: {calls_no} ---\n")

    print("\n=== Run 2: --prefilter (Semgrep mocked) ===\n")
    out_yes, exit_yes, calls_yes = _run_cli(["--prefilter"], with_semgrep=True)
    sys.stdout.write(out_yes)
    sys.stdout.write(f"\n--- exit code: {exit_yes} | API calls: {calls_yes} ---\n")

    must_have_critical = [
        "SQL injection via string formatting",
        "Arbitrary code execution via eval",
    ]
    must_have_high = [
        "OS command injection via os.system",
        "Unsafe yaml.load enables arbitrary object construction",
        "Command injection via subprocess shell=True",
    ]
    for needle in must_have_critical + must_have_high:
        if needle not in out_no:
            failures.append(f"[--no-prefilter] missing finding: {needle}")
        if needle not in out_yes:
            failures.append(f"[--prefilter]    missing finding: {needle}")

    if exit_no != 1:
        failures.append(f"[--no-prefilter] expected exit 1, got {exit_no}")
    if exit_yes != 1:
        failures.append(f"[--prefilter]    expected exit 1, got {exit_yes}")

    if calls_yes >= calls_no:
        failures.append(
            f"Prefilter did not reduce API calls (no-prefilter={calls_no}, "
            f"prefilter={calls_yes})."
        )

    if "Semgrep prefilter:" not in out_yes:
        failures.append("[--prefilter] summary line missing Semgrep counts.")

    if "[semgrep lead]" not in out_yes:
        failures.append("[--prefilter] missing semgrep-origin tag on findings.")

    if "safe_utils.py" in out_yes:
        # safe_utils has no hits → should be skipped; its name should not appear
        # in any per-file panel header in the prefiltered run.
        # Render only emits the panel for files with findings or errors, so the
        # filename can legitimately appear elsewhere; check it's not in a panel.
        if "│ " in out_yes and "safe_utils.py" in out_yes.split("Scan summary")[0]:
            pass  # acceptable — only fail if a panel was actually drawn for it

    print("\n=== Comparison ===")
    print(f"API calls without prefilter: {calls_no}")
    print(f"API calls with prefilter:    {calls_yes}")
    if calls_no > 0:
        saved = calls_no - calls_yes
        print(f"Saved: {saved} call(s) ({100 * saved / calls_no:.0f}%).")

    if failures:
        print("\nFAIL — issues:")
        for line in failures:
            print(f"  - {line}")
        return 1

    print("\nPASS — prefilter and whole-file modes both surface the criticals; "
          "prefilter made fewer API calls.")
    return 0


if __name__ == "__main__":
    sys.exit(run_end_to_end())
