"""One-shot helper: render `vulnscan --format markdown ./testcode/` with a
mocked analyzer so we can preview what the CI sticky comment will look like
without making a real API call.
"""

from __future__ import annotations

import json
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

RESPONSES = {
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
        "summary": "SQLi + command injection + secrets.",
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


def fake_init(self, model=analyzer_mod.DEFAULT_MODEL, client=None):
    self.model = model
    self._client = None
    self.request_count = 0


def fake_analyze(self, source: SourceFile, leads=None, changed_ranges=None):
    self.request_count += 1
    payload = RESPONSES.get(source.path.name, {"findings": [], "dismissed_leads": [], "summary": ""})
    findings, dismissed, summary, error = analyzer_mod._parse_response(
        json.dumps(payload),
        default_source="independent",
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


def main_demo() -> int:
    runner = CliRunner()
    patches = [
        patch.object(Analyzer, "__init__", fake_init),
        patch.object(Analyzer, "analyze", fake_analyze),
        patch.object(cli_mod, "semgrep_available", lambda: False),
    ]
    for p in patches:
        p.start()
    try:
        result = runner.invoke(
            main,
            [str(TESTCODE_DIR), "--no-prefilter", "--format", "markdown"],
            color=False,
        )
    finally:
        for p in patches:
            p.stop()

    print("=== stdout (the markdown that would be posted to the PR) ===")
    print(result.stdout, end="")
    print("=== /stdout ===")
    print(f"\nexit code: {result.exit_code}")
    print(f"stderr ({len(result.stderr)} bytes — kept off stdout):")
    print(result.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main_demo())
