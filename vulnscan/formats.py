"""Machine-readable output formats for vulnscan (JSON, SARIF 2.1.0)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import FileReport, Finding

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

SEVERITY_KEYS = ("critical", "high", "medium", "low")

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_FIRST_INT_RE = re.compile(r"\d+")
_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _now_iso() -> str:
    """UTC timestamp in ISO 8601 with `Z` suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _severity_counts(reports: list[FileReport]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_KEYS}
    for report in reports:
        for finding in report.findings:
            key = finding.severity.lower()
            if key in counts:
                counts[key] += 1
    return counts


def _normalize_rule_id(title: str) -> str:
    """Normalize a finding title to a stable SARIF ruleId.

    "SQL injection via string formatting" -> "sql-injection-via-string-formatting"
    """
    slug = _NORMALIZE_RE.sub("-", title.lower()).strip("-")
    return slug or "unspecified-finding"


def _first_line(spec: str) -> int:
    """First integer in a `lines` field; SARIF requires startLine >= 1."""
    match = _FIRST_INT_RE.search(spec or "")
    if not match:
        return 1
    return max(1, int(match.group(0)))


def to_json(
    reports: list[FileReport],
    target: Path,
    files_scanned: int,
    files_analyzed: int = 0,
    files_failed: int = 0,
    files_skipped: int = 0,
) -> str:
    """Render the stable vulnscan JSON document."""
    findings_out: list[dict] = []
    for report in reports:
        for finding in report.findings:
            findings_out.append(
                {
                    "file": str(report.source.path),
                    "language": report.source.language,
                    "title": finding.title,
                    "severity": finding.severity,
                    "lines": finding.lines,
                    "explanation": finding.explanation,
                    "remediation": finding.remediation,
                }
            )

    counts = _severity_counts(reports)
    document = {
        "tool": "vulnscan",
        "version": __version__,
        "scanned_at": _now_iso(),
        "target": str(target),
        "summary": {
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "files_scanned": files_scanned,
            "files_analyzed": files_analyzed,
            "files_failed": files_failed,
            "files_skipped": files_skipped,
            "inconclusive": files_failed > 0,
        },
        "findings": findings_out,
    }
    return json.dumps(document, indent=2)


def _sarif_rules(reports: list[FileReport]) -> tuple[list[dict], dict[str, str]]:
    """Build the rules table for SARIF, deduplicated by ruleId."""
    rules: list[dict] = []
    rule_index: dict[str, str] = {}
    for report in reports:
        for finding in report.findings:
            rule_id = _normalize_rule_id(finding.title)
            if rule_id in rule_index:
                continue
            rule_index[rule_id] = finding.title
            rules.append(
                {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {
                        "text": finding.explanation or finding.title,
                    },
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                    },
                    "properties": {"severity": finding.severity},
                }
            )
    return rules, rule_index


def _sarif_results(reports: list[FileReport]) -> list[dict]:
    results: list[dict] = []
    for report in reports:
        uri = Path(str(report.source.path)).as_posix()
        for finding in report.findings:
            rule_id = _normalize_rule_id(finding.title)
            message_text = finding.explanation or finding.title
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": _first_line(finding.lines)},
                            }
                        }
                    ],
                    "properties": {
                        "severity": finding.severity,
                        "source": finding.source,
                        "pre_existing": finding.pre_existing,
                        "lines": finding.lines,
                        "remediation": finding.remediation,
                        "language": report.source.language,
                    },
                }
            )
    return results


def to_sarif(
    reports: list[FileReport],
    files_scanned: int = 0,
    files_analyzed: int = 0,
    files_failed: int = 0,
) -> str:
    """Render a SARIF 2.1.0 document for the given reports."""
    rules, _ = _sarif_rules(reports)
    results = _sarif_results(reports)
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscan",
                        "version": __version__,
                        "informationUri": "https://github.com/anthropics/vulnscan",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": files_failed == 0,
                    }
                ],
                "results": results,
                "properties": {
                    "files_scanned": files_scanned,
                    "files_analyzed": files_analyzed,
                    "files_failed": files_failed,
                    "inconclusive": files_failed > 0,
                },
            }
        ],
    }
    _validate_sarif(document)
    return json.dumps(document, indent=2)


_MARKDOWN_TOP_PER_SEVERITY = 5
_MARKDOWN_INTRO_SEVERITIES = ("CRITICAL", "HIGH")


def _markdown_file_label(report: FileReport) -> str:
    """Render a path that reads well in a PR comment, preferring the repo-relative form."""
    raw = Path(str(report.source.path))
    try:
        relative = raw.resolve().relative_to(Path.cwd().resolve())
        return relative.as_posix()
    except ValueError:
        return raw.as_posix()


def to_markdown(
    reports: list[FileReport],
    target: Path,
    files_scanned: int,
    files_analyzed: int = 0,
    files_failed: int = 0,
) -> str:
    """Render a compact markdown summary suitable for a sticky PR comment."""
    counts = _severity_counts(reports)
    total_findings = sum(counts.values())
    files_with_findings = sum(1 for r in reports if r.findings)

    lines: list[str] = []
    if total_findings == 0:
        if files_failed > 0:
            analyzed_of = files_analyzed + files_failed
            lines.append("## vulnscan — incomplete results")
            lines.append("")
            lines.append(
                f"Analysis failed for {files_failed} of {analyzed_of} file(s). "
                "Results are inconclusive — re-run after resolving scan errors."
            )
        else:
            lines.append("## vulnscan — no findings in changed code")
            lines.append("")
            lines.append(
                f"Scanned {files_scanned} file(s) in `{target}`; nothing flagged "
                "above the noise floor."
            )
        lines.append("")
        lines.append(f"_Generated by vulnscan v{__version__} at {_now_iso()}._")
        return "\n".join(lines)

    lines.append(
        f"## vulnscan — {total_findings} finding(s) in {files_with_findings} file(s)"
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {severity} | {counts[severity.lower()]} |")
    lines.append("")

    # Group findings by severity, dropping pre-existing ones so the comment
    # focuses on what the PR actually introduced.
    grouped: dict[str, list[tuple[FileReport, Finding]]] = {}
    for report in reports:
        for finding in report.findings:
            if finding.pre_existing:
                continue
            grouped.setdefault(finding.severity, []).append((report, finding))

    rendered_any_group = False
    for severity in _MARKDOWN_INTRO_SEVERITIES:
        bucket = grouped.get(severity) or []
        if not bucket:
            continue
        rendered_any_group = True
        lines.append(f"### Top {severity.lower()} findings")
        lines.append("")
        for report, finding in bucket[:_MARKDOWN_TOP_PER_SEVERITY]:
            file_label = _markdown_file_label(report)
            start = _first_line(finding.lines)
            lines.append(f"- `{file_label}:{start}` — {finding.title}")
        if len(bucket) > _MARKDOWN_TOP_PER_SEVERITY:
            remaining = len(bucket) - _MARKDOWN_TOP_PER_SEVERITY
            lines.append(f"- _…and {remaining} more {severity.lower()} finding(s) in the full report._")
        lines.append("")

    pre_existing_count = sum(
        1 for r in reports for f in r.findings if f.pre_existing
    )
    if pre_existing_count:
        lines.append(
            f"> {pre_existing_count} pre-existing finding(s) outside the diff are "
            "in the full SARIF report but not blocking this PR."
        )
        lines.append("")
    if files_failed > 0:
        analyzed_of = files_analyzed + files_failed
        lines.append(
            f"> **Warning:** {files_failed} of {analyzed_of} file(s) failed to "
            "analyze — results may be incomplete."
        )
        lines.append("")

    if not rendered_any_group:
        # Only MEDIUM/LOW present — list a couple of mediums so reviewers see them.
        mediums = grouped.get("MEDIUM") or []
        if mediums:
            lines.append("### Medium findings")
            lines.append("")
            for report, finding in mediums[:_MARKDOWN_TOP_PER_SEVERITY]:
                file_label = _markdown_file_label(report)
                start = _first_line(finding.lines)
                lines.append(f"- `{file_label}:{start}` — {finding.title}")
            lines.append("")

    lines.append(
        f"_Generated by vulnscan v{__version__} at {_now_iso()}. Scanned "
        f"{files_scanned} file(s)._"
    )
    return "\n".join(lines)


def _validate_sarif(document: dict) -> None:
    """Cheap structural check — fail loudly if the SARIF shape regresses."""
    if document.get("version") != SARIF_VERSION:
        raise ValueError(f"SARIF version must be {SARIF_VERSION}")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF document must contain a non-empty `runs` array.")
    for run in runs:
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        if not driver.get("name"):
            raise ValueError("SARIF run.tool.driver.name is required.")
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError("SARIF run.results must be an array (possibly empty).")
        for result in results:
            if not result.get("ruleId"):
                raise ValueError("Every SARIF result needs a ruleId.")
            if result.get("level") not in {"none", "note", "warning", "error"}:
                raise ValueError(
                    f"Invalid SARIF result.level: {result.get('level')!r}"
                )
            message = result.get("message") or {}
            if not isinstance(message.get("text"), str):
                raise ValueError("Every SARIF result.message must have a `text` string.")
            locations = result.get("locations") or []
            if not locations:
                raise ValueError("Every SARIF result needs at least one location.")
            for loc in locations:
                physical = loc.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                if not artifact.get("uri"):
                    raise ValueError("Every SARIF location needs an artifactLocation.uri.")
                region = physical.get("region") or {}
                start = region.get("startLine")
                if not isinstance(start, int) or start < 1:
                    raise ValueError("SARIF region.startLine must be a positive int.")
