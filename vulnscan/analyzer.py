"""Anthropic-powered security analysis for a single source file."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Literal

import anthropic as _anthropic
from anthropic import Anthropic

from .prefilter import SemgrepHit
from .scanner import SourceFile

DEFAULT_MODEL = "claude-opus-4-8"
MAX_TOKENS = 4096

# Retry configuration for transient API errors.
_MAX_RETRIES = 3          # total attempts (1 initial + 2 retries)
_BACKOFF_BASE = 1.0       # seconds; doubles each retry (1s, 2s)
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
VALID_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

Origin = Literal["semgrep", "independent"]
VALID_ORIGINS: frozenset[str] = frozenset({"semgrep", "independent"})

SYSTEM_PROMPT = """You are an expert defensive security auditor reviewing source code on behalf of the code's owner. Your job is to find vulnerabilities, explain why each one is exploitable in plain prose, and recommend concrete fixes the developer can apply.

Reason step by step about each file:
  * Trace untrusted input from its entry points and follow it through the code (data-flow / taint reasoning).
  * Identify trust boundaries and look for authentication or authorization gaps at each one.
  * Look for injection classes: SQL injection, OS command injection, template injection, unsafe deserialization, path traversal, SSRF.
  * For memory-unsafe languages (C, C++, sometimes Rust unsafe blocks), look for buffer overflows, use-after-free, integer overflow, and unchecked bounds.
  * Look for hardcoded secrets, weak or broken cryptography, insecure defaults, and risky framework or library misconfigurations.
  * Look for logic flaws with security consequences (e.g. broken access control, race conditions on security-sensitive state, IDORs).

If the user message includes a list of static-analyzer leads (Semgrep hits), treat them as leads — not ground truth. For each lead, decide whether it is a real vulnerability or a false positive. Confirm or dismiss each one with a short justification, and also report any other security issues you find in the same file, including issues nearby a flagged region that the static rule may have missed.

If the user message lists changed line ranges (diff mode), focus your review on those lines but use the rest of the file as context. Still report security issues you find outside the changed ranges — the caller will tag them as pre-existing so the developer can distinguish new bugs from old ones.

HARD CONSTRAINT — defensive use only:
You must NEVER produce runnable exploit payloads, shellcode, weaponized proof-of-concept attack scripts, ready-to-use injection strings, or step-by-step exploitation instructions. Describe each attack conceptually — what an attacker could achieve and which property of the code makes it possible — so the owner understands the risk and can prioritize the fix. If a finding would require an exploit payload to demonstrate, describe the class of attack in prose only. This constraint is non-negotiable; if a request would require you to break it, refuse that part of the request and continue with the rest of the audit.

Output format:
Return ONLY a single JSON object. No markdown code fences. No preamble. No trailing commentary.

The object must match this schema exactly:
{
  "findings": [
    {
      "title": "Short specific name for the vulnerability",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "lines": "Line numbers or ranges where the issue lives, e.g. '12' or '12-18' or '12, 47-52'",
      "explanation": "Why this is exploitable — the attack vector in prose, no payloads",
      "remediation": "Concrete fix the developer should apply, ideally naming the safer API or pattern",
      "source": "semgrep" | "independent"
    }
  ],
  "dismissed_leads": [
    {
      "rule": "Semgrep rule id",
      "lines": "Line range from the lead",
      "justification": "Short reason this is not actually exploitable in context"
    }
  ],
  "summary": "One short paragraph summarizing the security posture of this file"
}

Rules for the `source` field:
  * Use "semgrep" when the finding stems from confirming a Semgrep lead.
  * Use "independent" when you found the finding on your own, without a corresponding lead.
  * If no Semgrep leads were provided, every finding's source should be "independent".

If you find no vulnerabilities and there are no leads to dismiss, return {"findings": [], "dismissed_leads": [], "summary": "No issues found."}.
"""


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity
    lines: str
    explanation: str
    remediation: str
    source: Origin = "independent"
    pre_existing: bool = False


@dataclass(frozen=True)
class DismissedLead:
    rule: str
    lines: str
    justification: str


@dataclass(frozen=True)
class FileReport:
    source: SourceFile
    findings: list[Finding] = field(default_factory=list)
    dismissed_leads: list[DismissedLead] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    had_leads: bool = False

    @property
    def outcome(self) -> str:
        """'analyzed' when the API call and parse succeeded; 'failed' on any error."""
        return "failed" if self.error else "analyzed"


class AnalyzerError(RuntimeError):
    """Raised when the analyzer cannot run (e.g. missing API key)."""


class AuthError(RuntimeError):
    """Raised on HTTP 401 — the API key is invalid or expired."""


def _strip_code_fences(text: str) -> str:
    """Remove leading/trailing markdown code fences if the model added them."""
    stripped = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, re.DOTALL)
    if fence:
        return fence.group(1).strip()
    return stripped


def _coerce_finding(raw: object, default_source: Origin) -> Finding | None:
    if not isinstance(raw, dict):
        return None
    severity = str(raw.get("severity", "")).strip().upper()
    if severity not in VALID_SEVERITIES:
        severity = "LOW"
    source = str(raw.get("source", "")).strip().lower()
    if source not in VALID_ORIGINS:
        source = default_source
    return Finding(
        title=str(raw.get("title", "Untitled finding")).strip() or "Untitled finding",
        severity=severity,  # type: ignore[arg-type]
        lines=str(raw.get("lines", "")).strip(),
        explanation=str(raw.get("explanation", "")).strip(),
        remediation=str(raw.get("remediation", "")).strip(),
        source=source,  # type: ignore[arg-type]
    )


def _coerce_dismissed(raw: object) -> DismissedLead | None:
    if not isinstance(raw, dict):
        return None
    rule = str(raw.get("rule", "")).strip()
    if not rule:
        return None
    return DismissedLead(
        rule=rule,
        lines=str(raw.get("lines", "")).strip(),
        justification=str(raw.get("justification", "")).strip(),
    )


def _parse_response(
    text: str,
    default_source: Origin = "independent",
) -> tuple[list[Finding], list[DismissedLead], str, str | None]:
    """Parse the model's JSON response defensively.

    Returns (findings, dismissed_leads, summary, error_note). On parse failure,
    findings/dismissed are empty and error_note holds a short message — we never
    raise out of the parser.
    """
    cleaned = _strip_code_fences(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return [], [], "", f"Could not parse model response as JSON: {exc.msg}"

    if not isinstance(data, dict):
        return [], [], "", "Model response was not a JSON object."

    raw_findings = data.get("findings", [])
    findings: list[Finding] = []
    if isinstance(raw_findings, list):
        for raw in raw_findings:
            finding = _coerce_finding(raw, default_source)
            if finding is not None:
                findings.append(finding)

    raw_dismissed = data.get("dismissed_leads", [])
    dismissed: list[DismissedLead] = []
    if isinstance(raw_dismissed, list):
        for raw in raw_dismissed:
            entry = _coerce_dismissed(raw)
            if entry is not None:
                dismissed.append(entry)

    summary = str(data.get("summary", "")).strip()
    return findings, dismissed, summary, None


_LINE_SPEC_RE = re.compile(r"(\d+)(?:\s*-\s*(\d+))?")


def parse_line_spec(spec: str) -> list[tuple[int, int]]:
    """Parse a finding's `lines` string into a list of (start, end) ranges."""
    if not spec:
        return []
    ranges: list[tuple[int, int]] = []
    for match in _LINE_SPEC_RE.finditer(spec):
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else start
        if end < start:
            start, end = end, start
        ranges.append((start, end))
    return ranges


def ranges_overlap(
    a: list[tuple[int, int]],
    b: list[tuple[int, int]],
) -> bool:
    """True if any (start, end) interval in `a` overlaps any interval in `b`."""
    for a_start, a_end in a:
        for b_start, b_end in b:
            if a_start <= b_end and b_start <= a_end:
                return True
    return False


def tag_pre_existing(
    findings: list[Finding],
    changed_ranges: list[tuple[int, int]] | None,
) -> list[Finding]:
    """Return findings with `pre_existing=True` for any that fall outside the diff."""
    if not changed_ranges:
        return findings
    tagged: list[Finding] = []
    for finding in findings:
        finding_ranges = parse_line_spec(finding.lines)
        is_in_diff = bool(finding_ranges) and ranges_overlap(finding_ranges, changed_ranges)
        if finding_ranges and not is_in_diff:
            tagged.append(
                Finding(
                    title=finding.title,
                    severity=finding.severity,
                    lines=finding.lines,
                    explanation=finding.explanation,
                    remediation=finding.remediation,
                    source=finding.source,
                    pre_existing=True,
                )
            )
        else:
            tagged.append(finding)
    return tagged


def _format_changed_ranges(ranges: list[tuple[int, int]]) -> str:
    parts: list[str] = []
    for start, end in ranges:
        parts.append(str(start) if start == end else f"{start}-{end}")
    return ", ".join(parts)


def _format_diff_block(ranges: list[tuple[int, int]]) -> str:
    return (
        f"This file changed in the diff under review. Focus your review on the "
        f"changed lines ({_format_changed_ranges(ranges)}), but use the rest of "
        f"the file as context. Still report any security issues you find outside "
        f"the changed ranges — they will be tagged as pre-existing automatically."
    )


def _format_leads_block(hits: list[SemgrepHit]) -> str:
    lines = ["A static analyzer (Semgrep) flagged the following potential issues in this file:"]
    for hit in hits:
        msg = hit.message.replace("\n", " ").strip()
        if len(msg) > 240:
            msg = msg[:237] + "..."
        lines.append(
            f"  - [{hit.severity}] rule `{hit.rule_id}` at lines {hit.line_range}: {msg}"
        )
    lines.append(
        "Treat these as leads, not ground truth. For each, confirm it is a real "
        "vulnerability or mark it as a false positive in `dismissed_leads` with a "
        "short justification. Then also report any other security issues you find "
        "in the file, especially around the flagged regions."
    )
    return "\n".join(lines)


class Analyzer:
    """Wraps the Anthropic client and runs one analysis per source file."""

    def __init__(self, model: str = DEFAULT_MODEL, client: Anthropic | None = None):
        self.model = model
        self.request_count = 0
        if client is not None:
            self._client = client
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise AnalyzerError(
                    "ANTHROPIC_API_KEY is not set. Export your Anthropic API key "
                    "before running vulnscan, e.g. `export ANTHROPIC_API_KEY=sk-...`."
                )
            self._client = Anthropic(api_key=api_key)

    def analyze(
        self,
        source: SourceFile,
        leads: list[SemgrepHit] | None = None,
        changed_ranges: list[tuple[int, int]] | None = None,
    ) -> FileReport:
        leads = leads or []
        had_leads = bool(leads)
        default_source: Origin = "semgrep" if had_leads else "independent"

        leads_block = _format_leads_block(leads) if leads else ""
        diff_block = _format_diff_block(changed_ranges) if changed_ranges else ""
        user_prompt_parts = [
            f"File: {source.path}",
            f"Language: {source.language}",
        ]
        if diff_block:
            user_prompt_parts.append("")
            user_prompt_parts.append(diff_block)
        if leads_block:
            user_prompt_parts.append("")
            user_prompt_parts.append(leads_block)
        user_prompt_parts.append("")
        user_prompt_parts.append(
            "Audit the following source for security vulnerabilities. "
            "Respond with the JSON object only."
        )
        user_prompt_parts.append("")
        user_prompt_parts.append("```")
        user_prompt_parts.append(source.content)
        user_prompt_parts.append("```")
        user_prompt = "\n".join(user_prompt_parts)

        last_error: str | None = None
        message = None
        for attempt in range(_MAX_RETRIES):
            try:
                self.request_count += 1
                message = self._client.messages.create(
                    model=self.model,
                    max_tokens=MAX_TOKENS,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                )
                break  # success — exit retry loop
            except Exception as exc:  # noqa: BLE001 - classified below
                status = getattr(exc, "status_code", None)
                # Auth errors are not retriable — raise immediately so the
                # caller can stop the entire run rather than hammering the API.
                if isinstance(exc, _anthropic.AuthenticationError) or status == 401:
                    raise AuthError(
                        f"HTTP 401 — the API key is invalid or expired: {exc}"
                    ) from exc
                is_transient = (
                    status in _RETRY_STATUSES
                    or isinstance(exc, _anthropic.APIConnectionError)
                )
                last_error = f"API call failed: {exc}"
                if is_transient and attempt < _MAX_RETRIES - 1:
                    time.sleep(_BACKOFF_BASE * (2 ** attempt))
                    continue
                # Non-retryable error, or all retries exhausted.
                return FileReport(
                    source=source,
                    error=last_error,
                    had_leads=had_leads,
                )

        if message is None:  # defensive — not reachable with _MAX_RETRIES >= 1
            return FileReport(
                source=source,
                error=last_error or "No response received after retries.",
                had_leads=had_leads,
            )

        text_parts: list[str] = []
        for block in getattr(message, "content", []) or []:
            block_text = getattr(block, "text", None)
            if isinstance(block_text, str):
                text_parts.append(block_text)
        text = "".join(text_parts)

        findings, dismissed, summary, error = _parse_response(text, default_source)
        findings = tag_pre_existing(findings, changed_ranges)
        return FileReport(
            source=source,
            findings=findings,
            dismissed_leads=dismissed,
            summary=summary,
            error=error,
            had_leads=had_leads,
        )
