"""Semgrep first-pass to narrow which files reach the Anthropic API."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SEMGREP_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class SemgrepHit:
    """A single Semgrep finding used as a lead for deeper analysis."""

    rule_id: str
    message: str
    start_line: int
    end_line: int
    severity: str

    @property
    def line_range(self) -> str:
        if self.start_line == self.end_line:
            return str(self.start_line)
        return f"{self.start_line}-{self.end_line}"


@dataclass(frozen=True)
class PrefilterResult:
    """Outcome of a Semgrep run, ready to drive analyzer decisions."""

    available: bool
    hits_by_file: dict[Path, list[SemgrepHit]]
    error: str | None = None

    def hits_for(self, path: Path) -> list[SemgrepHit]:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        return self.hits_by_file.get(resolved, [])


def semgrep_available() -> bool:
    """Return True iff the semgrep binary is on PATH."""
    return shutil.which("semgrep") is not None


def _coerce_hit(raw: dict) -> SemgrepHit | None:
    rule_id = str(raw.get("check_id") or "").strip() or "unknown"
    extra = raw.get("extra") or {}
    message = str(extra.get("message") or "").strip()
    severity = str(extra.get("severity") or "").strip().upper() or "UNKNOWN"

    start = raw.get("start") or {}
    end = raw.get("end") or {}
    try:
        start_line = int(start.get("line", 0)) or 0
        end_line = int(end.get("line", start_line)) or start_line
    except (TypeError, ValueError):
        return None
    if start_line <= 0:
        return None

    return SemgrepHit(
        rule_id=rule_id,
        message=message,
        start_line=start_line,
        end_line=max(end_line, start_line),
        severity=severity,
    )


def _parse_semgrep_json(payload: str) -> dict[Path, list[SemgrepHit]]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return {}

    hits_by_file: dict[Path, list[SemgrepHit]] = {}
    for raw in data.get("results", []) or []:
        if not isinstance(raw, dict):
            continue
        path_str = raw.get("path")
        if not isinstance(path_str, str) or not path_str:
            continue
        try:
            file_path = Path(path_str).resolve()
        except OSError:
            file_path = Path(path_str)
        hit = _coerce_hit(raw)
        if hit is None:
            continue
        hits_by_file.setdefault(file_path, []).append(hit)

    for file_path, hits in hits_by_file.items():
        hits.sort(key=lambda h: h.start_line)

    return hits_by_file


def run_semgrep(target: Path, runner=subprocess.run) -> PrefilterResult:
    """Invoke semgrep on the target path and return parsed hits per file.

    `runner` is injectable so tests can stub the subprocess call.
    """
    if not semgrep_available():
        return PrefilterResult(available=False, hits_by_file={}, error="binary-missing")

    cmd = [
        "semgrep",
        "--config",
        "auto",
        "--json",
        "--quiet",
        "--metrics=off",
        "--error",
        "--timeout",
        "0",
        str(target),
    ]

    try:
        completed = runner(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return PrefilterResult(available=False, hits_by_file={}, error="binary-missing")
    except subprocess.TimeoutExpired:
        return PrefilterResult(available=True, hits_by_file={}, error="timeout")
    except Exception as exc:  # noqa: BLE001 - surface as soft error
        return PrefilterResult(available=True, hits_by_file={}, error=f"run-failed: {exc}")

    stdout = getattr(completed, "stdout", "") or ""
    hits_by_file = _parse_semgrep_json(stdout)
    return PrefilterResult(available=True, hits_by_file=hits_by_file)
