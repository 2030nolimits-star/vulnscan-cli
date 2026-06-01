# vulnscan

A defensive, Anthropic-powered source-code security auditor. It reads code you own, reasons about it like an experienced security researcher, and produces a structured report of vulnerabilities, with a plain-prose explanation of why each one is exploitable and a concrete remediation. It does **not** generate runnable exploits, shellcode, weaponized proof-of-concept scripts, or ready-to-fire injection strings.

---

## Features

- **Multi-language** - Python, JavaScript/JSX, TypeScript/TSX, Java, Go, Ruby, PHP, C, C++, C#, Rust, Swift, Kotlin, Shell, SQL.
- **Deep per-file reasoning** - one Anthropic API call per file; Claude traces taint flow, trust boundaries, injection classes, memory safety, weak crypto, hardcoded secrets, and logic flaws.
- **Severity-ranked findings** - each finding carries a title, severity (CRITICAL / HIGH / MEDIUM / LOW), line numbers, a "Why" prose explanation, and a "Fix" remediation.
- **Semgrep prefilter** - optional fast first pass that narrows which files reach the API; Semgrep hits are attached as context so Claude can confirm, dismiss, or deepen each lead.
- **Diff mode** - `--diff` restricts the scan to files changed in git, with changed line ranges passed to Claude as focus context; pre-existing findings outside the diff are tagged separately.
- **Pre-commit hook** - `--install-hook` writes a `.git/hooks/pre-commit` that runs `vulnscan --diff --staged` before every commit.
- **Four output formats** - `terminal` (colored rich report), `json` (stable schema), `sarif` (SARIF 2.1.0 for GitHub code scanning), `markdown` (sticky PR comment).
- **CI gate** - distinct exit codes let you fail a CI check only when actual findings cross a severity threshold; inconclusive scans (API errors) exit with a separate code so they are never mistaken for a clean pass.
- **Retry and fast-fail** - transient errors (HTTP 429, 500, 502, 503, 504, connection resets) are retried with exponential backoff; a 401 auth error aborts the run immediately with setup guidance.

---

## Requirements

- Python 3.10 or later.
- An Anthropic API key (<https://console.anthropic.com/>).
- Semgrep 1.50 or later - optional; enables the prefilter that cuts API cost on large repos.

---

## Installation

```bash
git clone <this repo>
cd vulnscan
pip install -e .
```

To include the optional Semgrep prefilter dependency:

```bash
pip install -e '.[prefilter]'
```

**Windows note — build isolation failure:** if `pip install -e .` fails with a connection error while downloading `setuptools`, a firewall or AV may be blocking the isolated build environment. Work around it with:

```powershell
pip install --no-build-isolation -e .
```

If the `vulnscan` command is not on PATH after install (common in some virtual-environment setups), invoke it directly:

```bash
python -m vulnscan.cli
```

---

## API key setup

vulnscan calls the Anthropic API on every file it analyzes. Set your API key in the shell before running.

**PowerShell (session only):**

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**PowerShell (persistent — opens a new window to take effect):**

```powershell
setx ANTHROPIC_API_KEY "sk-ant-..."
```

**bash / zsh:**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

> **Security:** never commit your key to source control, paste it into a chat, or share it in a log. If a key is accidentally exposed, rotate it immediately in the Anthropic console and revoke the old one.

---

## Usage

Scan a directory (defaults to `.`):

```bash
vulnscan ./src
```

Scan a single file:

```bash
vulnscan app.py
```

Scan only files changed since the last commit (staged + unstaged vs HEAD):

```bash
vulnscan --diff
```

Scan only staged changes (for use in pre-commit hooks):

```bash
vulnscan --diff --staged
```

Scan everything new on a feature branch:

```bash
vulnscan --diff main
```

Override the model (default: `claude-opus-4-8`):

```bash
vulnscan --model claude-sonnet-4-6 ./src
```

Disable the Semgrep prefilter and send every file to the API:

```bash
vulnscan --no-prefilter ./src
```

Emit JSON and pipe to jq:

```bash
vulnscan ./src --format json | jq '.summary'
vulnscan ./src --format json 2>/dev/null | jq '.findings[] | select(.severity=="CRITICAL")'
```

Emit SARIF for GitHub code scanning:

```bash
vulnscan ./src --format sarif > vulnscan.sarif
```

Emit a markdown summary for a PR comment:

```bash
vulnscan --diff main --format markdown > vulnscan.md
```

**Windows paths:** use backslashes or forward slashes — both work with the `Path` argument:

```powershell
vulnscan .\src
vulnscan --diff --staged --format json | python -m json.tool
```

---

## Output and exit codes

In `json` and `sarif` modes, **stdout contains only the document**. All spinners, progress notes, warnings, and errors go to stderr, so piping is safe. In `terminal` and `markdown` modes everything goes to stdout.

| Code | Meaning |
|------|---------|
| 0 | All targeted files were analyzed; no findings at or above the `--block-on` threshold (default: HIGH). |
| 1 | Analysis completed and at least one finding at or above the threshold was found. |
| 2 | Configuration or authentication error: `ANTHROPIC_API_KEY` not set, invalid or expired key (HTTP 401), `--diff` used outside a git repo, or an invalid flag value. |
| 3 | **Inconclusive** — one or more files failed to analyze after all retries. The run is incomplete; exit 3 is not the same as "clean." |

Exit 3 can occur due to transient network failures or persistent API errors on individual files. When it fires, the summary prints how many files were analyzed versus how many failed. Treat a 3 exit as requiring investigation, not as a passing result.

The `--block-on` flag controls the threshold (default: `HIGH`, meaning CRITICAL and HIGH both block). The pre-installed pre-commit hook defaults to `CRITICAL` via `VULNSCAN_BLOCK_SEVERITY`.

---

## JSON output schema

```json
{
  "tool": "vulnscan",
  "version": "0.1.0",
  "scanned_at": "2026-06-01T12:34:56Z",
  "target": "./src",
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 0,
    "files_scanned": 5,
    "files_analyzed": 4,
    "files_failed": 1,
    "files_skipped": 0,
    "inconclusive": true
  },
  "findings": [
    {
      "file": "src/db.py",
      "language": "Python",
      "title": "SQL injection via string formatting",
      "severity": "CRITICAL",
      "lines": "47",
      "explanation": "...",
      "remediation": "..."
    }
  ]
}
```

`files_analyzed` counts files where the API call and response parse succeeded. `files_failed` counts files that produced errors after all retries. `inconclusive` mirrors `files_failed > 0`. These fields let downstream tools distinguish a genuine zero-findings run from an incomplete one.

---

## Supported languages

| Language | Extensions |
|----------|-----------|
| Python | `.py` |
| JavaScript | `.js` `.mjs` `.cjs` |
| JavaScript (JSX) | `.jsx` |
| TypeScript | `.ts` |
| TypeScript (TSX) | `.tsx` |
| Java | `.java` |
| Go | `.go` |
| Ruby | `.rb` |
| PHP | `.php` |
| C | `.c` `.h` |
| C++ | `.cc` `.cpp` `.cxx` `.hpp` `.hh` |
| C# | `.cs` |
| Rust | `.rs` |
| Swift | `.swift` |
| Kotlin | `.kt` `.kts` |
| Shell | `.sh` `.bash` `.zsh` |
| SQL | `.sql` |

Files larger than 200 KB are skipped. The following directories are never descended into: `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `dist`, `build`, `.next`, `vendor`, `target`.

---

## Semgrep prefilter

When the `semgrep` binary is on PATH, vulnscan runs `semgrep --config auto` over the target before the API pass. Only files Semgrep flags reach the Anthropic API; files with no hits are counted as scanned but skipped from the expensive step. On a large repo with a focused diff this typically reduces API calls to one or two.

Semgrep hits are forwarded to Claude as structured context (rule ID, message, and line range). Claude is asked to confirm or dismiss each lead and to report any additional issues it finds nearby — so the prefilter improves signal, not just cost.

The summary line shows the breakdown: `N flagged → M sent to deep-reasoning pass (K skipped)`.

If Semgrep is missing or times out (300-second limit), vulnscan falls back to whole-file mode automatically and logs a dim note. Pass `--no-prefilter` to force whole-file mode regardless.

**Install Semgrep:**

```bash
pip install -e '.[prefilter]'
# or
pipx install semgrep
```

---

## Pre-commit hook

```bash
vulnscan --install-hook
```

This writes `.git/hooks/pre-commit` and makes it executable. The hook runs `vulnscan --diff --staged --block-on $VULNSCAN_BLOCK_SEVERITY` before every commit.

- Exits 0 immediately when no scannable files are staged, no API call is made.
- Blocks the commit on **CRITICAL** findings by default.
- Prints HIGH / MEDIUM / LOW findings without blocking (below the default threshold).
- If `vulnscan` is not on PATH when the hook fires, the hook warns and exits 0 rather than breaking unrelated commits.

Raise the threshold for a single commit:

```bash
# bash / zsh
VULNSCAN_BLOCK_SEVERITY=HIGH git commit -m "..."

# PowerShell
$env:VULNSCAN_BLOCK_SEVERITY = "HIGH"; git commit -m "..."
```

Or set it permanently in your shell profile to apply to every commit in the repo.

Bypass the hook for a single emergency commit:

```bash
git commit --no-verify -m "..."
```

The hook refuses to overwrite an existing `.git/hooks/pre-commit`. Inspect and merge by hand if one already exists.

---

## CI integration (GitHub Actions)

The workflow at `.github/workflows/vulnscan.yml` is ready to use. It triggers on pull requests, pushes to `main`, and manual `workflow_dispatch`. Draft PRs are skipped.

### One-time setup

1. **Add the API key secret.** In your repo: **Settings → Secrets and variables → Actions → New repository secret**. Name: `ANTHROPIC_API_KEY`. Value: your key. The workflow reads it as `${{ secrets.ANTHROPIC_API_KEY }}` and it is never echoed to logs.

2. **(Optional) Set the block severity.** In **Settings → Secrets and variables → Actions → Variables**, add a repository variable `VULNSCAN_BLOCK_SEVERITY` set to `CRITICAL` (default if absent) or `HIGH`. Changing the variable takes effect on the next run without editing the workflow file.

3. **Commit the workflow file** to the default branch.

4. **(Optional) Require the check.** In **Settings → Branches → Branch protection rules**, add `vulnscan / Scan changed code` to the list of required status checks to block merges on blocking findings.

### What the workflow does

- Checks out the PR with `fetch-depth: 0` so `--diff origin/<base_ref>` can compute line-level hunks.
- Installs vulnscan and attempts to install the Semgrep prefilter (`continue-on-error: true` so a Semgrep failure does not block the scan).
- Runs `vulnscan --diff <base_ref> --format sarif --block-on $VULNSCAN_BLOCK_SEVERITY > vulnscan.sarif`. If vulnscan exits before writing anything (e.g., missing key, exit 2), a minimal empty SARIF is written so the upload step never sees a missing file.
- Uploads the SARIF with `github/codeql-action/upload-sarif@v3` (category `vulnscan`).
- Runs `vulnscan --diff <base_ref> --format markdown > vulnscan.md` for PR comments.
- Posts or updates a sticky PR comment via `marocchino/sticky-pull-request-comment@v2` (header `vulnscan`), re-runs update the same comment.
- A final step reads the captured exit code from the scan step and fails the workflow if it is non-zero, which gates the PR check. Exit 3 (inconclusive) fails the check.

### Where findings appear

- **Inline annotations** in the PR **Files changed** tab - one annotation per finding at the relevant line, driven by the SARIF upload.
- **Security → Code scanning** in the repo - aggregated dashboard across branches and PRs, filterable by severity. Findings auto-close when a subsequent run stops reporting them.
- **One sticky PR comment** with the severity counts table and the top critical/high findings, updated in place on every push.

### Tuning

- Change the block severity without editing the workflow file: update the repo variable `VULNSCAN_BLOCK_SEVERITY`.
- Trigger an ad-hoc scan with a custom threshold: **Actions → vulnscan → Run workflow** and choose from the dropdown.
- Disable the gate temporarily: uncheck `vulnscan / Scan changed code` from required status checks in branch protection.
- Concurrency is set to cancel in-progress runs for the same PR on a force-push.

---

## How it works

1. **Discovery.** `vulnscan.scanner` walks the path, filters to supported extensions, skips vendored directories, and reads files as UTF-8. Files above 200 KB are skipped.

2. **Prefilter (optional).** `vulnscan.prefilter` runs `semgrep --config auto --json --quiet --metrics=off` on the full target. Files with no Semgrep hits skip the API pass entirely; files with hits carry their hits as context into step 3.

3. **Deep reasoning.** `vulnscan.analyzer` sends one request to the Anthropic API per file (model: `claude-opus-4-8` by default). The system prompt instructs Claude to behave as a defensive auditor: trace taint flow from untrusted inputs, check trust boundaries, identify injection classes, memory-safety issues, weak crypto, hardcoded secrets, and logic flaws. In diff mode, the changed line ranges are included so Claude can focus review without losing file context. The model is instructed to return a single JSON object; the parser strips stray code fences and handles malformed responses without crashing, a parse failure marks the file as `failed` rather than crashing the whole run.

4. **Retry.** Transient errors (HTTP 429, 500, 502, 503, 504, connection resets) are retried up to three attempts total with exponential backoff (1 s, 2 s). An HTTP 401 stops the run immediately, retrying a bad key produces no useful result.

5. **Reporting.** `vulnscan.cli` renders findings with `rich` in terminal mode, or calls the appropriate formatter for json/sarif/markdown. The exit code is determined after all files finish: 1 if blocking findings were found, 3 if any files failed, 0 if all files analyzed cleanly.

---

## Limitations and responsible use

- **Token cost.** Analyzing a large repo in whole-file mode (no `--diff`, no prefilter) sends every supported file to the API. Use `--diff` for incremental scans and the Semgrep prefilter for batch scans to control cost.
- **AI-generated findings.** Results are produced by a language model. False positives and false negatives are possible. Review each finding before acting on it; do not rely on vulnscan as the only security control.
- **Authorized use only.** Run vulnscan on code you own or have explicit authorization to audit. Using it against systems you do not own is outside its intended use and may be illegal.
- **No exploit generation.** The system prompt is a hard constraint: Claude will not produce runnable payloads, shellcode, or step-by-step exploitation instructions. It describes vulnerabilities in prose so the owner can understand and fix them.

---

## Troubleshooting

**`vulnscan: command not found` (or similar)**

The entry point script may not be on PATH. Try:

```bash
python -m vulnscan.cli
```

Or activate the virtual environment where you installed the package.

---

**`export` is not recognized as a command (Windows)**

`export` is a bash/sh built-in. In PowerShell, set environment variables with:

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

---

**`Error: HTTP 401 — the API key is invalid or expired`**

The key in `ANTHROPIC_API_KEY` is wrong, was rotated, or has been revoked. vulnscan stops immediately on the first 401 rather than re-attempting with the same bad key. Fix:

1. Check the key value in your shell: `echo $env:ANTHROPIC_API_KEY` (PowerShell) or `echo $ANTHROPIC_API_KEY` (bash).
2. Generate or retrieve a valid key at <https://console.anthropic.com/>.
3. Set it in the **current shell session** (not a parent or child process) and re-run.
4. Verify your Anthropic account has active credits or a paid plan.

---

**`Connection reset` or `Could not fetch a wheel for setuptools` during install**

A firewall or AV is blocking pip's isolated build environment. Use:

```bash
pip install --no-build-isolation -e .
```

---

**`semgrep: not found` or `Semgrep binary not found on PATH`**

The Semgrep prefilter is optional. vulnscan falls back to whole-file scanning and logs a dim note. You can install Semgrep with:

```bash
pip install -e '.[prefilter]'
# or
pipx install semgrep
```

Or disable the prefilter entirely:

```bash
vulnscan --no-prefilter ./src
```

---

**Exit code 3 — inconclusive results**

One or more files failed to analyze after all retries (e.g., persistent network issues or API errors). The summary prints which files failed. An exit-3 run is **not** equivalent to "no findings", it means the result is incomplete. Re-run once the underlying connectivity or API issue is resolved.
