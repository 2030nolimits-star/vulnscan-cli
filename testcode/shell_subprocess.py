"""Deliberately vulnerable sample: subprocess with shell=True.

Semgrep's `python.lang.security.audit.subprocess-shell-true` rule catches this.
"""

import subprocess


def archive(path: str) -> int:
    # shell=True with user input → command injection via shell metacharacters.
    return subprocess.call("tar czf out.tgz " + path, shell=True)


def list_dir(path: str) -> bytes:
    return subprocess.check_output(f"ls -la {path}", shell=True)


if __name__ == "__main__":
    archive("/tmp/safe")
