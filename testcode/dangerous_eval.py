"""Deliberately vulnerable sample: eval on user input.

Semgrep's `python.lang.security.audit.eval-detected` rule reliably matches this.
"""


def run_user_expression(expr: str) -> object:
    # eval on attacker-controlled input — arbitrary code execution.
    return eval(expr)


def calculate_from_request(form: dict) -> object:
    value = form.get("formula", "0")
    return eval(value, {"__builtins__": {}})


if __name__ == "__main__":
    print(run_user_expression("__import__('os').listdir('.')"))
