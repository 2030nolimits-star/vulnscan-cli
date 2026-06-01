"""Deliberately vulnerable sample: yaml.load without a safe loader.

Semgrep's `python.lang.security.deserialization.avoid-pyyaml-load` rule catches this.
"""

import yaml


def load_config(payload: str) -> object:
    # yaml.load with the default loader allows arbitrary object construction.
    return yaml.load(payload)


def load_config_explicit_unsafe(payload: str) -> object:
    return yaml.load(payload, Loader=yaml.Loader)


if __name__ == "__main__":
    print(load_config("key: value"))
