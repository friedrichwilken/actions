"""
Minimal GitHub Actions toolkit shim.

Replaces the parts of ``@actions/core`` we actually use. The GHA runtime
communicates with the runner via well-known env vars and stdout formatting
described in <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands>.

Kept here rather than pulled in as a third-party dependency to minimize
supply-chain surface for a security-sensitive action.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _append_env_file(env_var: str, line: str) -> None:
    """Append ``line`` to the file at ``os.environ[env_var]``.

    The GHA runtime provides files (not stdout streams) for outputs and
    environment updates. Missing env var is a runtime configuration bug;
    print a warning to stderr and continue rather than crash.
    """
    path = os.environ.get(env_var)
    if not path:
        print(f"::warning::{env_var} is not set; cannot write '{line}'", file=sys.stderr)
        return
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def set_output(name: str, value: str) -> None:
    """Set an action output that downstream steps can reference."""
    _append_env_file("GITHUB_OUTPUT", f"{name}={value}")


def mask(value: str) -> None:
    """Register ``value`` as a secret so the runner redacts it from logs."""
    print(f"::add-mask::{value}")


def info(message: str) -> None:
    """Log an informational message. Renders as a plain line in the runner log."""
    print(message)


def warning(message: str) -> None:
    """Log a warning. Rendered with an icon in the workflow run summary."""
    print(f"::warning::{message}")


def error(message: str) -> None:
    """Log an error. Rendered with an icon in the workflow run summary."""
    print(f"::error::{message}")


def set_failed(message: str) -> None:
    """Log an error and mark the step as failed.

    Does not exit the process — the caller decides when to return. This
    matches ``@actions/core.setFailed`` semantics: setting failed is a state
    transition, not a control-flow abort.
    """
    error(message)
    # GITHUB_ACTIONS runners honor a non-zero exit as the failure signal.
    # We set the exit code so ``sys.exit(get_exit_code())`` at the end of
    # ``main`` produces the correct status.
    global _exit_code
    _exit_code = 1


_exit_code: int = 0


def get_exit_code() -> int:
    """Return the current exit code (0 unless ``set_failed`` was called)."""
    return _exit_code
