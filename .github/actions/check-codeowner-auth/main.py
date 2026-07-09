"""
Entry point for the check-codeowner-auth composite action.

Called from ``action.yml`` as ``python -m main``. Reads the workflow
context from environment variables, invokes the ``authorize`` coroutine,
translates the outcome into GHA outputs, and exits with a non-zero
status on denial.

No decision logic lives here — this file is purely I/O and translation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from githubkit import GitHub

from src import _actions
from src.authorize import AUTHORIZED_KINDS, Outcome, authorize


def _load_event_payload() -> dict | None:
    """Load the workflow event payload from ``$GITHUB_EVENT_PATH``.

    Returns the parsed payload as a dict, or ``None`` on any I/O or shape
    error. ``None`` is the "we already called ``set_failed``" signal —
    callers should short-circuit rather than reinterpret the value.

    Distinguishes several failure modes so the caller sees a specific
    ``::error::`` annotation in the workflow run summary rather than a
    silent exit-1:

    - ``GITHUB_EVENT_PATH`` unset: runner environment misconfigured.
    - File unreadable or not valid UTF-8 JSON: filesystem or shape.
    - Parsed value is not a JSON object: e.g. ``null``, ``[]``, ``"str"``,
      ``0``. Downstream code assumes ``event_payload.get("pull_request")``
      works; a list would raise ``AttributeError`` in ``authorize``.
    - Parsed object is empty (``{}``): legitimate JSON, but there's no
      event to authorize. Fail explicitly so the maintainer sees WHY the
      step failed, not just that it failed.
    """
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        _actions.set_failed("GITHUB_EVENT_PATH is not set.")
        return None
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _actions.set_failed(f"Could not read event payload from {path!r}: {e}")
        return None
    if not isinstance(payload, dict):
        _actions.set_failed(
            f"Event payload at {path!r} is a {type(payload).__name__}, "
            "not a JSON object. Cannot proceed."
        )
        return None
    if not payload:
        _actions.set_failed(
            f"Event payload at {path!r} is an empty JSON object. "
            "This action requires a pull_request_target or pull_request_review event."
        )
        return None
    return payload


async def _run() -> Outcome | None:
    """Do the work. Returns ``None`` iff an unrecoverable I/O error occurred."""
    # Read the caller-provided input verbatim. Do NOT fall back to the
    # runner's built-in GITHUB_TOKEN — it lacks the `read:org` scope we need
    # for team membership checks, so every membership call would 404 and
    # every legitimate codeowner PR would deny as DENIED_NO_APPROVAL with
    # no hint that the token is wrong. Composite `required: true` inputs
    # accept the empty string when a caller passes an unset secret, so we
    # have to reject empty ourselves.
    token = os.environ.get("INPUT_GITHUB_TOKEN", "").strip()
    if not token:
        _actions.set_failed(
            "No GitHub token provided. Pass an installation token via the "
            "`github-token` input (typically minted with "
            "`actions/create-github-app-token`). Do NOT pass the runner's "
            "built-in `GITHUB_TOKEN` — it lacks the `read:org` scope."
        )
        return None

    # Belt-and-braces: register the token as a secret so any accidental
    # log line containing it gets redacted. ``create-github-app-token``
    # already does this, but we can't assume the caller minted it that way.
    _actions.mask(token)

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    trusted_bot_ids_raw = os.environ.get("INPUT_TRUSTED_BOT_IDS", "")
    # Temporary bridge flag (default off). Only "true" (case-insensitive)
    # enables it; anything else — unset, empty, "false", garbage — is off.
    allow_individual_owners = (
        os.environ.get("INPUT_ALLOW_INDIVIDUAL_OWNERS", "").strip().lower() == "true"
    )
    event_payload = _load_event_payload()
    if event_payload is None:
        # ``_load_event_payload`` already called ``set_failed`` with a
        # specific diagnostic. Bail with the same convention as the
        # token-missing branch above.
        return None

    async with GitHub(token) as gh:
        return await authorize(
            gh,
            event_name=event_name,
            event_payload=event_payload,
            trusted_bot_ids_raw=trusted_bot_ids_raw,
            allow_individual_owners=allow_individual_owners,
        )


def main() -> int:
    """CLI entry point. Returns the process exit code."""
    outcome = asyncio.run(_run())
    if outcome is None:
        # ``_run`` already called ``set_failed`` with a specific reason.
        return _actions.get_exit_code() or 1

    if outcome.head_sha is not None:
        _actions.set_output("head-sha", outcome.head_sha)
    _actions.set_output("outcome", outcome.kind.value)

    # Branch on enum-set membership, NOT on string prefix. See the
    # AUTHORIZED_KINDS docstring in authorize.py for the rationale.
    if outcome.kind in AUTHORIZED_KINDS:
        _actions.info(outcome.message)
        return 0

    _actions.set_failed(outcome.message)
    return _actions.get_exit_code() or 1


if __name__ == "__main__":
    sys.exit(main())
