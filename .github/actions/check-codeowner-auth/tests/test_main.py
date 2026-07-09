"""Tests for the ``main.py`` entry point.

Covers I/O plumbing that ``authorize.py`` deliberately doesn't handle:
token input reading, event payload loading, exit-code translation.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src import _actions
from src.authorize import Outcome, OutcomeKind


@pytest.fixture(autouse=True)
def _reset_actions_state() -> None:
    """Reset the module-global exit code between tests.

    ``_actions._exit_code`` is a module-level counter set by ``set_failed``.
    Tests that expect exit code 0 will spuriously see 1 if a previous test
    left the state dirty.
    """
    _actions._exit_code = 0  # type: ignore[attr-defined]


def _write_event_file(tmp_path: Path, payload: dict | list | None | str) -> Path:
    p = tmp_path / "event.json"
    if isinstance(payload, str):
        p.write_text(payload)
    else:
        p.write_text(json.dumps(payload))
    return p


class TestTokenHandling:
    def test_missing_input_token_fails_with_specific_error(
        self, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
    ) -> None:
        # No INPUT_GITHUB_TOKEN environment variable set. Composite actions
        # with `required: true` do NOT reject empty inputs — GitHub expands
        # a missing secret to empty string — so this is a real caller-side
        # bug we have to catch here.
        monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")

        from main import _run

        result = asyncio.run(_run())
        assert result is None
        out = capfd.readouterr().out
        # Must emit a workflow-command annotation so the failure is visible
        # in the run summary, not just a red step.
        assert "::error::" in out
        # The error should tell the caller exactly what's wrong.
        assert "github-token" in out.lower()

    def test_empty_string_input_token_fails_does_not_fall_back(
        self, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
    ) -> None:
        # Regression: previously ``INPUT_GITHUB_TOKEN or GITHUB_TOKEN``
        # meant an empty INPUT_GITHUB_TOKEN silently fell back to the
        # runner's built-in GITHUB_TOKEN, which lacks `read:org`. Every
        # legitimate codeowner PR would then deny as DENIED_NO_APPROVAL
        # with no hint the token was wrong. Reject empty explicitly.
        monkeypatch.setenv("INPUT_GITHUB_TOKEN", "")
        monkeypatch.setenv("GITHUB_TOKEN", "would-have-worked-before-fix")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")

        from main import _run

        result = asyncio.run(_run())
        assert result is None
        out = capfd.readouterr().out
        assert "::error::" in out
        assert "github-token" in out.lower()

    def test_whitespace_only_input_token_rejected(
        self, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
    ) -> None:
        # Paranoia: a caller who accidentally quoted the input with whitespace
        # (or expanded a secret from a variable containing only whitespace)
        # should hit the same explicit rejection, not a mangled auth attempt.
        monkeypatch.setenv("INPUT_GITHUB_TOKEN", "   \n\t")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")

        from main import _run

        result = asyncio.run(_run())
        assert result is None
        out = capfd.readouterr().out
        assert "::error::" in out


class TestMainExitCodeMapping:
    """Verify the outcome-kind → exit code translation in ``main.main()``.

    These are pure translation tests; ``authorize()`` itself is mocked out.
    """

    def test_authorized_outcome_returns_zero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        event_path = _write_event_file(tmp_path, {})
        monkeypatch.setenv("INPUT_GITHUB_TOKEN", "fake-token")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
        monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))

        async def fake_run() -> Outcome:
            return Outcome(
                kind=OutcomeKind.AUTHORIZED_AUTHOR,
                message="ok",
                head_sha="sha-x",
            )

        import main

        monkeypatch.setattr(main, "_run", fake_run)
        assert main.main() == 0

    def test_denied_outcome_returns_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        event_path = _write_event_file(tmp_path, {})
        monkeypatch.setenv("INPUT_GITHUB_TOKEN", "fake-token")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
        monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))

        async def fake_run() -> Outcome:
            return Outcome(
                kind=OutcomeKind.DENIED_NO_APPROVAL,
                message="denied",
                head_sha="sha-x",
            )

        import main

        monkeypatch.setattr(main, "_run", fake_run)
        assert main.main() != 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
