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


class TestLoadEventPayload:
    """Verify ``_load_event_payload`` fails loudly (not silently) on every
    input shape that can't produce a valid workflow event dict."""

    def test_missing_env_path_calls_set_failed(
        self, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
        from main import _load_event_payload

        assert _load_event_payload() is None
        out = capfd.readouterr().out
        assert "::error::" in out
        assert "GITHUB_EVENT_PATH" in out

    def test_unreadable_file_calls_set_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Point at a path that doesn't exist.
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "does-not-exist.json"))
        from main import _load_event_payload

        assert _load_event_payload() is None
        out = capfd.readouterr().out
        assert "::error::" in out
        assert "Could not read event payload" in out

    def test_invalid_json_calls_set_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        p = tmp_path / "event.json"
        p.write_text("this is not JSON")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(p))
        from main import _load_event_payload

        assert _load_event_payload() is None
        out = capfd.readouterr().out
        assert "::error::" in out

    @pytest.mark.parametrize(
        "non_dict_json",
        [
            "null",
            "[]",
            "[1, 2, 3]",
            '"a string"',
            "42",
            "true",
        ],
    )
    def test_non_dict_json_calls_set_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
        tmp_path: Path,
        non_dict_json: str,
    ) -> None:
        # Legal JSON but not a JSON object. Downstream code assumes
        # ``event_payload.get("pull_request")`` works; a list would raise
        # AttributeError. Catch the shape mismatch here with a clear message.
        p = tmp_path / "event.json"
        p.write_text(non_dict_json)
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(p))
        from main import _load_event_payload

        assert _load_event_payload() is None
        out = capfd.readouterr().out
        assert "::error::" in out
        assert "not a JSON object" in out

    def test_empty_object_calls_set_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        # Regression from the PR-A review: a legitimate empty ``{}`` payload
        # used to make ``_run`` bail on ``not event_payload`` WITHOUT
        # calling ``set_failed``. The process would exit 1 with no
        # ``::error::`` annotation and the maintainer would see a red step
        # with no message. Now: explicit failure with a diagnostic.
        p = tmp_path / "event.json"
        p.write_text("{}")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(p))
        from main import _load_event_payload

        assert _load_event_payload() is None
        out = capfd.readouterr().out
        assert "::error::" in out
        assert "empty" in out.lower()

    def test_valid_dict_returns_the_dict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        p = tmp_path / "event.json"
        p.write_text('{"pull_request": {"number": 1}}')
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(p))
        from main import _load_event_payload

        result = _load_event_payload()
        assert result == {"pull_request": {"number": 1}}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
