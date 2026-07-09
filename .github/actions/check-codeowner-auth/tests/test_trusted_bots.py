"""Tests for the trusted-bot allowlist parser."""

from __future__ import annotations

import pytest

from src.trusted_bots import parse_ids


class TestParseIds:
    def test_empty_string(self) -> None:
        assert parse_ids("") == frozenset()

    def test_single_id(self) -> None:
        assert parse_ids("29139614") == frozenset({29139614})

    def test_multiple_ids(self) -> None:
        assert parse_ids("29139614,49699333") == frozenset({29139614, 49699333})

    def test_whitespace_tolerated(self) -> None:
        assert parse_ids("  29139614 , 49699333  ") == frozenset({29139614, 49699333})

    def test_trailing_comma(self) -> None:
        assert parse_ids("29139614,") == frozenset({29139614})

    def test_double_commas(self) -> None:
        assert parse_ids("29139614,,49699333") == frozenset({29139614, 49699333})

    def test_non_numeric_silently_dropped(self) -> None:
        # Malformed workflow input should not crash the gate.
        assert parse_ids("29139614,not-a-number,49699333") == frozenset({29139614, 49699333})

    def test_negative_ids_accepted(self) -> None:
        # int() accepts negatives; GitHub user IDs are never negative in
        # practice but the parser shouldn't invent a rejection rule.
        assert -1 in parse_ids("-1")

    def test_result_is_immutable(self) -> None:
        result = parse_ids("1,2,3")
        assert isinstance(result, frozenset)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
