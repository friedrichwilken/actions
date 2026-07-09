"""Tests for the review-filtering logic."""

from __future__ import annotations

import pytest

from src.approvals import Review, valid_approvals_at_head


def _review(
    *,
    login: str = "alice",
    reviewer_type: str = "User",
    state: str = "APPROVED",
    commit_id: str = "abc123",
) -> Review:
    return Review(
        reviewer_login=login,
        reviewer_type=reviewer_type,
        state=state,
        commit_id=commit_id,
    )


class TestBasicFiltering:
    def test_single_valid_approval(self) -> None:
        r = _review()
        assert valid_approvals_at_head([r], "abc123", "author") == (r,)

    def test_stale_sha_rejected(self) -> None:
        r = _review(commit_id="old-sha")
        assert valid_approvals_at_head([r], "new-sha", "author") == ()

    def test_bot_approval_rejected(self) -> None:
        r = _review(reviewer_type="Bot")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_self_approval_rejected(self) -> None:
        # Defense-in-depth: GitHub server-side already rejects with 422,
        # but if that check is ever bypassed we don't want to authorize.
        r = _review(login="author")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_changes_requested_rejected(self) -> None:
        r = _review(state="CHANGES_REQUESTED")
        assert valid_approvals_at_head([r], "abc123", "author") == ()

    def test_dismissed_rejected(self) -> None:
        r = _review(state="DISMISSED")
        assert valid_approvals_at_head([r], "abc123", "author") == ()


class TestLatestStateWins:
    """When a reviewer submits multiple reviews, only the latest counts."""

    def test_approved_then_changes_requested(self) -> None:
        # Reviewer approved, then requested changes — latest wins, no approval.
        reviews = [
            _review(state="APPROVED"),
            _review(state="CHANGES_REQUESTED"),
        ]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_changes_requested_then_approved(self) -> None:
        # Reviewer asked for changes, then approved after fixes.
        reviews = [
            _review(state="CHANGES_REQUESTED"),
            _review(state="APPROVED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert len(result) == 1
        assert result[0].state == "APPROVED"

    def test_comments_do_not_reset_state(self) -> None:
        # A COMMENTED review after an APPROVED one must not erase the approval.
        reviews = [
            _review(state="APPROVED"),
            _review(state="COMMENTED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert len(result) == 1
        assert result[0].state == "APPROVED"

    def test_multiple_reviewers_independent(self) -> None:
        reviews = [
            _review(login="alice", state="APPROVED"),
            _review(login="bob", state="CHANGES_REQUESTED"),
            _review(login="carol", state="APPROVED"),
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert {r.reviewer_login for r in result} == {"alice", "carol"}


class TestCombinations:
    """The filter rules combined."""

    def test_bot_approval_stale_and_wrong_author_all_rejected(self) -> None:
        reviews = [
            _review(login="alice", reviewer_type="Bot"),  # bot
            _review(login="bob", commit_id="old-sha"),  # stale
            _review(login="author"),  # self
        ]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()

    def test_one_valid_mixed_with_invalid(self) -> None:
        reviews = [
            _review(login="alice", reviewer_type="Bot"),  # bot: rejected
            _review(login="bob", commit_id="old-sha"),  # stale: rejected
            _review(login="carol"),  # valid
            _review(login="author"),  # self: rejected
        ]
        result = valid_approvals_at_head(reviews, "abc123", "author")
        assert {r.reviewer_login for r in result} == {"carol"}


class TestEdgeCases:
    def test_empty_reviews(self) -> None:
        assert valid_approvals_at_head([], "abc123", "author") == ()

    def test_only_comments(self) -> None:
        reviews = [_review(state="COMMENTED")]
        assert valid_approvals_at_head(reviews, "abc123", "author") == ()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
